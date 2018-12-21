/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*Coded by Tomaz Buh*/
#include <unistd.h>

#include <signal.h>
#include <getopt.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_reorder.h>
#include <rte_ip.h>
#include <rte_hash.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_arp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <rte_cycles.h>

#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
#include <rte_hash_crc.h>
#define DEFAULT_HASH_FUNC       rte_hash_crc
#else
#include <rte_jhash.h>
#define DEFAULT_HASH_FUNC       rte_jhash
#endif

#include "main.h"

#define DO_RFC_1812_CHECKS
#define NB_SOCKETS 2
//#define NUMA
#ifdef RTE_ARCH_X86_64
/* default to 4 million hash entries (approx) */
//#define PROXY_HASH_ENTRIES              1024*1024*4
//only 1 mio entries
#define PROXY_HASH_ENTRIES              1024*10
#else
/* 32-bit has less address-space for hugepage memory, limit to 1M entries */
#define PROXY_HASH_ENTRIES              1024*1024*1
#endif

#define  RTE_ETH_IS_ARP_HDR(ptype) ((ptype) & RTE_PTYPE_L2_ETHER_ARP)


#define RX_DESC_PER_QUEUE 128
#define TX_DESC_PER_QUEUE 512

#define MAX_PKTS_BURST 32
#define REORDER_BUFFER_SIZE 8192
#define MBUF_PER_POOL 65535
#define MBUF_POOL_CACHE_SIZE 250

#define RING_SIZE 16384

/* uncommnet below line to enable debug logs */
#define DEBUG

#ifdef DEBUG
#define LOG_LEVEL RTE_LOG_DEBUG
#define LOG_DEBUG(log_type, fmt, args...) RTE_LOG(DEBUG, log_type, fmt, ##args)
#else
#define LOG_LEVEL RTE_LOG_INFO
#define LOG_DEBUG(log_type, fmt, args...) do {} while (0)
#endif

/* Macros for printing using RTE_LOG */
#define RTE_LOGTYPE_RTPPRX          RTE_LOGTYPE_USER1

unsigned int portmask;
unsigned int enable_reorder;
unsigned int multiple_clients;
volatile uint8_t quit_signal;

static struct rte_mempool *mbuf_pool;
static struct rte_mempool *special_mp;

static struct rte_eth_conf port_conf_default= {
        .rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN ,.hw_ip_checksum = 1}
};;

struct worker_thread_args {
	struct rte_ring *ring_in;
	struct rte_ring *ring_out;
};

struct send_thread_args {
	struct rte_ring *ring_in;
	struct rte_reorder_buffer *buffer;
};

struct output_buffer {
	unsigned count;
	struct rte_mbuf *mbufs[MAX_PKTS_BURST];
};

volatile struct app_stats {
	struct {
		uint64_t rx_pkts;
		uint64_t enqueue_pkts;
		uint64_t enqueue_failed_pkts;
	} rx __rte_cache_aligned;

	struct {
		uint64_t dequeue_pkts;
		uint64_t enqueue_pkts;
		uint64_t enqueue_failed_pkts;
	} wkr __rte_cache_aligned;

	struct {
		uint64_t dequeue_pkts;
		/* Too early pkts transmitted directly w/o reordering */
		uint64_t early_pkts_txtd_woro;
		/* Too early pkts failed from direct transmit */
		uint64_t early_pkts_tx_failed_woro;
		uint64_t ro_tx_pkts;
		uint64_t ro_tx_failed_pkts;
	} tx __rte_cache_aligned;
} app_stats;

typedef struct rte_hash lookup_struct_t;
static lookup_struct_t *ipv4_proxy_lookup_struct[NB_SOCKETS];
static lookup_struct_t *ipv6_proxy_lookup_struct[NB_SOCKETS];

static volatile uint32_t ipv4_proxy_dst_ips[PROXY_HASH_ENTRIES] __rte_cache_aligned;
static volatile uint32_t ipv4_proxy_src_ips[PROXY_HASH_ENTRIES] __rte_cache_aligned;
static volatile uint16_t ipv4_proxy_dst_ports[PROXY_HASH_ENTRIES] __rte_cache_aligned;
static volatile uint16_t ipv4_proxy_src_ports[PROXY_HASH_ENTRIES] __rte_cache_aligned;
static __m128i mask0;
static lookup_struct_t *arp_hash_table[NB_SOCKETS];
static struct ether_addr arp_mac_table[PROXY_HASH_ENTRIES] __rte_cache_aligned;
uint64_t arp_age_table[PROXY_HASH_ENTRIES] __rte_cache_aligned;
uint8_t arp_state_table[PROXY_HASH_ENTRIES] __rte_cache_aligned;

/* ethernet addresses of ports */
static uint64_t dest_eth_addr[RTE_MAX_ETHPORTS];
static struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

static __m128i val_eth[RTE_MAX_ETHPORTS];
	
static inline uint32_t
ipv4_hash_crc(const void *data, __rte_unused uint32_t data_len,
        uint32_t init_val)
{
        const union ipv4_5tuple_host *k;
        uint32_t t;
        const uint32_t *p;

        k = data;
        t = k->proto;
        p = (const uint32_t *)&k->port_src;

#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
        init_val = rte_hash_crc_4byte(t, init_val);
        init_val = rte_hash_crc_4byte(k->ip_src, init_val);
        init_val = rte_hash_crc_4byte(k->ip_dst, init_val);
        init_val = rte_hash_crc_4byte(*p, init_val);
#else /* RTE_MACHINE_CPUFLAG_SSE4_2 */
        init_val = rte_jhash_1word(t, init_val);
        init_val = rte_jhash_1word(k->ip_src, init_val);
        init_val = rte_jhash_1word(k->ip_dst, init_val);
        init_val = rte_jhash_1word(*p, init_val);
#endif /* RTE_MACHINE_CPUFLAG_SSE4_2 */
        return (init_val);
}
static inline uint32_t
ipv6_hash_crc(const void *data, __rte_unused uint32_t data_len, uint32_t init_val)
{
        const union ipv6_5tuple_host *k;
        uint32_t t;
        const uint32_t *p;
#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
        const uint32_t  *ip_src0, *ip_src1, *ip_src2, *ip_src3;
        const uint32_t  *ip_dst0, *ip_dst1, *ip_dst2, *ip_dst3;
#endif /* RTE_MACHINE_CPUFLAG_SSE4_2 */

        k = data;
        t = k->proto;
        p = (const uint32_t *)&k->port_src;

#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
        ip_src0 = (const uint32_t *) k->ip_src;
        ip_src1 = (const uint32_t *)(k->ip_src+4);
        ip_src2 = (const uint32_t *)(k->ip_src+8);
        ip_src3 = (const uint32_t *)(k->ip_src+12);
        ip_dst0 = (const uint32_t *) k->ip_dst;
        ip_dst1 = (const uint32_t *)(k->ip_dst+4);
        ip_dst2 = (const uint32_t *)(k->ip_dst+8);
        ip_dst3 = (const uint32_t *)(k->ip_dst+12);
        init_val = rte_hash_crc_4byte(t, init_val);
        init_val = rte_hash_crc_4byte(*ip_src0, init_val);
        init_val = rte_hash_crc_4byte(*ip_src1, init_val);
        init_val = rte_hash_crc_4byte(*ip_src2, init_val);
        init_val = rte_hash_crc_4byte(*ip_src3, init_val);
        init_val = rte_hash_crc_4byte(*ip_dst0, init_val);
        init_val = rte_hash_crc_4byte(*ip_dst1, init_val);
        init_val = rte_hash_crc_4byte(*ip_dst2, init_val);
        init_val = rte_hash_crc_4byte(*ip_dst3, init_val);
        init_val = rte_hash_crc_4byte(*p, init_val);
#else /* RTE_MACHINE_CPUFLAG_SSE4_2 */
        init_val = rte_jhash_1word(t, init_val);
        init_val = rte_jhash(k->ip_src, sizeof(uint8_t) * IPV6_ADDR_LEN, init_val);
        init_val = rte_jhash(k->ip_dst, sizeof(uint8_t) * IPV6_ADDR_LEN, init_val);
        init_val = rte_jhash_1word(*p, init_val);
#endif /* RTE_MACHINE_CPUFLAG_SSE4_2 */
        return (init_val);
}
static inline void
add_ipv4_proxy_entry_to_hash_table(const struct rte_hash* h,union ipv4_5tuple_host* hash_key, 
		struct ipv4_4tuple* new_values)
{
	
                int32_t ret = rte_hash_add_key(h,(void *) hash_key);
		//printf("Add HASH to %d\n",ret);
		if (ret < 0) {
			if (ret == -EINVAL)
				printf("Invalid parameters...exiting\n");
			else if (ret == -ENOSPC)
				printf("No space...exiting\n");
			rte_exit(EXIT_FAILURE, "Unable to add entry.\n");
		}
		__sync_lock_test_and_set(&ipv4_proxy_dst_ips[ret],new_values->ip_dst);
		__sync_lock_test_and_set(&ipv4_proxy_src_ips[ret],new_values->ip_src);
		__sync_lock_test_and_set(&ipv4_proxy_dst_ports[ret],new_values->port_dst);
		__sync_lock_test_and_set(&ipv4_proxy_src_ports[ret],new_values->port_src);
}
static inline void
del_ipv4_proxy_entry_from_hash_table(const struct rte_hash* h,union ipv4_5tuple_host* hash_key)
{
	
                int32_t ret = rte_hash_del_key(h,(void *) hash_key);
		if (ret < 0) {
			printf("Unable to remove entry.\n");
		}
}
static inline uint32_t
arp_hash_calc(const void *data, __rte_unused uint32_t data_len,
        uint32_t init_val)
{
	const struct arpkey *akey;
	akey=data;
#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
        init_val = rte_hash_crc_4byte(akey->ip_dst, init_val);
#else /* RTE_MACHINE_CPUFLAG_SSE4_2 */
        init_val = rte_jhash_1word(akey->ip_dst, init_val);
#endif /* RTE_MACHINE_CPUFLAG_SSE4_2 */
	return (init_val);
}
static inline void
add_arp_entry_to_hash_table(const struct rte_hash* h,uint32_t* hash_key, 
		struct ether_addr* mac_addr,enum arp_state state,uint64_t timestamp)
{
	
                int32_t ret = rte_hash_add_key(h,(void *) hash_key);
		if (ret < 0) {
			printf("No space left...\n");
			//rte_exit(EXIT_FAILURE, "Unable to add entry.\n");
		}
		else{
			ether_addr_copy(mac_addr,&arp_mac_table[ret]);
			arp_age_table[ret]=timestamp;
			arp_state_table[ret]=state;
		}
}
/**
 * Get the last enabled lcore ID
 *
 * @return
 *   The last enabled lcore ID.
 */
static unsigned int
get_last_lcore_id(void)
{
	int i;
	for (i = RTE_MAX_LCORE - 1; i >= 0; i--)
		if (rte_lcore_is_enabled(i))
			return i;
	return 0;
}

/**
 * Get the previous enabled lcore ID
 * @param id
 *  The current lcore ID
 * @return
 *   The previous enabled lcore ID or the current lcore
 *   ID if it is the first available core.
 */
static unsigned int
get_previous_lcore_id(unsigned int id)
{
	int i;

	for (i = id - 1; i >= 0; i--)
		if (rte_lcore_is_enabled(i))
			return i;
	return id;
}
#ifdef DO_RFC_1812_CHECKS
static inline int
is_valid_ipv4_pkt(struct ipv4_hdr *pkt, uint32_t link_len)
{
        /* From http://www.rfc-editor.org/rfc/rfc1812.txt section 5.2.2 */
        /*
 *          * 1. The packet length reported by the Link Layer must be large
 *                   * enough to hold the minimum length legal IP datagram (20 bytes).
 *                            */
        if (link_len < sizeof(struct ipv4_hdr))
                return -1;

        /* 2. The IP checksum must be correct. */
        /* this is checked in H/W */

        /*
 *          * 3. The IP version number must be 4. If the version number is not 4
 *                   * then the packet may be another version of IP, such as IPng or
 *                            * ST-II.
 *                                     */
        if (((pkt->version_ihl) >> 4) != 4)
                return -3;
        /*
 *          * 4. The IP header length field must be large enough to hold the
 *                   * minimum length legal IP datagram (20 bytes = 5 words).
 *                            */
        if ((pkt->version_ihl & 0xf) < 5)
                return -4;

        /*
 *          * 5. The IP total length field must be large enough to hold the IP
 *                   * datagram header, whose length is specified in the IP header length
 *                            * field.
 *                                     */
        if (rte_cpu_to_be_16(pkt->total_length) < sizeof(struct ipv4_hdr))
                return -5;

        return 0;
}
#endif
static inline void
pktmbuf_free_bulk(struct rte_mbuf *mbuf_table[], unsigned n)
{
	unsigned int i;

	for (i = 0; i < n; i++)
		rte_pktmbuf_free(mbuf_table[i]);
}

/* display usage */
static void
print_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK\n"
			"  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
			"  --multiple-clients:  enable multiple clients for modifying proxy table\n",
			prgname);
}

static int
parse_portmask(const char *portmask)
{
	unsigned long pm;
	char *end = NULL;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (pm == 0)
		return -1;

	return pm;
}

/* Parse the argument given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
	int opt;
	int option_index;
	char **argvopt;
	char *prgname = argv[0];
	static struct option lgopts[] = {
		{"enable-reorder", 0, 0, 0},
		{"multiple-clients", 0, 0, 0},
		{NULL, 0, 0, 0}
	};

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "p:",
					lgopts, &option_index)) != EOF) {
		switch (opt) {
		/* portmask */
		case 'p':
			portmask = parse_portmask(optarg);
			if (portmask == 0) {
				printf("invalid portmask\n");
				print_usage(prgname);
				return -1;
			}
			break;
		/* long options */
		case 0:
			if (!strcmp(lgopts[option_index].name, "enable-reorder")) {
				printf("reorder enabled\n");
				enable_reorder = 1;
			}
			if (!strcmp(lgopts[option_index].name, "multiple-clients")) {
				printf("multiple clients mode enabled\n");
				multiple_clients = 1;
			}
			break;
		default:
			print_usage(prgname);
			return -1;
		}
	}
	if (optind <= 1) {
		print_usage(prgname);
		return -1;
	}

	argv[optind-1] = prgname;
	optind = 0; /* reset getopt lib */
	return 0;
}

static inline int
configure_eth_port(uint8_t port_id)
{
	struct ether_addr addr;
	const uint16_t rxRings = 1, txRings = 1;
	const uint8_t nb_ports = rte_eth_dev_count();
	int ret;
	uint16_t q;

	if (port_id > nb_ports)
		return -1;

	ret = rte_eth_dev_configure(port_id, rxRings, txRings, &port_conf_default);
	if (ret != 0)
		return ret;

	for (q = 0; q < rxRings; q++) {
		ret = rte_eth_rx_queue_setup(port_id, q, RX_DESC_PER_QUEUE,
				rte_eth_dev_socket_id(port_id), NULL,
				mbuf_pool);
		if (ret < 0)
			return ret;
	}

	for (q = 0; q < txRings; q++) {
		ret = rte_eth_tx_queue_setup(port_id, q, TX_DESC_PER_QUEUE,
				rte_eth_dev_socket_id(port_id), NULL);
		if (ret < 0)
			return ret;
	}

	ret = rte_eth_dev_start(port_id);
	if (ret < 0)
		return ret;

	rte_eth_macaddr_get(port_id, &addr);
	printf("Port %u MAC: %02"PRIx8" %02"PRIx8" %02"PRIx8
			" %02"PRIx8" %02"PRIx8" %02"PRIx8"\n",
			(unsigned)port_id,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	rte_eth_promiscuous_enable(port_id);

	return 0;
}

static void
print_stats(void)
{
	/*TODO upadte stats for custom application*/
	const uint8_t nb_ports = rte_eth_dev_count();
	unsigned i;
	struct rte_eth_stats eth_stats;

	printf("\nRX thread stats:\n");
	printf(" - Pkts rxd:				%"PRIu64"\n",
						app_stats.rx.rx_pkts);
	printf(" - Pkts enqd to workers ring:		%"PRIu64"\n",
						app_stats.rx.enqueue_pkts);

	printf("\nWorker thread stats:\n");
	printf(" - Pkts deqd from workers ring:		%"PRIu64"\n",
						app_stats.wkr.dequeue_pkts);
	printf(" - Pkts enqd to tx ring:		%"PRIu64"\n",
						app_stats.wkr.enqueue_pkts);
	printf(" - Pkts enq to tx failed:		%"PRIu64"\n",
						app_stats.wkr.enqueue_failed_pkts);

	printf("\nTX stats:\n");
	printf(" - Pkts deqd from tx ring:		%"PRIu64"\n",
						app_stats.tx.dequeue_pkts);
	printf(" - Ro Pkts transmitted:			%"PRIu64"\n",
						app_stats.tx.ro_tx_pkts);
	printf(" - Ro Pkts tx failed:			%"PRIu64"\n",
						app_stats.tx.ro_tx_failed_pkts);
	printf(" - Pkts transmitted w/o reorder:	%"PRIu64"\n",
						app_stats.tx.early_pkts_txtd_woro);
	printf(" - Pkts tx failed w/o reorder:		%"PRIu64"\n",
						app_stats.tx.early_pkts_tx_failed_woro);

	for (i = 0; i < nb_ports; i++) {
		rte_eth_stats_get(i, &eth_stats);
		printf("\nPort %u stats:\n", i);
		printf(" - Pkts in:   %"PRIu64"\n", eth_stats.ipackets);
		printf(" - Pkts out:  %"PRIu64"\n", eth_stats.opackets);
		printf(" - In Errs:   %"PRIu64"\n", eth_stats.ierrors);
		printf(" - Out Errs:  %"PRIu64"\n", eth_stats.oerrors);
		printf(" - Mbuf Errs: %"PRIu64"\n", eth_stats.rx_nombuf);
	}
}

static void
int_handler(int sig_num)
{
	printf("Exiting on signal %d\n", sig_num);
	quit_signal = 1;
}

static int
process_packet(struct rte_mbuf *pkt)
{
        struct ether_hdr *eth_hdr;
        struct ipv4_hdr *ipv4_hdr;
        struct tcp_hdr *tcp=NULL;
        struct udp_hdr *udp=NULL;
         uint16_t myvlan=0;
	//TODO use local IP or any IP
	uint32_t my_ip = rte_cpu_to_be_32(IPv4(192,18,0,42));
	//TODO maybe do not strip VLAN, but onyl adapt packet to it. 
        eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	if (eth_hdr->ether_type == rte_cpu_to_be_16(ETHER_TYPE_VLAN)){
		rte_vlan_strip(pkt);	
		//printf("VLAN ID: %d\n",(pkt->vlan_tci<<4)>>4);
                myvlan=pkt->vlan_tci;
                eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *); 
	}
	if (eth_hdr->ether_type == rte_be_to_cpu_16(ETHER_TYPE_IPv4)){
		//printf("Handling IPv4 packet.\n");
		LOG_DEBUG(RTPPRX, "Handling IPv4 packet.\n");
                /* Handle IPv4 headers.*/
                ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct ipv4_hdr *,
                                                   sizeof(struct ether_hdr));
		/*Get layer 4 type*/
	        switch (ipv4_hdr->next_proto_id) {
	        case IPPROTO_TCP:
	                tcp = (struct tcp_hdr *)((unsigned char *) ipv4_hdr +
	                                        sizeof(struct ipv4_hdr));
	                break;
	        case IPPROTO_UDP:
	                udp = (struct udp_hdr *)((unsigned char *) ipv4_hdr +
	                                        sizeof(struct ipv4_hdr));
	                break;
	        default:
			RTE_LOG(DEBUG, RTPPRX, "Not UDP or TCP. Processing aborted.\n");
			return -1;
	        }

#ifdef DO_RFC_1812_CHECKS
                /* Check to make sure the packet is valid (RFC1812) */
                if (is_valid_ipv4_pkt(ipv4_hdr, pkt->pkt_len) < 0) {

			RTE_LOG(DEBUG, RTPPRX, "Not valid IPv4. Processing aborted.\n");
                        return -1;
                }
		//RTE_LOG(DEBUG, RTPPRX, "Handling valid IPv4 packet.\n");
#endif
	        int ret = 0;
	        union ipv4_5tuple_host key;
		void *ipv4_hdr_p;

	        ipv4_hdr_p = (uint8_t *)ipv4_hdr + offsetof(struct ipv4_hdr, time_to_live);
	        __m128i data = _mm_loadu_si128((__m128i*)(ipv4_hdr_p));
	        /* Get 5 tuple: dst port, src port, dst IP address, src IP address and protocol */
	        key.xmm = _mm_and_si128(data, mask0);
	        /* Find destination port */
#ifdef NUMA
		//TODO handle NUMA correct sockets
	        //ret = rte_hash_lookup(ipv4_proxy_lookup_struct[1], (const void *)&key);
	        ret = rte_hash_lookup(ipv4_proxy_lookup_struct[0], (const void *)&key);
#else
	        ret = rte_hash_lookup(ipv4_proxy_lookup_struct[0], (const void *)&key);
#endif
	        //return (uint8_t)((ret < 0)? portid : ipv4_l3fwd_out_if[ret]);
	        if (ret < 0){
			//RTE_LOG(DEBUG, RTPPRX, "Not found in tables. Processing aborted.\n");
			return -1;
		}
		else{
			//printf("found.\n");
			//printf("Nov port: %d\n",ipv4_proxy_dst_ports[ret]);		
			if (udp != NULL){
				//RTE_LOG(DEBUG, RTPPRX, "UDP packet.\n");
				ipv4_hdr->src_addr=__sync_fetch_and_sub(&ipv4_proxy_src_ips[ret],0);
				ipv4_hdr->dst_addr=__sync_fetch_and_sub(&ipv4_proxy_dst_ips[ret],0);
				udp->src_port=__sync_fetch_and_sub(&ipv4_proxy_src_ports[ret],0);
				udp->dst_port=__sync_fetch_and_sub(&ipv4_proxy_dst_ports[ret],0);
				udp->dgram_cksum = 0;
				udp->dgram_cksum=rte_ipv4_udptcp_cksum(ipv4_hdr,udp); 	
				
			}
			else if (tcp != NULL){
				ipv4_hdr->src_addr=__sync_fetch_and_sub(&ipv4_proxy_src_ips[ret],0);
				ipv4_hdr->dst_addr=__sync_fetch_and_sub(&ipv4_proxy_dst_ips[ret],0);
				tcp->src_port=__sync_fetch_and_sub(&ipv4_proxy_src_ports[ret],0);
				tcp->dst_port=__sync_fetch_and_sub(&ipv4_proxy_dst_ports[ret],0);
				//RTE_LOG(DEBUG, RTPPRX, "TCP packet.\n");
				tcp->cksum = 0;
				tcp->cksum=rte_ipv4_udptcp_cksum(ipv4_hdr,udp); 	

			}
		}

#ifdef DO_RFC_1812_CHECKS
                /* Update time to live and header checksum */
		/*TODO check if this is necessary*/
                --(ipv4_hdr->time_to_live);
                ++(ipv4_hdr->hdr_checksum);
#endif
		/*Currently if multiple ports are used then pacets are sent to the next one*/
		const uint8_t nb_ports = rte_eth_dev_count();
		const unsigned xor_val = (nb_ports > 1);
		pkt->port ^= xor_val;
		int arp_is_old=0;
		
#ifdef NUMA
		//TODO handle NUMA correct sockets
	        ret = rte_hash_lookup(arp_hash_table[0], (const void *)&ipv4_hdr->dst_addr);
#else
	        ret = rte_hash_lookup(arp_hash_table[0], (const void *)&ipv4_hdr->dst_addr);
#endif
		if (ret >= 0){
			//printf("ARP entry found.\n");
			if (arp_state_table[ret] == ARP_REPLIED){
                		ether_addr_copy(&arp_mac_table[ret], &eth_hdr->d_addr);
			}
			else{
				if ( (rte_get_tsc_cycles() - arp_age_table[ret])/rte_get_tsc_hz() >= 2){
					arp_is_old=1;
					rte_hash_del_key(arp_hash_table[0],(const void *)&ipv4_hdr->dst_addr); 	
				}
			}
		}
	        if ( (ret <  0) || (arp_is_old) ){
			//TODO need to send arp request now and enqueue the packet
			//printf("ARP entry not found or too old. Sending REQ\n");
                        struct rte_mbuf   * m ;
                        struct ether_hdr  * eth_hdr;
			struct arp_hdr    *arp_h;

                        m   = rte_pktmbuf_alloc(special_mp);
                        if ( unlikely(m == NULL) ) {
                                printf("No special packet buffers availible.\n");
                                //return;
                        }
                        eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
                        arp_h = (struct arp_hdr *) ((char *)eth_hdr + sizeof(struct ether_hdr));

                        /* eth header src and dest addr */
                        memset(&eth_hdr->d_addr, 0xFF, 6);
                        ether_addr_copy(&ports_eth_addr[pkt->port], &eth_hdr->s_addr);
                        eth_hdr->ether_type = htons(ETHER_TYPE_ARP);

                        memset(arp_h, 0, sizeof(struct arp_hdr));

                        rte_memcpy(&arp_h->arp_data.arp_sha, &ports_eth_addr[pkt->port],6);
			arp_h->arp_data.arp_sip=my_ip;

              /*          if ( unlikely(type == GRATUITOUS_ARP) ) {
                                rte_memcpy( &arp->tha, &ports_eth_addr[pkt->port], 6 );
                                inetAddrCopy(&arp->tpa, &sip);
                        } else {
                                memset( &arp->tha, 0, 6 );
                                inetAddrCopy(&arp->tpa, &tip);
                        }*/
                        memset(&arp_h->arp_data.arp_tha, 0, 6 );
			arp_h->arp_data.arp_tip=ipv4_hdr->dst_addr;

                        /* Fill in the rest of the ARP packet header */
                        arp_h->arp_hrd    = htons(ARP_HRD_ETHER);
                        arp_h->arp_pro    = htons(ETHER_TYPE_IPv4);
                        arp_h->arp_hln    = 6;
                        arp_h->arp_pln    = 4;
                        arp_h->arp_op     = rte_cpu_to_be_16(ARP_OP_REQUEST);
                        m->pkt_len  = 60;
                        m->data_len = 60;
			m->vlan_tci=myvlan;
			rte_vlan_insert(&m);
			rte_eth_tx_burst(pkt->port, 0, &m,1);	
			add_arp_entry_to_hash_table(arp_hash_table[0],&arp_h->arp_data.arp_tip,&arp_h->arp_data.arp_tha,ARP_SENT,rte_get_tsc_cycles());
                        rte_pktmbuf_free(m);
       			return -1; 
		}
                /* src addr */
                ether_addr_copy(&ports_eth_addr[pkt->port], &eth_hdr->s_addr);
		rte_vlan_insert(&pkt);
                ipv4_hdr->hdr_checksum=0;
		ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
//                send_single_packet(m, dst_port);
        } //end ipv4

	else if (eth_hdr->ether_type == rte_be_to_cpu_16(ETHER_TYPE_IPv6)){
	//printf("processing packet IPv6 not implemented\n");
		/*const uint8_t nb_ports = rte_eth_dev_count();
		const unsigned xor_val = (nb_ports > 1);
		pkt->port ^= xor_val;*/
                /* Handle IPv6 headers.*/
		//RTE_LOG(DEBUG, RTPPRX, "Handling IPv6 packet.\n");
//                struct ipv6_hdr *ipv6_hdr;
//
//                ipv6_hdr = rte_pktmbuf_mtod_offset(m, struct ipv6_hdr *,
//                                                   sizeof(struct ether_hdr));
        }
	else if (eth_hdr->ether_type == rte_be_to_cpu_16(ETHER_TYPE_ARP)){
		         /*
			 * Build ARP reply.
			 */
			struct arp_hdr    *arp_h;
			struct ether_addr eth_addr;
			uint32_t ip_addr;
			//TODO ad this address to local ARP table
			arp_h = (struct arp_hdr *) ((char *)eth_hdr + sizeof(struct ether_hdr));
			if (arp_h->arp_op == rte_cpu_to_be_16(ARP_OP_REQUEST)){
				if (arp_h->arp_data.arp_tip != my_ip)
					return -1;
				arp_h->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);
				
				ether_addr_copy(&eth_hdr->s_addr, &eth_hdr->d_addr);
				ether_addr_copy(&ports_eth_addr[pkt->port], &eth_hdr->s_addr);
	
				rte_memcpy(&eth_addr, &arp_h->arp_data.arp_tha, 6);
				rte_memcpy(&arp_h->arp_data.arp_tha,&arp_h->arp_data.arp_sha, 6);
				rte_memcpy(&arp_h->arp_data.arp_sha,&eth_hdr->s_addr, 6);
				/* Swap IP addresses in ARP payload */
				rte_memcpy(&ip_addr, &arp_h->arp_data.arp_sip, 4);
				rte_memcpy(&arp_h->arp_data.arp_sip,&arp_h->arp_data.arp_tip, 4);
				rte_memcpy(&arp_h->arp_data.arp_tip, &ip_addr, 4);
				rte_vlan_insert(&pkt);
	
				rte_eth_tx_burst(pkt->port, 0, &pkt,1);	
				rte_pktmbuf_free(pkt);
				return -1;
			}
			else if (arp_h->arp_op == rte_cpu_to_be_16(ARP_OP_REPLY)){
				if (arp_h->arp_data.arp_tip != my_ip)
					return -1;
			        int ret = rte_hash_lookup(arp_hash_table[0], (const void *)&arp_h->arp_data.arp_sip);
				if (ret >= 0){
			                ether_addr_copy(&arp_h->arp_data.arp_sha,&arp_mac_table[ret]);
			                arp_age_table[ret]=rte_get_tsc_cycles();
			                arp_state_table[ret]=ARP_REPLIED;
				}

				return -1;
			}
			else{
				printf("Unhandled ARP packet on port: %d obtained (type: %d).\n",pkt->port,rte_be_to_cpu_16(arp_h->arp_op));
				return -1;
			}

	}
	else{
                /* Free the mbuf that contains non-IPV4/IPV6 packet */
		RTE_LOG(DEBUG, RTPPRX, "Not IPv4 or IPv6. Processing aborted.\n");
		return -1;
        }
	return 0;
}

static inline void
flush_one_port(struct output_buffer *outbuf, uint8_t outp)
{
	unsigned nb_tx = rte_eth_tx_burst(outp, 0, outbuf->mbufs,
			outbuf->count);
	app_stats.tx.ro_tx_pkts += nb_tx;

	if (unlikely(nb_tx < outbuf->count)) {
		/* free the mbufs which failed from transmit */
		app_stats.tx.ro_tx_failed_pkts += (outbuf->count - nb_tx);
		LOG_DEBUG(RTPPRX, "%s:Packet loss with tx_burst\n", __func__);
		pktmbuf_free_bulk(&outbuf->mbufs[nb_tx], outbuf->count - nb_tx);
	}
	outbuf->count = 0;
}

/**
 * This thread receives fully processes mbufs on a single core. 
 */
static int
process_thread(void)
{
	const uint8_t nb_ports = rte_eth_dev_count();
	uint32_t seqn = 0;
	uint16_t i = 0,index=0;
	uint16_t nb_rx_pkts;
	uint8_t port_id;
	struct rte_mbuf *pkts[MAX_PKTS_BURST];

	uint16_t processed_counter = 0;
        struct rte_mbuf **pkts_buffer_start=NULL;

	static struct output_buffer tx_buffers[RTE_MAX_ETHPORTS];
	struct output_buffer *outbuf;
	uint8_t outp;

	RTE_LOG(INFO, RTPPRX, "%s() started on lcore %u\n", __func__,
							rte_lcore_id());
	while (!quit_signal) {
		for (port_id = 0; port_id < nb_ports; port_id++) {
			if ((portmask & (1 << port_id)) != 0) {

				/* receive packets */
				nb_rx_pkts = rte_eth_rx_burst(port_id, 0,
								pkts, MAX_PKTS_BURST);
				if (nb_rx_pkts == 0) {
					LOG_DEBUG(RTPPRX,
					"%s():Received zero packets\n",	__func__);
					continue;
				}
				app_stats.rx.rx_pkts += nb_rx_pkts;

				processed_counter=0;
		                pkts_buffer_start=&pkts[0];
				/* process packets on mbuf */
				for (i = 0; i < nb_rx_pkts;)
				{
					if (process_packet(pkts[i]) < 0){
							//printf("Lookup not successful bs: %d.\n",burst_size);
							rte_pktmbuf_free(pkts[i]);
							if (processed_counter > 0)
							{
								//TODO tx packets...
								for (index = 0; index < processed_counter; index++) {
									outp = pkts_buffer_start[index]->port;
									// skip ports that are not enabled 
									if ((portmask & (1 << outp)) == 0) {
											rte_pktmbuf_free(pkts_buffer_start[index]);
											continue;
									}
				
									outbuf = &tx_buffers[outp];
									outbuf->mbufs[outbuf->count++] = pkts_buffer_start[index];
									flush_one_port(outbuf, outp);
								}
								processed_counter=0;
							}
							if ((i+1) < nb_rx_pkts)
								pkts_buffer_start=&pkts[i+1];
					}
					else{
							processed_counter++;
					}
					i++;
				}
				for (index = 0; index < processed_counter; index++) {
					outp = pkts_buffer_start[index]->port;
					/* skip ports that are not enabled */
					if ((portmask & (1 << outp)) == 0) {
							rte_pktmbuf_free(pkts_buffer_start[index]);
							continue;
					}

					outbuf = &tx_buffers[outp];
					outbuf->mbufs[outbuf->count++] = pkts_buffer_start[index];
					if ( (outbuf->count == MAX_PKTS_BURST) || (index == processed_counter-1) )
							flush_one_port(outbuf, outp);
				}
			}
		}
	}
	return 0;
}

static void process_command(int client_sock,char* command)
{
	unsigned int i;
	union ipv4_5tuple_host keyA;
	struct ipv4_4tuple valueB;
        for (i=0;i<strlen(command);i++){

		if (command[i]== '.')
			command[i]=' ';
	}
	//printf("Got: %s\n",command);
	int comm,fsip,fsport,fdip,fdport,tsip,tsport,tdip,tdport;
	//int proto;
	sscanf(command,"%u %u %u %u %u %u %u %u %u",&comm,&fsip,&fsport,&fdip,&fdport,&tsip,&tsport,&tdip,&tdport);
	keyA.pad0=0;
	keyA.proto=IPPROTO_UDP;
	//keyA.proto=proto;
	keyA.pad1=0;
	keyA.ip_src=fsip;
	keyA.ip_dst=fdip;
	keyA.port_src=fsport;
	keyA.port_dst=fdport;
	valueB.ip_src=tsip;
	valueB.ip_dst=tdip;
	valueB.port_src=tsport;
	valueB.port_dst=tdport;
	if (comm == 1)
	{
#ifdef NUMA
		//TODO add numa support
		add_ipv4_proxy_entry_to_hash_table(ipv4_proxy_lookup_struct[0],&keyA,&valueB);
#else
		add_ipv4_proxy_entry_to_hash_table(ipv4_proxy_lookup_struct[0],&keyA,&valueB);
#endif
		write(client_sock , "1" , strlen("1"));
	}
	else if (comm == 0)
	{
#ifdef NUMA
		//TODO add numa support
		del_ipv4_proxy_entry_from_hash_table(ipv4_proxy_lookup_struct[0],&keyA);
#else
		del_ipv4_proxy_entry_from_hash_table(ipv4_proxy_lookup_struct[0],&keyA);
#endif
		write(client_sock , "1" , strlen("1"));
	}

}
/*
* This will handle connection for each client
* */
static void *connection_handler(void *socket_desc)
{
	//Get the socket descriptor
	int sock = *(int*)socket_desc;
	int read_size;
	char /**message ,*/ client_message[2000];
	
	//Receive a message from client
	while( (read_size = recv(sock , client_message , 2000 , 0)) > 0 )
	{
		client_message[read_size]=0;
		process_command(sock,client_message);
	}
	if(read_size == 0)
	{
		puts("Client disconnected");
		fflush(stdout);
	}
	else if(read_size == -1)
	{
		perror("recv failed");
	}	
	//Free the socket pointer
	free(socket_desc);
	
	return 0;
}

static int
communication_thread(void)
{
	int socket_desc , client_sock , c , *new_sock;
	struct sockaddr_in server , client;
	
	//Create socket
	socket_desc = socket(AF_INET , SOCK_STREAM , 0);
	if (socket_desc == -1){
		printf("Socket could not be created.\n");
	}
	//Prepare the sockaddr_in structure
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons( 8888 );
	
	//Bind
	if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0){
		//print the error message
		perror("bind failed. Error");
		return 1;
	}
	//Listen
	listen(socket_desc , 3);
	puts("RTP proxy active.");
	puts("RTP proxy API ready.");
	c = sizeof(struct sockaddr_in);
	while( (client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c)) ){
		if (!multiple_clients){
			int read_size;
			char client_message[2000];
			//Receive a message from client
			while( (read_size = recv(client_sock , client_message , 2000 , 0)) > 0 ){
				client_message[read_size]=0;
				process_command(client_sock,client_message);
			}
			if(read_size == 0){
				fflush(stdout);
				close(client_sock);
			}
			else if(read_size == -1){
				perror("recv failed");
			}
		}
		else{
			pthread_t sniffer_thread;
			new_sock = malloc(1);
			*new_sock = client_sock;
			
			if( pthread_create( &sniffer_thread , NULL ,  connection_handler , (void*) new_sock) < 0){
				perror("could not create thread");
				return 1;
			}
			
		}
	}
	
	if (client_sock < 0){
		perror("accept failed");
		return 1;
	}
	
	return 0;
}

#define BYTE_VALUE_MAX 256
#define ALL_32_BITS 0xffffffff
#define BIT_8_TO_15 0x0000ff00
static void
setup_hash(int socketid)
{
    if ( (ipv4_proxy_lookup_struct[socketid] != NULL ) || (ipv6_proxy_lookup_struct[socketid] != NULL ) || (arp_hash_table[socketid] != NULL) )
	return;
printf("Init for socket %d\n",socketid);
    struct rte_hash_parameters ipv4_proxy_hash_params = {
        .name = NULL,
        .entries = PROXY_HASH_ENTRIES,
        .key_len = sizeof(union ipv4_5tuple_host),
        .hash_func = ipv4_hash_crc,
        .hash_func_init_val = 0,
    };

    struct rte_hash_parameters ipv6_proxy_hash_params = {
        .name = NULL,
        .entries = PROXY_HASH_ENTRIES,
        .key_len = sizeof(union ipv6_5tuple_host),
        .hash_func = ipv6_hash_crc,
        .hash_func_init_val = 0,
    };

    struct rte_hash_parameters arp_hash_params = {
        .name = NULL,
        .entries = PROXY_HASH_ENTRIES,
        .key_len = sizeof(uint32_t),
        .hash_func = arp_hash_calc,
        .hash_func_init_val = 0,
    };

    char myname[64];
       /* create ipv4 hash */
        snprintf(myname, sizeof(myname), "ipv4_proxy_hash_%d", socketid);
        ipv4_proxy_hash_params.name = myname;
        ipv4_proxy_hash_params.socket_id = socketid;
        ipv4_proxy_lookup_struct[socketid] = rte_hash_create(&ipv4_proxy_hash_params);
        if (ipv4_proxy_lookup_struct[socketid] == NULL)
                rte_exit(EXIT_FAILURE, "Unable to create the proxy hash (v4) on "
                                "socket %d\n", socketid);

        /* create ipv6 hash */
        snprintf(myname, sizeof(myname), "ipv6_proxy_hash_%d", socketid);
        ipv6_proxy_hash_params.name = myname;
        ipv6_proxy_hash_params.socket_id = socketid;
        ipv6_proxy_lookup_struct[socketid] = rte_hash_create(&ipv6_proxy_hash_params);
        if (ipv6_proxy_lookup_struct[socketid] == NULL)
                rte_exit(EXIT_FAILURE, "Unable to create the proxy hash (v6) on "
                                "socket %d\n", socketid);


    char myname2[64];
       /* create arp hash */
        snprintf(myname2, sizeof(myname2), "arp_hash_table_%d", socketid);
        arp_hash_params.name = myname2;
        arp_hash_params.socket_id = socketid;
        arp_hash_table[socketid] = rte_hash_create(&arp_hash_params);
        if (arp_hash_table[socketid] == NULL)
                rte_exit(EXIT_FAILURE, "Unable to create the arp hash on "
                                "socket %d\n", socketid);

	mask0 = _mm_set_epi32(ALL_32_BITS, ALL_32_BITS, ALL_32_BITS, BIT_8_TO_15);
}
int
main(int argc, char **argv)
{
	int ret;
	unsigned nb_ports;
	unsigned int last_lcore_id, master_lcore_id;
	uint8_t port_id;
	uint8_t nb_ports_available;
	int dual_core=0;

	/* catch ctrl-c so we can print on exit */
	signal(SIGINT, int_handler);

	/* Initialize EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		return -1;

	argc -= ret;
	argv += ret;

	/* Parse the application specific arguments */
	ret = parse_args(argc, argv);
	if (ret < 0)
		return -1;

	/* Check if we have proper core configuration */
	if (rte_lcore_count() == 1){
		printf("Using single core is currently not supported. I the future it will be by using posix thread for communication.\n");
		printf("Please corect core mask.\n");
		exit(1);
	}
	else if (rte_lcore_count() == 2){
		printf("Using dual core configuration.\n");
		dual_core=1;
	}
	else if (rte_lcore_count() < 3)
		rte_exit(EXIT_FAILURE, "Error, This application needs "
				"2 logical cores to run:\n"
				"1 lcore for data path\n"
				"1 lcore for control pathX\n");

	last_lcore_id   = get_last_lcore_id();
	master_lcore_id = rte_get_master_lcore();

	nb_ports = rte_eth_dev_count();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "Error: no ethernet ports detected\n");
	if (nb_ports != 1 && (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even, except "
				"when using a single port\n");
        if (nb_ports > RTE_MAX_ETHPORTS)
                nb_ports = RTE_MAX_ETHPORTS;
	/* initialize memory*/
	mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", MBUF_PER_POOL,
			MBUF_POOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
			rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "%s\n", rte_strerror(rte_errno));
	if (special_mp == NULL) {
		special_mp = rte_pktmbuf_pool_create("special_mp", 64/*number of buffers*/,
			0/*cache size*/, 0/*default priv size*/,
			RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (special_mp == NULL)
		rte_exit(EXIT_FAILURE,"Cannot init special mbuf pool.\n");
 	else
		printf("Allocated special mbuf pool.\n");
	}
#ifdef NUMA
	for (lcore_id = 0; lcore_id <= get_previous_lcore_id(last_lcore_id); lcore_id++){
		if (rte_lcore_is_enabled(lcore_id) && lcore_id != master_lcore_id){
			RTE_LOG(INFO,RTPPRX,"Hash setup for lcore: %d at socket: %d\n",lcore_id,rte_lcore_to_socket_id(lcore_id));
			setup_hash(rte_lcore_to_socket_id(lcore_id));
		}
	}
#else
	RTE_LOG(INFO,RTPPRX,"Hash setup for lcore: %d at socket: %d\n",master_lcore_id,rte_lcore_to_socket_id(master_lcore_id));
	setup_hash(rte_lcore_to_socket_id(master_lcore_id));
#endif
        /* pre-init dst MACs for all ports to 02:00:00:00:00:xx */
        for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
                dest_eth_addr[port_id] = ETHER_LOCAL_ADMIN_ADDR + ((uint64_t)port_id << 40);
                *(uint64_t *)(val_eth + port_id) = dest_eth_addr[port_id];
        }	

	nb_ports_available = nb_ports;

	/* initialize all ports */
	for (port_id = 0; port_id < nb_ports; port_id++) {
		/* skip ports that are not enabled */
		if ((portmask & (1 << port_id)) == 0) {
			printf("\nSkipping disabled port %d\n", port_id);
			nb_ports_available--;
			continue;
		}
		/* init port */
		printf("Initializing port %u... done\n", (unsigned) port_id);

		if (configure_eth_port(port_id) != 0)
			rte_exit(EXIT_FAILURE, "Cannot initialize port %"PRIu8"\n",
					port_id);
                
		rte_eth_macaddr_get(port_id, &ports_eth_addr[port_id]);
	}

	if (!nb_ports_available) {
		rte_exit(EXIT_FAILURE,
			"All available ports are disabled. Please set portmask.\n");
	}
	if (dual_core){
		//INFO - communication thread is blocking, so it goes to slave cpu
		rte_eal_remote_launch((lcore_function_t *)communication_thread, NULL,
                                        1);
		process_thread();
		printf("Dual core.\n");
	}
        else{
		printf("Currently only dual core configuration is supported.\n");

	}
	print_stats();
	return 0;
}
