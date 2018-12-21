typedef union {
        uint16_t        _16[3];
        uint8_t         _8[6];
} mac_e;

typedef union {
        uint16_t        _16[2];
        uint32_t        _32;
} ip4_e;

/*hashes*/
#define IPV6_ADDR_LEN 16
#define XMM_NUM_IN_IPV6_5TUPLE 3

union ipv4_5tuple_host {
        struct {
                uint8_t  pad0;
                uint8_t  proto;
                uint16_t pad1;
                uint32_t ip_src;
                uint32_t ip_dst;
                uint16_t port_src;
                uint16_t port_dst;
        };
        __m128i xmm;
};
union ipv6_5tuple_host {
        struct {
                uint16_t pad0;
                uint8_t  proto;
                uint8_t  pad1;
                uint8_t  ip_src[IPV6_ADDR_LEN];
                uint8_t  ip_dst[IPV6_ADDR_LEN];
                uint16_t port_src;
                uint16_t port_dst;
                uint64_t reserve;
        };
        __m128i xmm[XMM_NUM_IN_IPV6_5TUPLE];
};
struct ipv4_4tuple {
        uint32_t ip_dst;
        uint32_t ip_src;
        uint16_t port_dst;
        uint16_t port_src;
} __attribute__((__packed__));
struct arpkey {
	uint32_t ip_dst;
};
enum arp_state { ARP_NOT_SENT = 0, ARP_SENT = 1, ARP_REPLIED = 2};
