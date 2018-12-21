rtpproxy powered by DPDK
==============

Copyright
-------------
Tomaz Buh  
<hubber.devel@gmail.com>  
Licenced under the GPL.

About
--------------

The rtp proxy is very fast end efficient rtpproxy, which uses DPDK libraries for fast RTP packet reception and transmission. For communication it uses TCP/IP communication on port 8888. 
Please note that this app fully utilizes one core (100%) because of polling mode when receiving network packets. 


Installation
--------------

rtpproxy includes a compatible vanilla DPDK library, so DPDK library must be compiled and configured prior to compiling and running rtpproxy app. 
Steps:
1. Go to dpdk library directory. 
2.a Run usertoos/dpdk-setup.sh. This will give you interactive UI. Choose the appropriate numbers for the following options: 
	1. Select appropriate compiler/architecture settings. This will compile DPDK library. 
	2. Load igb_uio module. 
	3. Set appropriate memory size for hugepage mappings (non-NUMA and/or NUMA)
	4. Select the appropriate PCI address of network interface to be used for rtpproxy. This interface is exclusively used by DPDK libraries (it is bound to DPDK) and is afterwards not seen on system. PCI addresses of interfaces can be obtained by issuing command: lspci. 
2.b. You can skip step 2 if you run script 'custom_setup.sh PCI_address_of_network_interface' in rtpproxy dir. 
3. Compile rtpproxy application in directory:
	1. source env-localdpdk
        2. make

In the future, we will add rpm packages for DPDK libraries and rtpproxy application. Currently there is also no 'make install ' procedure. 

Usage
--------------

When compile process and DPDK setup (loaded module and bound interfaces) are succesfully executed the rtpproxy can be found in sources location: build/app/rtpproxy. 
rtpprocy can use standard EAL DPDK options (more info https://dpdk.org/doc/guides/testpmd_app_ug/run_app.html) and rtpproxy options. 
Basic syntax:  
   
`rtpproxy [EAL options] -- [rtpproxy options]`

Common EAL options are:
- -`c COREMASK`
Set the hexadecimal bitmask of the cores to run on. (currently we use two cores - one is used by rtpproxy polling engine (100% utilized) and the other for communication with clients (small utilization). 
- `-l CORELIST`
List of cores to run on. The argument format is <c1>[-c2][,c3[-c4],...] where c1, c2, etc are core indexes between 0 and 128.
- `-n NUM`
Set the number of memory channels to use.
- `-b, --pci-blacklist domain:bus:devid.func`
Blacklist a PCI device to prevent EAL from using it. Multiple -b options are allowed.
- `-m MB`
Memory to allocate. See also --socket-mem.
- `-r NUM`
Set the number of memory ranks (auto-detected by default).

rtpproxy options are:  
- -`p PORTMASK`  
Set the hexadecimal bitmask of the ports used by application.
- `--multiple-clients`  
Enable multiple clients for modifying proxy table. 


Some examples:

	#Run rtpproxy on first two cores by using a first DPDK port and with two memorry channels:
	build/app/rtpproxy  -c 0x3 -n 2 -- -p 0x1
	#Run rtpproxy on 2nd and 3rd core by using a second DPDK port and with two memorry channels:
	build/app/rtpproxy  -c 0x6 -n 2 -- -p 0x2

