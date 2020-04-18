#ifndef __COMMON_H__
#define __COMMON_H__

#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <arpa/inet.h>

#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

#include <net/ethernet.h>
#include <net/if.h>

#include <netpacket/packet.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <fcntl.h>
#include <errno.h>
#include <assert.h>

typedef struct {
    int tcp;
    int udp;
    int icmp;
    int igmp;
    int other;
    int all;
} IPProtocols;
typedef enum {
    all = ETH_P_ALL,
    ip = ETH_P_IP,
	ipv6 = ETH_P_IPV6,
	arp = ETH_P_ARP,
	rarp = ETH_P_RARP
} allProtocols;

typedef struct {
    FILE* log;
    IPProtocols* protocols;
} snifferLog;

typedef unsigned char* BUFFER;

#ifndef __cplusplus
	typedef enum {false, true} bool;
#endif

#define RECV_BUFFER_SIZE 65536

#define CLRSCREEN() printf("\033[H\033[2J")

#endif // !__COMMON_H__