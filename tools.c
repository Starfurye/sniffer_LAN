#include "tools.h"

inline void showTime() {
    printf("[%s %s] ", __DATE__, __TIME__);
}

void initScreen() {
    CLRSCREEN();
    showTime();
    printf("Sniffer start working!\n\n");
}

bool togglePromiscuous(int sd, char* ifrName, int isPromiscuous) {
    struct ifreq ifr;
    bzero(&ifr, sizeof(ifr));

    assert(ifrName != NULL);
    strcpy(ifr.ifr_name, ifrName);

    if (ioctl(sd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("ioctl(): ");
        return false;
    }

    if (isPromiscuous) {
        ifr.ifr_flags &= ~IFF_PROMISC;
    } else {
        ifr.ifr_flags |= IFF_PROMISC;
    }

    if (ioctl(sd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("ioctl(): ");
        return false;
    }

    return true;
}

int initSocket(char* ifrName, allProtocols protocolType, bool isPromiscuous) {
    int sd;

    if ((sd = socket(AF_PACKET, SOCK_RAW, htons(protocolType))) < 0) {
        perror("socket(): ");
        return -1;
    }

    if (!isPromiscuous) {
        if (!togglePromiscuous(sd, ifrName, 0)) {
            perror("togglePromiscuous(): ");
            close(sd);
            return -1;
        }  
    }

    int recvSize = RECV_BUFFER_SIZE;
    if (setsockopt(sd, SOL_SOCKET, SO_RCVBUF, &recvSize, sizeof(int)) < 0) {
        perror("setsockopt(): ");
        close(sd);
        return -1;
    }

    struct ifreq ifr;
    bzero(&ifr, sizeof(ifr));
    strcpy(ifr.ifr_name, ifrName);

    if (ioctl(sd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl(): ");
        close(sd);
        return -1;
    }

    struct sockaddr_ll sock_ll;

    bzero(&sock_ll, sizeof(sock_ll));
    sock_ll.sll_family = AF_PACKET;
    sock_ll.sll_ifindex = ifr.ifr_ifindex;
    sock_ll.sll_protocol = htons(protocolType);
	
	if (bind(sd, (struct sockaddr *)&sock_ll, sizeof(sock_ll)) < 0) {
		perror("bind(): ");
		close(sd);
		return -1;
	}

	return sd;
}

void deinitSocket(int sd, char* ifrName) {
    togglePromiscuous(sd, ifrName, true);
    close(sd);
}

void showCatch(snifferLog* slog) {
    if (slog->protocols->tcp > 0) {
        printf("TCP : %d", slog->protocols->tcp);
    }
    if (slog->protocols->udp > 0) {
        printf("  UDP : %d", slog->protocols->udp);
    }
    if (slog->protocols->icmp > 0) {
        printf("  ICMP : %d", slog->protocols->icmp);
    }
    if (slog->protocols->igmp > 0) {
        printf("  IGMP : %d", slog->protocols->igmp);
    }
    if (slog->protocols->other > 0) {
        printf("  OTHER : %d", slog->protocols->other);
    }
    printf("  ALL : %d\n", slog->protocols->all);
}