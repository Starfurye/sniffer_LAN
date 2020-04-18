#include "parse.h"

void parseFrame(BUFFER buffer, int size, snifferLog* slog) {
    const struct ether_header* ethh = (const struct ether_header*)buffer;
    int i = 0;

    fprintf(slog->log, "\n\n\n<Ethnet Header>\n");

    fprintf(slog->log, "[Src MAC] ");
    for (i = 0; i < ETHER_ADDR_LEN - 1; ++i) {
        fprintf(slog->log, "%02x:", ethh->ether_shost[i]);
    }
    fprintf(slog->log, "%02x\n", ethh->ether_shost[i]);
    fprintf(slog->log, "[Dst MAC] ");
    for (i = 0; i < ETHER_ADDR_LEN - 1; ++i) {
        fprintf(slog->log, "%02x:", ethh->ether_dhost[i]);
    }
    fprintf(slog->log, "%02x", ethh->ether_dhost[i]);

    buffer += sizeof(struct ether_header);
    size -= sizeof(struct ether_header);

    switch (ntohs(ethh->ether_type))
    {
    case ETHERTYPE_IP:
        parseIP(buffer, size, slog);
        break;
    
    default:
        printf("\nshould not reach here\n");
        break;
    }
}

void parseIP(BUFFER buffer, int size, snifferLog* slog) {
    struct iphdr* iph = (struct iphdr*)buffer;
    ++slog->protocols->all;

    switch (iph->protocol)
    {
    case 1:
        ++slog->protocols->icmp;
        parseICMPHeader(buffer, size, slog);
        break;
    case 2:
        ++slog->protocols->igmp;
        // TODO
        break;
    case 6:
        ++slog->protocols->tcp;
        parseTCPHeader(buffer, size, slog);
        break;

    case 17:
        ++slog->protocols->udp;
        parseUDPHeader(buffer, size, slog);
        break;

    default:
        ++slog->protocols->other;
        break;
    }

    showTime();
    showCatch(slog);
}

void parseIPHeader(BUFFER buffer, int size, snifferLog* slog) {
    struct iphdr* iph;
    struct sockaddr_in source;
    struct sockaddr_in destination;

    iph = (struct iphdr*)buffer;
    
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    memset(&destination, 0, sizeof(destination));
    destination.sin_addr.s_addr = iph->daddr;

    fprintf(slog->log,"\n");
    fprintf(slog->log,"<IP Header>\n");
    fprintf(slog->log,"      [IP Version] %d\n",(unsigned int)iph->version);
    fprintf(slog->log,"[IP Header Length] %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(slog->log," [Type Of Service] %d\n",(unsigned int)iph->tos);
    fprintf(slog->log," [IP Total Length] %d Bytes(size of Packet)\n",ntohs(iph->tot_len));
    fprintf(slog->log,"  [Identification] %d\n",ntohs(iph->id));
    fprintf(slog->log,"             [TTL] %d\n",(unsigned int)iph->ttl);
    fprintf(slog->log,"        [Protocol] %d\n",(unsigned int)iph->protocol);
    fprintf(slog->log,"        [Checksum] %d\n",ntohs(iph->check));
    fprintf(slog->log,"          [Src IP] %s\n",inet_ntoa(source.sin_addr));
    fprintf(slog->log,"          [Dst IP] %s\n",inet_ntoa(destination.sin_addr));
}
void parseICMPHeader(BUFFER buffer, int size, snifferLog* slog) {
    struct iphdr* iph;
    struct icmphdr* icmph;
    unsigned short iphlen;

    iph = (struct iphdr*)buffer;
    iphlen = iph->ihl * 4;
    icmph = (struct icmphdr*)(buffer + iphlen);

    fprintf(slog->log,"\n");
    fprintf(slog->log,"\n\n============ ICMP PACKET ============");
    parseIPHeader(buffer, size, slog);

    fprintf(slog->log, "\n");
    fprintf(slog->log,"<ICMP Header>\n");
    fprintf(slog->log,"           [Type] %d",(unsigned int)(icmph->type));  
    if((unsigned int)(icmph->type) == 11) 
        fprintf(slog->log,"    (TTL Expired)\n");
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY) 
        fprintf(slog->log,"(ICMP Echo Reply)\n");
    fprintf(slog->log,"           [Code] %d\n",(unsigned int)(icmph->code));
    fprintf(slog->log,"       [Checksum] %d\n",ntohs(icmph->checksum));
    fprintf(slog->log,"\n");

    fprintf(slog->log,"IP Header\n");
    printPayload(buffer, iphlen, slog);
    fprintf(slog->log,"UDP Header\n");
    printPayload(buffer + iphlen, sizeof(icmph), slog);
    fprintf(slog->log,"Data Payload\n");
    printPayload(buffer + iphlen + sizeof(icmph), 
                (size - sizeof(icmph) - iph->ihl * 4),
                slog);
    
    fprintf(slog->log,"\n=======================================");
}
void parseTCPHeader(BUFFER buffer, int size, snifferLog* slog) {
    struct iphdr* iph;
    struct tcphdr* tcph;
    unsigned short iphlen;

    iph = (struct iphdr*)buffer;
    iphlen = iph->ihl * 4;
    tcph = (struct tcphdr*)(buffer + iphlen);
    parseIPHeader(buffer, size, slog);
    
    fprintf(slog->log,"\n");
    fprintf(slog->log,"<TCP Header>\n");
    fprintf(slog->log,"         [Source Port] %u\n",ntohs(tcph->source));
    fprintf(slog->log,"    [Destination Port] %u\n",ntohs(tcph->dest));
    fprintf(slog->log,"     [Sequence Number] %u\n",ntohl(tcph->seq));
    fprintf(slog->log,"  [Acknowledge Number] %u\n",ntohl(tcph->ack_seq));
    fprintf(slog->log,"       [Header Length] %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff * 4);
    fprintf(slog->log,"         [Urgent Flag] %d\n",(unsigned int)tcph->urg);
    fprintf(slog->log,"[Acknowledgement Flag] %d\n",(unsigned int)tcph->ack);
    fprintf(slog->log,"           [Push Flag] %d\n",(unsigned int)tcph->psh);
    fprintf(slog->log,"          [Reset Flag] %d\n",(unsigned int)tcph->rst);
    fprintf(slog->log,"    [Synchronise Flag] %d\n",(unsigned int)tcph->syn);
    fprintf(slog->log,"         [Finish Flag] %d\n",(unsigned int)tcph->fin);
    fprintf(slog->log,"              [Window] %d\n",ntohs(tcph->window));
    fprintf(slog->log,"            [Checksum] %d\n",ntohs(tcph->check));
    fprintf(slog->log,"      [Urgent Pointer] %d\n",tcph->urg_ptr);
    fprintf(slog->log,"\n");
    fprintf(slog->log,"                        DATA Dump                         ");
    fprintf(slog->log,"\n");

    fprintf(slog->log,"IP Header\n");
    printPayload(buffer, iphlen, slog);

    fprintf(slog->log,"TCP Header\n");
    printPayload(buffer + iphlen, tcph->doff * 4, slog);

    fprintf(slog->log,"Data Payload\n");
    printPayload(buffer + iphlen + tcph->doff * 4,
                (size - tcph->doff*4-iph->ihl*4),
                slog);

    fprintf(slog->log,"\n=======================================");
}
void parseUDPHeader(BUFFER buffer, int size, snifferLog* slog) {
    struct iphdr* iph;
    struct udphdr* udph;
    unsigned short iphlen;

    iph = (struct iphdr*)buffer;
    iphlen = iph->ihl * 4;
    udph = (struct udphdr*)(buffer + iphlen);
    fprintf(slog->log,"\n\n============ UDP PACKET ============\n");    
    parseIPHeader(buffer, size, slog);

    fprintf(slog->log,"\n<UDP Header>\n");
    fprintf(slog->log,"     [Source Port] %d\n" , ntohs(udph->source));
    fprintf(slog->log,"[Destination Port] %d\n" , ntohs(udph->dest));
    fprintf(slog->log,"      [UDP Length] %d\n" , ntohs(udph->len));
    fprintf(slog->log,"    [UDP Checksum] %d\n" , ntohs(udph->check));
    
    fprintf(slog->log,"\n");
    fprintf(slog->log,"IP Header\n");
    printPayload(buffer, iphlen, slog);
    
    fprintf(slog->log,"UDP Header\n");
    printPayload(buffer + iphlen, sizeof(udph), slog);
    
    fprintf(slog->log,"Data Payload\n");
    printPayload(buffer + iphlen + sizeof udph,
            (size - sizeof udph - iph->ihl * 4),
            slog);
    
    fprintf(slog->log,"\n=======================================");
}

void printPayload(BUFFER buffer, int size, snifferLog* slog) {
    int	i;
    for(i = 0; i < size; i++) {
        if(i % 16 == 0) {
            fprintf(slog->log, "\n");
        }
        fprintf(slog->log, " %02X", (unsigned int)buffer[i]);
        if(i == size - 1) {
	        fprintf(slog->log, "\n");
	    }
    }
}