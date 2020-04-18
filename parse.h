#ifndef __PARSE_H__
#define __PARSE_H__

#include "common.h"
#include "tools.h"

// parse datalink frames
void parseFrame(BUFFER buffer, int size, snifferLog* slog);

// parse IP Packet
void parseIP(BUFFER buffer, int size, snifferLog* slog);

// parse IP header
void parseIPHeader(BUFFER buffer, int size, snifferLog* slog);
// parse ICMP header
void parseICMPHeader(BUFFER buffer, int size, snifferLog* slog);
// parse TCP header
void parseTCPHeader(BUFFER buffer, int size, snifferLog* slog);
// parse UDP header
void parseUDPHeader(BUFFER buffer, int size, snifferLog* slog);

// print payload
void printPayload(BUFFER buffer, int size, snifferLog* slog);

#endif // !__PARSE_H__