#ifndef __TOOLS_H__
#define __TOOLS_H__

#include "common.h"

void showTime();
void initScreen();

// set interface to promiscuous mode or not
bool togglePromiscuous(int sd, char* ifrName, int isPromiscuous);

// init socket and set interface to promiscuous mode
int initSocket(char* ifrName, allProtocols protocolType, bool isPromiscuous);

// deinit socket and set interface back
void deinitSocket(int sd, char* ifrName);

// show catches for IP packets
void showCatch(snifferLog* slog);

#endif // !__TOOLS_H__
