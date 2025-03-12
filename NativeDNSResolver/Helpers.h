#pragma once
#include "pch.h"
#include "FixedDNSHdr.h"
#include "DNSAnswerHdr.h"

unsigned int ipTo32Bit(const char* ip_str);
int encodedHostname(const char *host, char *packet);
void *parseResponse(char *buf, int pktSize, USHORT sendPktTXID);
