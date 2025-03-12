// Leonardo Frias CSCE463-500 Spring 2025
#pragma once
#include "pch.h"

class Socket
{
public:
	SOCKET sock;

	struct hostent* remote;

	struct sockaddr_in server;

	char* buf;				// current buffer
	int allocatedSize;		// bytes allocated for buf
	int curPos;				// current position in the buffer	

	Socket();
	~Socket();
	int connectToServer(SOCKET sock, hostent* remote, sockaddr_in& server, char* host, char* port, bool isRobots);
	int sendHTTPRequest(char* host, char* path, char* query, bool isRobots);
	int DNSLookup(SOCKET sock, hostent* remote, sockaddr_in& server, char* host, char* port, bool& lookupDone, char*& IP_str, bool verify, int& successLookups, int& passedIPUniqueness);
	bool Read(bool isRobots);
	int parseHTTPResponse(char* host, bool isRobots);
};