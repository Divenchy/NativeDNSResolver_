#include "pch.h"
#include "FixedDNSHdr.h"
#include "DNSAnswerHdr.h"


// TESTING
// random9.irl 128.194.135.82


int main(int argc, char** argv) {
	// Include NativeDNSResolver.cpp in arg count
	if (argc != 3) {
		printf("Usage: {hostname or IP} {DNS server IP}");
	}

	// Setup
	int offset = 0;	// Offset in outgoing packet (where are we in the packet)
	char *host = argv[1];
	struct sockaddr_in local;
	struct sockaddr_in remote;
	struct hostent *dns;
	int pktSize = strlen(host) + 2 + sizeof(FixedDNSHdr) + sizeof(QueryHeader);

	// Send packet (outgoing)
	char *packet = new char[MAX_DNS_SIZE]; // 512

	// Seed for random TXID
	srand((unsigned)time(NULL));

	//From homework 
	// FixedDNSheader *fdh = (FixedDNSheader *) buf;
	// QueryHeader *qh = (QueryHeader*) (buf + pkt_size – sizeof(QueryHeader));

	// Initialize FDH
	FixedDNSHdr *fdh = (FixedDNSHdr *) packet;		// Copies the fdh directly into the packet instead of through memcpy_s
	USHORT randID = (USHORT)(rand() % 0x10000);
	fdh->ID = htons(randID); // Set to random number
	fdh->flags = htons(DNS_QUERY | DNS_RD | DNS_STDQUERY); // Set flags --> query, with recursion desired and stadard query (opcode)
	fdh->questions = htons(1); // One question
	fdh->answers = 0;
	fdh->authRecords = 0;
	fdh->addRecords = 0;

	// Offset in packet, offset in class size not ptr size
	offset += sizeof(FixedDNSHdr);

	int iResult;
	WSADATA wsaData;

	int BufLen = 1024;

	//// DECIDE QUERY TYPE ////

	printf("Lookup  : %s\n", host);
	// Determine whether the query is an IP or hostname
	// If success, proceed with PTR query, otherwise type-A

	DWORD IP = inet_addr(host); // Network Byte Order
	if (IP == INADDR_NONE)
	{
		// type-A query
		// e.g www.google.com
		// [3] www [6] google [3] com [0]
		// Ensure that 3 and 6 stuff gets added too
		int hostLen = encodedHostname(host, packet + offset);
		if (hostLen < 0) {
			printf("Error: not enough space in buffer\n");
			return -1;
		}
		if (hostLen == 0) {
			printf("Error occurred during encoding hostname\n");
			return -1;
		}
		else if (hostLen == 1) {
			printf("Encoded host is length 0\n");
			return -1;
		}
		offset += hostLen;


		// Set Qtype and class

		QueryHeader* qh = (QueryHeader*)(packet + offset);
		qh->qClass = htons(1);	// A-type query
		qh->qType = htons(1);	// Internet
		offset += sizeof(QueryHeader);
		printf("Query   : %s, type %d, TXID 0x%.4X\n", host, ntohs(qh->qClass), fdh->ID);

	}
	else
	{
		/// type-PTR query
		
		// Extract Octet, already reversed in IP
		unsigned int oct1, oct2, oct3, oct4;
		oct1 = (IP >> 24) & 0xFF;
		oct2 = (IP >> 16) & 0xFF;
		oct3 = (IP >> 8) & 0xFF;
		oct4 = (IP) & 0xFF;


		// Reverse and append .in-addr.arpa
		char PTRQueryIP[64];
		sprintf_s(PTRQueryIP, "%u.%u.%u.%u.in-addr.arpa", oct1, oct2, oct3, oct4);
		//printf("PTR: %s\n", PTRQueryIP);

		// After reversing, encode like in A-type
		int hostLen = encodedHostname(PTRQueryIP, packet + offset);
		if (hostLen < 0) {
			printf("Error: not enough space in buffer\n");
			return -1;
		}
		if (hostLen == 0) {
			printf("Error occurred during encoding hostname\n");
			return -1;
		}
		else if (hostLen == 1) {
			printf("Encoded host is length 0\n");
			return -1;
		}
		offset += hostLen;

		QueryHeader* qh = (QueryHeader*)(packet + offset);
		qh->qType = htons(12);  // PTR record
		qh->qClass = htons(1);  // Internet
		offset += sizeof(QueryHeader);
		printf("Query   : %s, type %d, TXID 0x%.4X\n", PTRQueryIP, ntohs(qh->qType), fdh->ID);
	}

	// Resulting packet
	//printf("Constructed Packet (%d bytes):\n", offset);
	//for (int i = 0; i < offset; i++) {
	//	printf("%02X ", (unsigned char)packet[i]);
	//	if ((i + 1) % 16 == 0)
	//		printf("\n");
	//}
	//printf("\n");

	printf("Server  : %s\n", argv[2]);
	printf("*******************************\n");

	// Init winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != NO_ERROR) {
		wprintf(L"WSAStartup failed with error: %d\n", iResult); // Used in MSDN
		return -1;
	}

	// Create socket and open UDP socket
	SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
	// Handle errors
	if (sock == INVALID_SOCKET) {
		wprintf(L"Error in creating socket, %d\n", WSAGetLastError());
		WSACleanup();
		return -1;
	}

	// Local setup
	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = INADDR_ANY;		// Allows to receive packets on all physical interfaces
	local.sin_port = htons(0);		// Let OS decide next port

	// No connect phase and sockets can be used immediately after binding
	// Acting as receiver
	memset(&remote, 0, sizeof(remote));
	remote.sin_family = AF_INET;
	remote.sin_addr.s_addr = inet_addr(argv[2]);		// server's IP
	remote.sin_port = htons(53);	// DNS port on server


	// Bind socket
	if (bind(sock, (struct sockaddr*)&local, sizeof(local)) == SOCKET_ERROR) {
		wprintf(L"Error in binding socket, %d\n", WSAGetLastError());			// MSDN uses wprintf
		closesocket(sock);
		WSACleanup();
		return -1;
	}

	///// LOOP FOR MAX ATTEMPTS IN CASE OF PACKET LOSS /////
	// don't need to loop to recieve data as in HW1 as in this we send a packet and receive a packet (in HW1 we received data in chunks not here we just get all at once//
	// this loop is just in case of packet loss, so loop until we have successfully received a packer //
	// or until we have reached the max number of attempts //

	/* Also be mindful of timeouts in sending/receiving packets*/
	int count = 0;
	int _offset = 0;
	// timeval {tp.sec = 10, tp.usec = 0}
    const timeval tp = {10, 0};	// 10 second timeout
	while (count < MAX_ATTEMPTS) {

		printf("Attempt %d with %d bytes... ", count, offset);
		count++;
		// sendto signature --> (socket, buf, length of buf, 0, receiveAddr, sizeof(receiveAddr) )
		// offset should be used for length of DNS packet
		int startSendReceive = clock();
		if (sendto(sock, packet, offset, 0, (struct sockaddr*)&remote, sizeof(remote)) == SOCKET_ERROR) {
			wprintf(L"sendto failed with error: %d\n", WSAGetLastError());
			continue;
		}

		// get ready to receive
		fd_set fd;
		FD_ZERO(&fd);
		FD_SET(sock, &fd);
		int available = select(0, &fd, NULL, NULL, &tp);
		// Error and timeout check
		if (available == SOCKET_ERROR) {
			wprintf(L"select failed with error: %d\n", WSAGetLastError());
			continue;
		}
		if (available == 0) {
			printf("timeout in %d ms\n", clock() - startSendReceive);
			continue;
		}


		if (available > 0) {
			//// Now receive answers
			// revfrom done as in MSDN https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recvfrom example
			char *buf = new char[MAX_DNS_SIZE];
			struct sockaddr_in response;
			int response_len = sizeof(response);
			// Get size of received packet and packet into buf
			iResult = recvfrom(sock, buf, MAX_DNS_SIZE, 0, (struct sockaddr *)&response, &response_len);		// MSDN style
			if (iResult == SOCKET_ERROR) {
				wprintf(L"recvfrom failed with error: %d\n", WSAGetLastError());
				continue;
			}

			// check if this packet came from the server to which we sent the query earlier, from hw
			if (response.sin_addr.s_addr != remote.sin_addr.s_addr || response.sin_port != remote.sin_port) {
				printf("Received packet from unknown source\n");
				continue;
			}

			// Got packet from right source
			printf("response in %d ms with %d bytes\n", clock() - startSendReceive, iResult);

			///// Parse the received packet
			parseResponse(buf, iResult, fdh->ID);

			// Read received packet successfully, break
			break;
		}

		// error checking here?? Maybe?
	}

	// When finished with socket, close socket
	if (closesocket(sock) == SOCKET_ERROR) {
		wprintf(L"Error in closing socket after sending, %d", WSAGetLastError());
		WSACleanup();
		return -1;
	}
	// Clean up and quit.
	WSACleanup();
	return 0;
}

