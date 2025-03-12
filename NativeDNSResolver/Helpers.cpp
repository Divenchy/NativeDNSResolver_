#include "pch.h"
#include "Helpers.h"

unsigned int ipTo32Bit(const char *ip_str) {
	unsigned int oct1, oct2, oct3, oct4;
	// Read from string
	if (sscanf_s(ip_str, "%u.%u.%u.%u", &oct1, &oct2, &oct3, &oct4) != 4) {
		printf("Incorrect format: %s\n", ip_str);
		return -1;
	}

	// Validate int values
	if (oct1 > 255 || oct2 > 255 || oct3 > 255 || oct4 > 255) {
		// fprintf for sending errors to error stream
		fprintf(stderr, "IP octet out of range\n");
		return -1;
	}


	// Return 32-bit IP interger using bitwise operations
	return (oct1 << 24) | (oct2 << 16) | (oct3 << 8) | oct4;
}

// Returns num of bytes written
int encodedHostname(const char *host, char *packet) {
	int pos = 0;
	const char *start = host;
	const char *end = host;
	// Loop until reach every .
	while (*end) {
		if (*end == '.') {
			int segmentLen = end - start;
			// Extending size of packet
			if (pos + 1 + segmentLen > MAX_DNS_SIZE) {
				printf("Error encoding hostname due to not enough space in buffer.\n");
				return -1;
			}
			packet[pos++] = (char)segmentLen;
			memcpy_s(packet + pos, MAX_DNS_SIZE - pos, start, segmentLen);
			pos += segmentLen;
			start = end + 1;
		}
		end++;
	}

	// Empty string, encode last [0]
	int segmentLen = end - start;
	if (segmentLen > 0) {
		if (pos + 1 + segmentLen > MAX_DNS_SIZE) {
			printf("Error encoding hostname due to not enough space in buffer.\n");
			return -1;
		}
		packet[pos++] = (char)segmentLen;
		memcpy_s(packet + pos, MAX_DNS_SIZE - pos, start, segmentLen);
		pos += segmentLen;
	}
	packet[pos++] = 0;
	return pos;
}


int determineQueryType(char *host, char *packet, int &offset, FixedDNSHdr *fdh) {
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
		printf("Query   : %s, type %d, TXID 0x%X\n", host, ntohs(qh->qClass), fdh->ID);

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
		printf("Query   : %s, type %d, TXID 0x%4X\n", PTRQueryIP, ntohs(qh->qType), fdh->ID);
	}

}

int decodeDNSName(char *buf, int curOffset, int pktSize, char *domainName, int sizeOfName) {
	int posDomainName = 0;
	int origOffset = curOffset;
	bool compressed = false;	// Check if compression pointer is used
	int compressedOffset = 0;	// Offset to jump to

	// To identify if compressed first byte is 0xC0 (first two bits are 1)
	// If compressed then the next byte is a pointer to the offset where the name is
	// The next 14 bits is an encoded offset to the name
	// If not compressed, then the first byte is the length of the next segment

	// Counter to track if infinite loop
	int numJumps = 0;
	while ((curOffset < pktSize) && buf[curOffset] != 0) {
		unsigned char len = buf[curOffset];
		if (numJumps >= 10) {
			printf("  ++ invalid record: jump loop\n");
			return 500;
		}
		if ((len & 0xC0) == 0xC0) {
			numJumps++;
			// Compressed, get pointer
			if (curOffset + 1 >= pktSize) {		// Malformed pkt (nothing after pointer)
				printf("  ++ invalid record: truncated jump offset\n");
				return 500;
			}
			// Mask out the first two bits (the 11) and then keep the remaining 6 bits to join them with the next 8 bits forming the 14-bit offset
			int pointer = ((len & 0x3F) << 8) | buf[curOffset + 1];
			if (pointer < sizeof(FixedDNSHdr)) {
				// Jumped into header area, uh oh
				printf("  ++ invalid record: jump into fixed DNS header\n");
				return 500;
			}
			if (pointer >= pktSize) {
				printf("  ++ invalid record: jump beyond packet boundary\n");
				return 500;
			}
			if (!compressed) {
				compressedOffset = curOffset + 2;
			}
			curOffset = pointer;
			compressed = true;
			continue;
		}
		else {
			// Not compressed
			if (curOffset >= pktSize) {		// Malformed pkt
				printf("  ++ invalid record: truncated name\n");
				return 500;
			}

			curOffset++;	// Moving from len
			for (int i = 0; i < len && curOffset + i < pktSize; i++) {
				if (posDomainName < sizeOfName - 1) {
					domainName[posDomainName++] = buf[curOffset + i];
				}
			}
			curOffset += len;
			// See if more for name
			if ((buf[curOffset] != 0) && (posDomainName < sizeOfName - 1)) {
				domainName[posDomainName++] = '.';
			}
		}
	}

	// Null terminate decoded domain name
	if ((posDomainName > 0) && domainName[posDomainName - 1] == '.') {
		domainName[posDomainName - 1] = '\0';
	}
	else {
		domainName[posDomainName] = '\0';
	}

	// Check if jumped
	// If we jumped, resume at jumpOffset; otherwise, move past the null terminator.
	if (compressed) {
		return compressedOffset - origOffset;
	} 
	else {
		return (curOffset - origOffset) + 1;
	}
}

void *parseResponse(char *buf, int pktSize, USHORT sendPktTXID) {
	// Check if reply is too small
	if (pktSize < sizeof(FixedDNSHdr)) {
		printf("  ++ invalid reply: packet smaller than fixed DNS header\n");	// malformed packet
		return (void *) -1;
	}

	// Parse the received packet
	int offset = 0;
	FixedDNSHdr *fdh = (FixedDNSHdr *)buf;
	// read fdh->ID and other fields
	// Read ID, every field is aligned to be 2 bytes long
	fdh->ID = (*(USHORT *)buf);
	// Read flags
	fdh->flags = ntohs(*(USHORT *)(buf + 2));
	// Read questions
	fdh->questions = ntohs(*(USHORT *)(buf + 4));
	// Read answers
	fdh->answers = ntohs(*(USHORT *)(buf + 6));
	// Read authRecords
	fdh->authRecords = ntohs(*(USHORT *)(buf + 8));
	// Read addRecords
	fdh->addRecords = ntohs(*(USHORT *)(buf + 10));
	offset = sizeof(FixedDNSHdr);	// Move 12
	printf("  TXID: 0x%.4X, flags: 0x%.4X, questions: %d, answers: %d, authority: %d, additional: %d\n", fdh->ID, fdh->flags, fdh->questions, fdh->answers, fdh->authRecords, fdh->addRecords);
	if (fdh->ID != sendPktTXID) {
		printf("  ++ invalid reply: TXID mismatch, sent 0x%.4X, received 0x%.4X\n", sendPktTXID, fdh->ID);
		return 0;
	}

	// Check if response is valid, extract lowest 4 bits, mask others
	int rCode = (fdh->flags & 0x000F);
	if (rCode == 0) {
		printf("  succeeded with Rcode = %d\n", rCode);
	}
	else {
		printf("  failed with Rcode = %d\n", rCode);
		return (void *) -1;
	}

	// Variable to keep track of number of records
	int numRecords = 0;

	// Questions section, encoded hostname ends with 0 (e.g. [3] www [6] google [3] com [0])
	// Also check for compression pointer
	if (fdh->questions > 0) {
		printf("  ------------ [questions] ----------\n");
	}
	for (int i = 0; i < fdh->questions; i++) {
		// Decode response
		char domainName[256];
		int domainLength = decodeDNSName(buf, offset, pktSize, domainName, 256);
		// Check hit inside
		if (domainLength == 500) {
			return (void *)-1;
		}
		if (domainLength < 0) {
			printf("  ++ invalid record: truncated name\n");
			return (void *)-1;
		}
		offset += domainLength;
		// Skip Qtype and Qclass, each 2 bytes
		USHORT qType = ntohs(*(USHORT *)(buf + offset));
		USHORT qClass = ntohs(*(USHORT *)(buf + offset + 2));
		printf("        %s type %d class %d\n", domainName, qType, qClass);
		offset += 4;
		numRecords++;
	}

	// Check section
	if (numRecords != fdh->questions) {
		printf("  ++ invalid section: not enough records\n");
		return (void *) -1;
	}
	numRecords = 0;
	
	// Parse answers
	// DNS answers given in the form of domain name --> answer header --> RDATA --> answer
	if (fdh->answers > 0) {
		printf("  ------------ [answers] ----------\n");
	}
	for (int i = 0; i < fdh->answers; i++) {
		// Decode response, starts with RR namee
		char _domainName[256];
		int domainLength = decodeDNSName(buf, offset, pktSize, _domainName, 256);
		// Check hit inside
		if (domainLength == 500) {
			return (void *)-1;
		}
		if (domainLength < 0) {
			printf("  ++ invalid record: truncated name\n");
			return (void *)-1;
		}
		offset += domainLength;
		printf("        %s ", _domainName);


		// Before reading DNSAns check if there is 10 bytes atleast, if not then truncated answer
		if ((offset + sizeof(DNSAnswerHdr)) > pktSize) {
			printf("  ++ invalid record: truncated RR answer header\n");
		}

		// Read type and class
		// For type-A answer is a 4-byte IP
		DNSAnswerHdr *dah = (DNSAnswerHdr *)(buf + offset);
		dah->type = ntohs(*(USHORT *)(buf + offset));
		dah->_class = ntohs(*(USHORT *)(buf + offset + 2));
		dah->TTL = ntohl(*(ULONG *)(buf + offset + 4));
		dah->len = ntohs(*(USHORT *)(buf + offset + 8));	// Length of answer
		offset += sizeof(DNSAnswerHdr);
		
		if (offset + dah->len > pktSize) {
			printf("  ++ invalid record: RR value length stretches the answer beyond packet\n");
			return (void *) - 1;
		}

		// Type A
		if (dah->type == DNS_A) {
			// IP is 4 bytes
			if (dah->len != 4) {
				printf("Error: IP length is not 4 bytes\n");
				return (void *) -1;
			}
			char ipStr[INET_ADDRSTRLEN];
			struct in_addr ipAddr; // From MSDN can be formatted as four u_chars
			memcpy(&ipAddr, buf + offset, 4);
			// MSDN ipv4 address to string, AF_INET for IPv4
			inet_ntop(AF_INET, &ipAddr, ipStr, sizeof(ipStr));
			printf("A %s ", ipStr);
		}
		else if (dah->type == DNS_PTR) {
			// Type PTR
			char ptrName[256];
			int domainLength = decodeDNSName(buf, offset, pktSize, ptrName, sizeof(ptrName));
			// Check hit inside
			if (domainLength == 500) {
				return (void *)-1;
			}
			printf("PTR %s ", ptrName);
		}
		else if (dah->type == DNS_CNAME) {
			// Type CNAME
			char ptrName[256];
			int domainLength = decodeDNSName(buf, offset, pktSize, ptrName, sizeof(ptrName));
			// Check hit inside
			if (domainLength == 500) {
				return (void *) -1;
			}
			printf("CNAME %s ", ptrName);
		}
		else {
			printf("Unknown type %d", dah->type);
		}
		printf("TTL = %d\n", dah->TTL);
		offset += dah->len;
		numRecords++;
	}

	// Check section
	if (numRecords != fdh->answers) {
		printf("  ++ invalid section: not enough records\n");
		return (void *) -1;
	}
	numRecords = 0;

	// Parse authority records
	if (fdh->authRecords > 0) {
		printf("  ------------ [authority] ----------\n");
	}
	for (int i = 0; i < fdh->authRecords; i++) {
		// Decode response
		char _domainName[256];
		int domainLength = decodeDNSName(buf, offset, pktSize, _domainName, 256);
		// Check hit inside
		if (domainLength == 500) {
			return (void *) -1;
		}
		if (domainLength < 0) {
			printf("  ++ invalid record: truncated name\n");
			return (void *)-1;
		}
		offset += domainLength;
		printf("        %s ", _domainName);

		// Before reading DNSAns check if there is 10 bytes atleast, if not then truncated answer
		if ((offset + sizeof(DNSAnswerHdr)) > pktSize) {
			printf("  ++ invalid record: truncated RR answer header\n");
			return (void *)-1;
		}

		// Read type and class
		// For type-A answer is a 4-byte IP
		DNSAnswerHdr *dah = (DNSAnswerHdr *)(buf + offset);
		dah->type = ntohs(*(USHORT *)(buf + offset));
		dah->_class = ntohs(*(USHORT *)(buf + offset + 2));
		dah->TTL = ntohl(*(ULONG *)(buf + offset + 4));
		dah->len = ntohs(*(USHORT *)(buf + offset + 8));	// Length of answer
		offset += sizeof(DNSAnswerHdr);


		// Parse records
		if (dah->type == DNS_NS) {
			// Type NS
			char nsName[256];
			int domainLength = decodeDNSName(buf, offset, pktSize, nsName, sizeof(nsName));
			// Check hit inside
			if (domainLength == 500) {
				return (void *) -1;
			}
			printf("NS %s ", nsName);
		}
		else {
			printf("Unknown type %d", dah->type);
		}
		printf("TTL = %d\n", dah->TTL);
		offset += dah->len;
		numRecords++;
	}

	// Check section
	if (numRecords != fdh->authRecords) {
		printf("  ++ invalid section: not enough records\n");
		return (void *) -1;
	}
	numRecords = 0;

	// Parse additional records
	if (fdh->addRecords > 0) {
		printf("  ------------ [additional] ----------\n");
	}
	for (int i = 0; i < fdh->addRecords; i++) {
		// Decode response
		char _domainName[256];
		int domainLength = decodeDNSName(buf, offset, pktSize, _domainName, 256);
		// Check hit inside
		if (domainLength == 500) {
			return (void *)-1;
		}
		if (domainLength < 0) {
			printf("  ++ invalid record: truncated name\n");
			return (void *)-1;
		}
		offset += domainLength;
		printf("        %s ", _domainName);

		// Before reading DNSAns check if there is 10 bytes atleast, if not then truncated answer
		if ((offset + sizeof(DNSAnswerHdr)) > pktSize) {
			printf("  ++ invalid record: truncated RR answer header\n");
			return (void *)-1;
		}

		// Read type and class
		// For type-A answer is a 4-byte IP
		DNSAnswerHdr *dah = (DNSAnswerHdr *)(buf + offset);
		dah->type = ntohs(*(USHORT *)(buf + offset));
		dah->_class = ntohs(*(USHORT *)(buf + offset + 2));
		dah->TTL = ntohl(*(ULONG *)(buf + offset + 4));
		dah->len = ntohs(*(USHORT *)(buf + offset + 8));	// Length of answer
		offset += sizeof(DNSAnswerHdr);


		// Parse records
		if (dah->type == DNS_A) {
			// Type A
			// IP is 4 bytes
			if (dah->len != 4) {
				printf("Error: IP length is not 4 bytes\n");
				return 0;
			}
			char ipStr[INET_ADDRSTRLEN];
			struct in_addr ipAddr; // From MSDN can be formatted as four u_chars
			memcpy(&ipAddr, buf + offset, 4);
			// MSDN ipv4 address to string, AF_INET for IPv4
			inet_ntop(AF_INET, &ipAddr, ipStr, sizeof(ipStr));
			printf("A %s ", ipStr);
		}
		else if (dah->type == DNS_PTR) {
			// Type PTR
			char ptrName[256];
			int domainLength = decodeDNSName(buf, offset, pktSize, ptrName, sizeof(ptrName));
			// Check hit inside
			if (domainLength == 500) {
				return (void *) -1;
			}
			printf("PTR %s ", ptrName);
		}
		else if (dah->type == DNS_CNAME) {
			// Type CNAME
			char ptrName[256];
			int domainLength = decodeDNSName(buf, offset, pktSize, ptrName, sizeof(ptrName));
			// Check hit inside
			if (domainLength == 500) {
				return (void *) -1;
			}
			printf("CNAME %s ", ptrName);
		}
		else {
			printf("Unknown type %d", dah->type);
		}
		printf("TTL = %d\n", dah->TTL);
		offset += dah->len;
		numRecords++;
	}

	// Check section
	if (numRecords != fdh->addRecords) {
		printf("  ++ invalid section: not enough records\n");
		return (void *) -1;
	}
	numRecords = 0;

	return 0;
}
