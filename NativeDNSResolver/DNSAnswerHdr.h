#pragma once
#include "pch.h"

#pragma pack(push,1)	// sets struct padding/alignment to 1 byte
class DNSAnswerHdr {
public:
	u_short type;
	u_short _class;
	u_int TTL;
	u_short len;
};
#pragma pack(pop)		// restores old packing
