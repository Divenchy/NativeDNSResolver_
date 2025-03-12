#pragma once
#include "pch.h"
#pragma pack(push,1)		// Sets struct padding/alignment to 1 byte
class QueryHeader {
public:
	USHORT qType;
	USHORT qClass;
};
// Fill in ID, flags, and num of questions, everything else 0, should have 6 fields, and be 12 bytes long
class FixedDNSHdr {
public:
	USHORT ID;
	USHORT flags;
	USHORT questions;	// Num of questions
	USHORT answers;		// Num of answers
	USHORT authRecords; // Num of authority records
	USHORT addRecords;	// Num of additional records
	FixedDNSHdr(USHORT ID, USHORT flags, USHORT questions, USHORT ans, USHORT authRecords, USHORT addRecords);
};
#pragma pack(pop)			// restores old packing
