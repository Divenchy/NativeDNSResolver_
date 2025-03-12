#include "pch.h"
#include "FixedDNSHdr.h"

FixedDNSHdr::FixedDNSHdr(USHORT ID, USHORT flags, USHORT questions, USHORT ans, USHORT authRecords, USHORT addRecords) {
	this->ID = ID;
	this->flags = flags;
	this->questions = questions;
	this->answers = ans;
	this->authRecords = authRecords;
	this->addRecords = addRecords;
}
