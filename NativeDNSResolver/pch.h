// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

// add headers that you want to pre-compile here
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <atomic>
#include <stdio.h>
#include <set>
#include <string>
#include <ctime>
#include <queue>
#include "common.h"
#include "Helpers.h"

#pragma comment(lib, "Ws2_32.lib")

#endif //PCH_H
