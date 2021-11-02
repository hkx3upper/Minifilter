#pragma once

#include "global.h"

BOOLEAN EptInitCommPort();

VOID EptCloseCommPort();

#define EPT_HELLO_KERNEL			1
#define EPT_INSERT_PROCESS_RULES	2
#define EPT_PRIVILEGE_DECRYPT		4
#define EPT_PRIVILEGE_ENCRYPT		8

typedef struct EPT_MESSAGE_HEADER
{
	int Command;
	int Length;

}EPT_MESSAGE_HEADER, * PEPT_MESSAGE_HEADER;

typedef struct EPT_MESSAGE_PRIV_DECRYPT
{
	CHAR FileName[260];

}EPT_MESSAGE_PRIV_DECRYPT, * PEPT_MESSAGE_PRIV_DECRYPT;

