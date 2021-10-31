#pragma once

#include "global.h"

BOOLEAN EptInitCommPort();

VOID EptCloseCommPort();

#define EPT_INSERT_PROCESS_RULES 2

typedef struct EPT_MESSAGE_HEADER
{
	int Command;
	int Length;

}EPT_MESSAGE_HEADER, * PEPT_MESSAGE_HEADER;

