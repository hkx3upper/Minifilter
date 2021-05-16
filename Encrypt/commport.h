#pragma once

#include "global.h"

BOOLEAN EptInitCommPort();

VOID EptCloseCommPort();

typedef struct EPT_MESSAGE_HEADER
{
	int Command;
	int Length;

}EPT_MESSAGE_HEADER, * PEPT_MESSAGE_HEADER;

