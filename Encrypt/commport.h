#pragma once

#include "global.h"

BOOLEAN EptInitCommPort();

VOID EptCloseCommPort();

typedef struct EPT_MESSAGE_HEADER
{
	int Command;
	int Length;
}EPT_MESSAGE_HEADER, * PEPT_MESSAGE_HEADER;

//扩展名用 , （英文）分隔，用 , （英文）结束 例如：txt,docx，并在count中记录数量
typedef struct EPT_PROCESS_RULES
{
	char TargetProcessName[260];
	char TargetExtension[100];
	int count;
}EPT_PROCESS_RULES, * PEPT_PROCESS_RULES;

extern EPT_PROCESS_RULES ProcessRules;