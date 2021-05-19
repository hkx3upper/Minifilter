#pragma once

#include <Windows.h>
#include <stdio.h>

#include <fltUser.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "fltLib.lib")

#define COMMPORTNAME L"\\Encrypt-hkx3upper"
#define MESSAGE_SIZE 1024

typedef struct EPT_MESSAGE_HEADER
{
	int Command;
	int Length;
}EPT_MESSAGE_HEADER, *PEPT_MESSAGE_HEADER;

//扩展名用 , （英文）分隔，用 , （英文）结束 例如：txt,docx，并在count中记录数量
typedef struct EPT_PROCESS_RULES
{
	char TargetProcessName[MAX_PATH];
	char TargetExtension[100];
	int count;
	UCHAR Hash[32];

}EPT_PROCESS_RULES, * PEPT_PROCESS_RULES;