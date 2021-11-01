#pragma once

#include <Windows.h>
#include <stdio.h>

#include <fltUser.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "fltLib.lib")

#define COMMPORTNAME L"\\Encrypt-hkx3upper"
#define MESSAGE_SIZE 1024

#define EPT_HELLO_KERNEL			1
#define EPT_INSERT_PROCESS_RULES	2
#define EPT_PRIVILEGE_DECRYPT		4

typedef struct EPT_MESSAGE_HEADER
{
	int Command;
	int Length;

}EPT_MESSAGE_HEADER, *PEPT_MESSAGE_HEADER;

#define EPT_PR_ACCESS_READ_WRITE			0x00000001
#define EPT_PR_ACCESS_BACKUP_RESTORE		0x00000002
#define EPT_PR_ACCESS_NO_ACCESS				0x00000004

//扩展名用 , （英文）分隔，用 , （英文）结束 例如：txt,docx，并在count中记录数量
typedef struct EPT_PROCESS_RULES
{
	LIST_ENTRY ListEntry;
	char TargetProcessName[260];
	char TargetExtension[100];
	int count;
	ULONG Access;
	UCHAR Hash[32];
	BOOLEAN IsCheckHash;

}EPT_PROCESS_RULES, * PEPT_PROCESS_RULES;

typedef struct EPT_MESSAGE_PRIV_DECRYPT
{
	CHAR FileName[260];

}EPT_MESSAGE_PRIV_DECRYPT, * PEPT_MESSAGE_PRIV_DECRYPT;