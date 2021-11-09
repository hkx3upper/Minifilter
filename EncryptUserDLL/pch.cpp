// pch.cpp: 与预编译标头对应的源文件

#include "pch.h"

// 当使用预编译的头时，需要使用此源文件，编译才能成功。

#include <Windows.h>
#include <stdio.h>
#include <fltUser.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "fltLib.lib")


#define COMMPORTNAME L"\\Encrypt-hkx3upper"

#define EPT_HELLO_KERNEL			1
#define EPT_INSERT_PROCESS_RULES	2
#define EPT_PRIVILEGE_DECRYPT		4
#define EPT_PRIVILEGE_ENCRYPT		8

typedef struct EPT_MESSAGE_HEADER
{
	UINT Command;
	int Length;

}EPT_MESSAGE_HEADER, * PEPT_MESSAGE_HEADER;

typedef struct EPT_GET_MESSAGE
{
	FILTER_MESSAGE_HEADER MessageHeader;
	EPT_MESSAGE_HEADER Message;

}EPT_GET_MESSAGE, * PEPT_GET_MESSAGE;


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

typedef struct EPT_MESSAGE_PRIV_ENDECRYPT
{
	CHAR FileName[260];

}EPT_MESSAGE_PRIV_ENDECRYPT, * PEPT_MESSAGE_PRIV_ENDECRYPT;

#define MESSAGE_SIZE 1024



INT EptUserInitCommPort(IN HANDLE* hPort)
{
	HRESULT hResult;

	hResult = FilterConnectCommunicationPort(COMMPORTNAME, NULL, NULL, NULL, NULL, hPort);

	if (hResult != S_OK)
	{
		return hResult;
	}

	return 0;
}


INT EptUserSendMessage(IN HANDLE hPort, IN LPVOID lpInBuffer, IN INT Command)
{

	if (NULL == lpInBuffer)
	{
		return 1;
	}

	HRESULT hResult;
	DWORD BytesReturned;
	EPT_MESSAGE_HEADER MessageHeader = { 0 };
	char Buffer[MESSAGE_SIZE] = { 0 };


	MessageHeader.Command = Command;
	MessageHeader.Length = strlen((PCHAR)lpInBuffer);

	RtlMoveMemory(Buffer, &MessageHeader, sizeof(MessageHeader));
	RtlMoveMemory(Buffer + sizeof(MessageHeader), lpInBuffer, strlen((PCHAR)lpInBuffer));

	hResult = FilterSendMessage(hPort, Buffer, MESSAGE_SIZE, NULL, NULL, &BytesReturned);

	if (FAILED(hResult))
	{
		//等待的操作过时
		return hResult;
	}

	return 0;
}


INT EptUserGetMessage(IN HANDLE hPort, IN UINT* Command)
{
	HRESULT hResult = 0;
	OVERLAPPED OverLapped = { 0 };

	EPT_GET_MESSAGE Message = { 0 };


	while (TRUE)
	{
		hResult = FilterGetMessage(hPort, &Message.MessageHeader, sizeof(EPT_GET_MESSAGE), &OverLapped);

		Sleep(1000);

		if (Message.Message.Command != 0)
		{
			*Command = Message.Message.Command;
			break;
		}
	}

	return 0;
}


INT EptAddProcessRules(IN HANDLE hPort, IN PCHAR ProcessName, IN PCHAR ExtensionName, IN int count, IN int Access, IN bool isCheckHash)
{

	if (NULL == ProcessName)
	{
		return 1;
	}

	if (NULL == ExtensionName)
	{
		return 1;
	}

	if (0 == count)
	{
		return 1;
	}


	EPT_MESSAGE_HEADER MessageHeader = { 0 };
	EPT_PROCESS_RULES ProcessRules = { 0 };
	char Buffer[MESSAGE_SIZE] = { 0 };

	DWORD BytesReturned = 0;
	HRESULT Ret = 0;


	MessageHeader.Command = EPT_INSERT_PROCESS_RULES;
	MessageHeader.Length = sizeof(EPT_PROCESS_RULES);
	RtlMoveMemory(Buffer, &MessageHeader, sizeof(MessageHeader));

	RtlMoveMemory(ProcessRules.TargetProcessName, ProcessName, strlen(ProcessName));
	RtlMoveMemory(ProcessRules.TargetExtension, ExtensionName, strlen(ExtensionName));
	ProcessRules.count = count;
	ProcessRules.Access = Access;
	ProcessRules.IsCheckHash = isCheckHash;

	//这里先不写hash值了，因为驱动中的相关代码被我注释掉了，因为进程的路径不是之前的完整路径了，没做这一块
	ULONGLONG Hash[4];
	Hash[0] = 0xa28438e1388f272a;
	Hash[1] = 0x52559536d99d65ba;
	Hash[2] = 0x15b1a8288be1200e;
	Hash[3] = 0x249851fdf7ee6c7e;

	ULONGLONG TempHash;

	for (ULONG i = 0; i < 4; i++)
	{
		TempHash = Hash[i];
		for (ULONG j = 0; j < 8; j++)
		{
			ProcessRules.Hash[8 * (i + 1) - 1 - j] = TempHash % 256;
			TempHash = TempHash / 256;
		}

	}

	RtlMoveMemory(Buffer + sizeof(MessageHeader), &ProcessRules, sizeof(EPT_PROCESS_RULES));

	Ret = FilterSendMessage(hPort, Buffer, MESSAGE_SIZE, NULL, NULL, &BytesReturned);

	return Ret;
}