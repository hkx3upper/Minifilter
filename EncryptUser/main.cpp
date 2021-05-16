
#include "global.h"

HANDLE hPort;

BOOLEAN EptUserInitCommPort()
{
	HRESULT hResult;

	hResult = FilterConnectCommunicationPort(COMMPORTNAME, NULL, NULL, NULL, NULL, &hPort);

	if (hResult != S_OK)
	{
		return FALSE;
	}

	return TRUE;
}


BOOLEAN EptUserSendMessage(LPVOID lpInBuffer) 
{

	HRESULT hResult;
	DWORD BytesReturned;

	hResult = FilterSendMessage(hPort, lpInBuffer, sizeof(lpInBuffer), NULL, NULL, &BytesReturned);

	if (hResult != S_OK)
	{
		return FALSE;
	}

	return TRUE;
}


int main() 
{

	EPT_MESSAGE_HEADER MessageHeader;
	EPT_PROCESS_RULES ProcessRules;
	char Buffer[MESSAGE_SIZE];

	printf("Hello World.\n");

	if (!EptUserInitCommPort())
	{
		printf("EptUserInitCommPort failed.\n");
		return 0;
	}

	//发送一个Hello
	memset(Buffer, 0, MESSAGE_SIZE);
	MessageHeader.Command = 1;
	MessageHeader.Length = MESSAGE_SIZE - sizeof(MessageHeader);

	RtlMoveMemory(Buffer, &MessageHeader, sizeof(MessageHeader));
	RtlMoveMemory(Buffer + sizeof(MessageHeader), "Hello driver, test from Encrypt User", sizeof("Hello driver, test from Encrypt User"));

	if (!EptUserSendMessage(Buffer))
	{
		printf("EptUserSendMessage failed.\n");
		return 0;
	}

	//发送进程规则
	memset(Buffer, 0, MESSAGE_SIZE);
	MessageHeader.Command = 2;
	MessageHeader.Length = MESSAGE_SIZE - sizeof(MessageHeader);
	RtlMoveMemory(Buffer, &MessageHeader, sizeof(MessageHeader));

	RtlMoveMemory(ProcessRules.TargetProcessName, "notepad++.exe", sizeof("notepad++.exe"));
	RtlMoveMemory(ProcessRules.TargetExtension, "txt,", sizeof("txt,"));
	ProcessRules.count = 1;
	RtlMoveMemory(Buffer + sizeof(MessageHeader), &ProcessRules, sizeof(EPT_PROCESS_RULES));

	if (!EptUserSendMessage(Buffer))
	{
		printf("EptUserSendMessage failed.\n");
		return 0;
	}


	return 0;
}