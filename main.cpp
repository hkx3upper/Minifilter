
#include "global.h"

HANDLE hPort;
#define COMMPORTNAME L"\\Encrypt-hkx3upper"
#define MESSAGE_SIZE 256

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

	printf("Hello World.\n");

	if (!EptUserInitCommPort())
	{
		printf("EptUserInitCommPort failed.\n");
		return 0;
	}

	char Buffer[MESSAGE_SIZE];
	memset(Buffer, 0, MESSAGE_SIZE);

	RtlMoveMemory(Buffer, "Test from Encrypt User", sizeof("Test from Encrypt User"));

	if (!EptUserSendMessage(Buffer))
	{
		printf("EptUserSendMessage failed.\n");
		return 0;
	}

	return 0;
}