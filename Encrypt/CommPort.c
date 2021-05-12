
#include "commport.h"

PFLT_PORT gServerPort;
PFLT_PORT gClientPort;
EPT_PROCESS_RULES ProcessRules;

NTSTATUS ConnectNotifyCallback(PFLT_PORT ClientPort, PVOID ServerPortCookie, PVOID ConnectionContext, ULONG SizeOfContext, PVOID* ConnectionPortCookie)
{

	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionPortCookie);

	PAGED_CODE();

	DbgPrint("Encrypt connect with user.\n");

	gClientPort = ClientPort;

	return STATUS_SUCCESS;
}


VOID DisconnectNotifyCallback(PVOID ConnectionCookie)
{
	UNREFERENCED_PARAMETER(ConnectionCookie);

	PAGED_CODE();

	DbgPrint("Encrypt disconnect with user.\n");

	FltCloseClientPort(gFilterHandle, &gClientPort);
}


NTSTATUS MessageNotifyCallback(PVOID PortCookie, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnOutputBufferLength)
{
	UNREFERENCED_PARAMETER(PortCookie);
	UNREFERENCED_PARAMETER(InputBufferLength);
	UNREFERENCED_PARAMETER(OutputBuffer);
	UNREFERENCED_PARAMETER(OutputBufferLength);
	UNREFERENCED_PARAMETER(ReturnOutputBufferLength);

	PAGED_CODE();

	PUCHAR Buffer;
	EPT_MESSAGE_HEADER MessageHeader;

	if (InputBuffer != NULL)
	{

		try
		{
			Buffer = InputBuffer;

		}
		except(EXCEPTION_EXECUTE_HANDLER)
		{
			return GetExceptionCode();
		}

		RtlMoveMemory(&MessageHeader, Buffer, sizeof(EPT_MESSAGE_HEADER));

		switch (MessageHeader.Command)
		{
		case 1:
		{
			DbgPrint("%s", (Buffer + sizeof(EPT_MESSAGE_HEADER)));
			break;
		}
		case 2:
		{
			RtlMoveMemory(&ProcessRules, Buffer + sizeof(EPT_MESSAGE_HEADER), sizeof(EPT_PROCESS_RULES));
			break;
		}
		}

		

	}

	
	return STATUS_SUCCESS;
}


BOOLEAN EptInitCommPort()
{

	NTSTATUS Status;
	PSECURITY_DESCRIPTOR SecurityDescriptor;
	UNICODE_STRING CommPortName;
	OBJECT_ATTRIBUTES ObjectAttributes;

	Status = FltBuildDefaultSecurityDescriptor(&SecurityDescriptor, FLT_PORT_ALL_ACCESS);

	if(!NT_SUCCESS(Status))
	{
		return FALSE;
	}

	RtlInitUnicodeString(&CommPortName, L"\\Encrypt-hkx3upper");

	InitializeObjectAttributes(&ObjectAttributes, &CommPortName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, SecurityDescriptor);

	Status = FltCreateCommunicationPort(gFilterHandle, &gServerPort, &ObjectAttributes, NULL, ConnectNotifyCallback, DisconnectNotifyCallback, MessageNotifyCallback, 1);

	FltFreeSecurityDescriptor(SecurityDescriptor);

	if (!NT_SUCCESS(Status))
	{
		FltCloseCommunicationPort(gServerPort);
		return FALSE;
	}

	return TRUE;

}


VOID EptCloseCommPort()
{
	if (gServerPort)
	{
		FltCloseCommunicationPort(gServerPort);
	}
}