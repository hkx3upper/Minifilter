
#include "commport.h"
#include "processidentity.h"

PFLT_PORT gServerPort;
PFLT_PORT gClientPort;

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
			//DbgPrint("%s", (Buffer + sizeof(EPT_MESSAGE_HEADER)));

			PEPT_PROCESS_RULES ProcessRules;
			ProcessRules = ExAllocatePoolWithTag(PagedPool, sizeof(EPT_PROCESS_RULES), PROCESS_RULES_BUFFER_TAG);
			if (!ProcessRules)
			{
				DbgPrint("DriverEntry ExAllocatePoolWithTag ProcessRules failed.\n");
				return 0;
			}

			RtlZeroMemory(ProcessRules, sizeof(EPT_PROCESS_RULES));


			RtlMoveMemory(ProcessRules->TargetProcessName, Buffer + sizeof(EPT_MESSAGE_HEADER), sizeof(EPT_PROCESS_RULES) - sizeof(LIST_ENTRY));

			//DbgPrint("InsertTailList ProcessRules = %s ProcessRules->TargetProcessName = %s.\n", ProcessRules, ProcessRules->TargetProcessName);
			InsertTailList(&ListHead, &ProcessRules->ListEntry);

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