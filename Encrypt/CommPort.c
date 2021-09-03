
#include "commport.h"
#include "processverify.h"

PFLT_PORT gServerPort;
PFLT_PORT gClientPort;

NTSTATUS ConnectNotifyCallback(IN PFLT_PORT ClientPort, IN PVOID ServerPortCookie, IN PVOID ConnectionContext, IN ULONG SizeOfContext, IN PVOID* ConnectionPortCookie)
{

	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionPortCookie);

	PAGED_CODE();

	DbgPrint("[ConnectNotifyCallback]->connect with user.\n");

	gClientPort = ClientPort;

	return STATUS_SUCCESS;
}


VOID DisconnectNotifyCallback(IN PVOID ConnectionCookie)
{
	UNREFERENCED_PARAMETER(ConnectionCookie);

	PAGED_CODE();

	DbgPrint("[DisconnectNotifyCallback]->disconnect with user.\n");

	FltCloseClientPort(gFilterHandle, &gClientPort);
}


NTSTATUS MessageNotifyCallback(IN PVOID PortCookie, IN PVOID InputBuffer, IN ULONG InputBufferLength, IN PVOID OutputBuffer, IN ULONG OutputBufferLength, OUT PULONG ReturnOutputBufferLength)
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
		DbgPrint("[EptInitCommPort]->FltBuildDefaultSecurityDescriptor failed. Status = %x\n", Status);
		return FALSE;
	}

	RtlInitUnicodeString(&CommPortName, L"\\Encrypt-hkx3upper");

	InitializeObjectAttributes(&ObjectAttributes, &CommPortName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, SecurityDescriptor);

	Status = FltCreateCommunicationPort(gFilterHandle, &gServerPort, &ObjectAttributes, NULL, ConnectNotifyCallback, DisconnectNotifyCallback, MessageNotifyCallback, 1);

	FltFreeSecurityDescriptor(SecurityDescriptor);

	if (!NT_SUCCESS(Status))
	{
		FltCloseCommunicationPort(gServerPort);
		DbgPrint("[EptInitCommPort]->FltCreateCommunicationPort failed. Status = %x\n", Status);
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