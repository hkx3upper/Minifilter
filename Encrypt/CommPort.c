
#include "commport.h"
#include "processverify.h"
#include "linkedList.h"

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
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

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
		case EPT_INSERT_PROCESS_RULES:
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

			EPT_PROCESS_RULES TempPR = { 0 };
			RtlMoveMemory(TempPR.TargetProcessName, ProcessRules->TargetProcessName, strlen(ProcessRules->TargetProcessName));
			Status = EptIsPRInLinkedList(&TempPR);

			//把链表指针清零，为之后的比较
			RtlZeroMemory(&TempPR, sizeof(LIST_ENTRY));

			if (EPT_STATUS_TARGET_MATCH == Status)
			{
				if (!strncmp(ProcessRules->TargetExtension, TempPR.TargetExtension, sizeof(ProcessRules->TargetExtension)) &&
					!strncmp((PCHAR)ProcessRules->Hash, (PCHAR)TempPR.Hash, sizeof(ProcessRules->Hash)) &&
					ProcessRules->IsCheckHash == TempPR.IsCheckHash)
				{
					DbgPrint("MessageNotifyCallback->%s PR already exsits.\n", ProcessRules->TargetProcessName);

					if (NULL != ProcessRules)
					{
						ExFreePoolWithTag(ProcessRules, PROCESS_RULES_BUFFER_TAG);
						ProcessRules = NULL;
					}
					
					break;
				}
				else
				{
					Status = EptReplacePRInLinkedList(*ProcessRules);

					DbgPrint("MessageNotifyCallback->EptReplacePRInLinkedList %s.\n", ProcessRules->TargetProcessName);

					if (STATUS_SUCCESS != Status)
					{
						DbgPrint("MessageNotifyCallback->EptReplacePRInLinkedList %s failed.\n", ProcessRules->TargetProcessName);
						return Status;
					}

					break;
				}

			}

			DbgPrint("MessageNotifyCallback->InsertTailList ProcessRules->TargetProcessName = %s.\n", ProcessRules->TargetProcessName);
			ExInterlockedInsertTailList(&ProcessRulesListHead, &ProcessRules->ListEntry, &ProcessRulesListSpinLock);

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