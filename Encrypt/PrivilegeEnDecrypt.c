
#include "privilegeendecrypt.h"
#include "commport.h"


KEVENT g_SynchronizationEvent;

KSTART_ROUTINE KRemoveHeaderAndDecrypt;
KSTART_ROUTINE KAppendHeaderAndEncrypt;

VOID KRemoveHeaderAndDecrypt(IN PVOID StartContext)
{
	NTSTATUS Status;
	PWCHAR FileName = NULL;

	/*Status = KeReadStateEvent(&g_SynchronizationEvent);
	DbgPrint("KRemoveHeaderAndDecrypt g_SynchronizationEvent state = %d", Status);*/

	Status = KeWaitForSingleObject(&g_SynchronizationEvent, Executive, KernelMode, FALSE, NULL);

	DbgPrint("\nKRemoveHeaderAndDecrypt->start.\n\n");

	if (!NT_SUCCESS(Status))
	{
		DbgPrint("KRemoveHeaderAndDecrypt->KeWaitForSingleObject failed status = 0x%x.\n", Status);
		goto EXIT;
	}

	FileName = (PWCHAR)StartContext;

	Status = EptRemoveEncryptHeaderAndDecrypt(FileName);

	if (EPT_REMOVE_ENCRYPT_HEADER != Status)
	{
		DbgPrint("KRemoveHeaderAndDecrypt->EptRemoveEncryptHeaderAndDecrypt failed status = 0x%x.\n", Status);
		goto EXIT;
	}

EXIT:
	KeSetEvent(&g_SynchronizationEvent, IO_NO_INCREMENT, FALSE);

	EPT_MESSAGE_HEADER SendBuffer = { 0 };
	SendBuffer.Command = Status;

	Status = FltSendMessage(gFilterHandle, &gClientPort, &SendBuffer, sizeof(EPT_MESSAGE_HEADER), NULL, NULL, NULL);

	if (STATUS_SUCCESS != Status)
	{
		DbgPrint("KRemoveHeaderAndDecrypt->FltSendMessage failed status = 0x%x.\n", Status);
	}
	else
	{
		DbgPrint("KRemoveHeaderAndDecrypt->FltSendMessage success.\n");
	}

	PsTerminateSystemThread(Status);
}


VOID KAppendHeaderAndEncrypt(IN PVOID StartContext)
{
	NTSTATUS Status;
	PWCHAR FileName = NULL;

	/*Status = KeReadStateEvent(&g_SynchronizationEvent);
	DbgPrint("KRemoveHeaderAndDecrypt g_SynchronizationEvent state = %d", Status);*/

	Status = KeWaitForSingleObject(&g_SynchronizationEvent, Executive, KernelMode, FALSE, NULL);

	DbgPrint("\nKAppendHeaderAndEncrypt->start.\n\n");

	if (!NT_SUCCESS(Status))
	{
		DbgPrint("KAppendHeaderAndEncrypt->KeWaitForSingleObject failed status = 0x%x.\n", Status);
		goto EXIT;
	}

	FileName = (PWCHAR)StartContext;

	Status = EptAppendEncryptHeaderAndEncryptEx(FileName);

	if (EPT_APPEND_ENCRYPT_HEADER != Status)
	{
		DbgPrint("KAppendHeaderAndEncrypt->EptAppendEncryptHeaderAndEncryptEx failed status = 0x%x.\n", Status);
		goto EXIT;
	}


EXIT:
	KeSetEvent(&g_SynchronizationEvent, IO_NO_INCREMENT, FALSE);
	DbgPrint("\nKAppendHeaderAndEncrypt->KeSetEvent.\n\n");

	EPT_MESSAGE_HEADER SendBuffer = { 0 };
	SendBuffer.Command = Status;

	Status = FltSendMessage(gFilterHandle, &gClientPort, &SendBuffer, sizeof(EPT_MESSAGE_HEADER), NULL, NULL, NULL);

	if (STATUS_SUCCESS != Status)
	{
		DbgPrint("KAppendHeaderAndEncrypt->FltSendMessage failed status = 0x%x.\n", Status);
	}
	else
	{
		DbgPrint("KAppendHeaderAndEncrypt->FltSendMessage success.\n");
	}

	PsTerminateSystemThread(STATUS_SUCCESS);
}


//因为特权解密的命令是由桌面传入的，和内核的线程要做多线程的同步
NTSTATUS EptPrivilegeEnDecrypt(IN PUNICODE_STRING FileName, IN LONG OperType)
{
	if (NULL == FileName)
	{
		DbgPrint("EptPrivilegeEnDecrypt->FileName is NULL.\n");
		return EPT_NULL_POINTER;
	}

	NTSTATUS Status = 0;
    HANDLE ThreadHandle = NULL;
	PVOID ThreadObj = NULL;

	if (EPT_PRIVILEGE_DECRYPT == OperType)
	{
		Status = PsCreateSystemThread(&ThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, KRemoveHeaderAndDecrypt, (PVOID)FileName->Buffer);
	}
	else if (EPT_PRIVILEGE_ENCRYPT == OperType)
	{
		Status = PsCreateSystemThread(&ThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, KAppendHeaderAndEncrypt, (PVOID)FileName->Buffer);
	}
	else
	{
		DbgPrint("EptPrivilegeEnDecrypt->Wrong OperType.\n");
		goto EXIT;
	}


	if (STATUS_SUCCESS != Status)
	{
		DbgPrint("EptPrivilegeEnDecrypt->PsCreateSystemThread failed status = 0x%x.\n", Status);
		goto EXIT;
	}

	Status = ObReferenceObjectByHandle(ThreadHandle, 0, NULL, KernelMode, &ThreadObj, NULL);

	if (STATUS_SUCCESS != Status)
	{
		DbgPrint("EptPrivilegeEnDecrypt->ObReferenceObjectByHandle failed ststus = 0x%x.\n", Status);
		goto EXIT;
	}

	//等待进程结束再返回 FileName
	//KeWaitForSingleObject(ThreadObj, Executive, KernelMode, FALSE, NULL);
	

EXIT:
	if (NULL != ThreadHandle)
	{
		ZwClose(ThreadHandle);
		ThreadHandle = NULL;
	}

	/*if (NULL != FileName->Buffer)
	{
		RtlFreeUnicodeString(FileName);
		FileName->Buffer = NULL;
	}*/

	if (NULL != ThreadObj)
	{
		ObDereferenceObject(ThreadObj);
		ThreadObj = NULL;
	}

	return Status;
}