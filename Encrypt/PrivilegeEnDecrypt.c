
#include "privilegeendecrypt.h"


KEVENT g_SynchronizationEvent;

KSTART_ROUTINE KRemoveHeaderAndDecrypt;

VOID KRemoveHeaderAndDecrypt(IN PVOID StartContext)
{
	NTSTATUS Status;
	PWCHAR FileName = NULL;

	/*Status = KeReadStateEvent(&g_SynchronizationEvent);
	DbgPrint("KRemoveHeaderAndDecrypt g_SynchronizationEvent state = %d", Status);*/

	Status = KeWaitForSingleObject(&g_SynchronizationEvent, Executive, KernelMode, FALSE, NULL);

	if (!NT_SUCCESS(Status))
	{
		DbgPrint("KRemoveHeaderAndDecrypt->KeWaitForSingleObject failed status = 0x%x.\n", Status);
		goto EXIT;
	}

	FileName = (PWCHAR)StartContext;

	Status = EptRemoveEncryptHeaderAndDecrypt(FileName);

	if (STATUS_SUCCESS != Status)
	{
		DbgPrint("KRemoveHeaderAndDecrypt->EptRemoveEncryptHeaderAndDecrypt failed status = 0x%x.\n", Status);
		goto EXIT;
	}

EXIT:
	KeSetEvent(&g_SynchronizationEvent, IO_NO_INCREMENT, FALSE);
	PsTerminateSystemThread(STATUS_SUCCESS);
}

//因为特权解密的命令是由桌面传入的，和内核的线程要做多线程的同步
NTSTATUS EptPrivilegeDecrypt(IN PUNICODE_STRING FileName)
{
    NTSTATUS Status;
    HANDLE ThreadHandle = NULL;
	PVOID ThreadObj = NULL;

	Status = PsCreateSystemThread(&ThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, KRemoveHeaderAndDecrypt, (PVOID)FileName->Buffer);

	if (STATUS_SUCCESS != Status)
	{
		DbgPrint("EptPrivilegeDecrypt->PsCreateSystemThread failed status = 0x%x.\n", Status);
		goto EXIT;
	}

	Status = ObReferenceObjectByHandle(ThreadHandle, 0, NULL, KernelMode, &ThreadObj, NULL);

	if (STATUS_SUCCESS != Status)
	{
		DbgPrint("EptPrivilegeDecrypt->ObReferenceObjectByHandle failed ststus = 0x%x.\n", Status);
		goto EXIT;
	}

	//等待进程结束再返回 FileName
	KeWaitForSingleObject(ThreadObj, Executive, KernelMode, FALSE, NULL);

	ObDereferenceObject(ThreadObj);

EXIT:
	if (NULL != ThreadHandle)
	{
		ZwClose(ThreadHandle);
		ThreadHandle = NULL;
	}

	if (NULL != FileName->Buffer)
	{
		RtlFreeUnicodeString(FileName);
		FileName->Buffer = NULL;
	}

	return Status;
}