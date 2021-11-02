
#include "processverify.h"
#include "linkedList.h"
#include <wdm.h>
#include <bcrypt.h>



NTSTATUS ComputeHash(IN PUCHAR Data, IN ULONG DataLength, IN OUT PUCHAR* DataDigestPointer, IN OUT ULONG* DataDigestLengthPointer)
{
	//Windows-classic-samples-master\Samples\Security\SignHashAndVerifySignature

	NTSTATUS                Status;

	BCRYPT_ALG_HANDLE       HashAlgHandle = NULL;
	BCRYPT_HASH_HANDLE      HashHandle = NULL;
	
	PUCHAR                   HashDigest = NULL;
	ULONG                   HashDigestLength = 0;

	ULONG                   ResultLength = 0;

	*DataDigestPointer = NULL;
	*DataDigestLengthPointer = 0;

	//
	// Open a Hash algorithm handle
	//

	Status = BCryptOpenAlgorithmProvider(
		&HashAlgHandle,
		BCRYPT_SHA256_ALGORITHM,
		NULL,
		0);
	if (!NT_SUCCESS(Status))
	{
		//ReportError(Status);
		goto cleanup;
	}


	//
	// Calculate the length of the Hash
	//

	Status = BCryptGetProperty(
		HashAlgHandle,
		BCRYPT_HASH_LENGTH,
		(PUCHAR)&HashDigestLength,
		sizeof(HashDigestLength),
		&ResultLength,
		0);
	if (!NT_SUCCESS(Status))
	{
		//ReportError(Status);
		goto cleanup;
	}

	//allocate the Hash buffer on the heap
	HashDigest = (PUCHAR)ExAllocatePoolWithTag(PagedPool, HashDigestLength, PROCESS_RULES_HASH_TAG);
	if (NULL == HashDigest)
	{
		Status = STATUS_NO_MEMORY;
		//ReportError(Status);
		goto cleanup;
	}

	//
	// Create a Hash
	//

	Status = BCryptCreateHash(
		HashAlgHandle,
		&HashHandle,
		NULL,
		0,
		NULL,
		0,
		0);
	if (!NT_SUCCESS(Status))
	{
		//ReportError(Status);
		goto cleanup;
	}

	//
	// Hash message(s)
	//
	Status = BCryptHashData(
		HashHandle,
		(PUCHAR)Data,
		DataLength,
		0);
	if (!NT_SUCCESS(Status))
	{
		//ReportError(Status);
		goto cleanup;
	}

	//
	// Close the Hash
	//

	Status = BCryptFinishHash(
		HashHandle,
		HashDigest,
		HashDigestLength,
		0);
	if (!NT_SUCCESS(Status))
	{
		//ReportError(Status);
		goto cleanup;
	}

	*DataDigestPointer = HashDigest;
	HashDigest = NULL;
	*DataDigestLengthPointer = HashDigestLength;

	Status = STATUS_SUCCESS;

cleanup:

	if (NULL != HashDigest)
	{
		ExFreePool(HashDigest);
		HashDigest = NULL;
	}

	if (NULL != HashHandle)
	{
		Status = BCryptDestroyHash(HashHandle);
		HashHandle = NULL;
	}

	if (NULL != HashAlgHandle)
	{
		BCryptCloseAlgorithmProvider(HashAlgHandle, 0);
	}

	return Status;
}


BOOLEAN EptVerifyHash(IN PUCHAR Buffer, IN ULONG Length, IN PUCHAR	OrigHash)
{
	if (NULL == Buffer)
	{
		DbgPrint("[EptVerifyHash]->Buffer is NULL.\n");
		return FALSE;
	}

	if (0 == Length)
	{
		DbgPrint("[EptVerifyHash]->Length is NULL.\n");
		return FALSE;
	}

	if (NULL == OrigHash)
	{
		DbgPrint("[EptVerifyHash]->Please input the hash of the confidential process\n");
		return FALSE;
	}

	ULONG LengthReturned;
	PUCHAR Hash;

	ComputeHash(
		Buffer, 
		Length, 
		&Hash,
		&LengthReturned);

	if (Hash != NULL)
	{
		if (!strncmp((char*)Hash, (char*)OrigHash, 32)) 
		{
			DbgPrint("[EptVerifyHash]->Hash is match.\n");
			ExFreePool(Hash);
			Hash = NULL;
			return TRUE;
		}

		ExFreePool(Hash);
		Hash = NULL;
	}

	return FALSE;
}


NTSTATUS EptReadProcessFile(IN UNICODE_STRING ProcessName, OUT PUCHAR* Buffer, OUT PULONG Length)
{

	if (NULL == ProcessName.Buffer)
	{
		DbgPrint("[EptReadProcessFile]->ProcessName is NULL.\n");
		return FALSE;
	}

	OBJECT_ATTRIBUTES ObjectAttributes;
	NTSTATUS Status;
	HANDLE FileHandle;
	IO_STATUS_BLOCK IoStatusBlock;

	FILE_STANDARD_INFORMATION FileStandInfo;
	LARGE_INTEGER ByteOffset;

	InitializeObjectAttributes(
		&ObjectAttributes, 
		&ProcessName, 
		OBJ_CASE_INSENSITIVE, 
		NULL, 
		NULL);

	Status = ZwOpenFile(
		&FileHandle, 
		GENERIC_READ,
		&ObjectAttributes, 
		&IoStatusBlock, 
		FILE_SHARE_VALID_FLAGS,
		FILE_NON_DIRECTORY_FILE);

	if (!NT_SUCCESS(Status))
	{
		//STATUS_SHARING_VIOLATION
		DbgPrint("[EptReadProcessFile]->ZwOpenFile failed. Status = %X.\n", Status);
		return Status;
	}

	//查询文件大小，分配内存
	Status = ZwQueryInformationFile(
		FileHandle, 
		&IoStatusBlock, 
		&FileStandInfo, 
		sizeof(FILE_STANDARD_INFORMATION), 
		FileStandardInformation);

	if (!NT_SUCCESS(Status))
	{
		DbgPrint("[EptReadProcessFile]->ZwQueryInformationFile failed. Status = %X.\n", Status);

		if (NULL != FileHandle)
		{
			ZwClose(FileHandle);
			FileHandle = NULL;
		}
		return Status;
	}

	(*Buffer) = ExAllocatePoolWithTag(
		PagedPool, 
		FileStandInfo.EndOfFile.QuadPart, 
		PROCESS_FILE_BUFFER_TAG);

	if (!(*Buffer))
	{
		DbgPrint("[EptReadProcessFile]->ExAllocatePoolWithTag Buffer failed.\n");
		if (NULL != FileHandle)
		{
			ZwClose(FileHandle);
			FileHandle = NULL;
		}
		return Status;
	}

	ByteOffset.QuadPart = 0;
	Status = ZwReadFile(
		FileHandle, 
		NULL, NULL, NULL, 
		&IoStatusBlock, 
		(*Buffer),
		(ULONG)FileStandInfo.EndOfFile.QuadPart, 
		&ByteOffset, 
		NULL);

	if (!NT_SUCCESS(Status))
	{
		DbgPrint("[EptReadProcessFile]->ZwReadFile failed. Status = %X.\n", Status);
		if (NULL != FileHandle)
		{
			ZwClose(FileHandle);
			FileHandle = NULL;
		}

		if (NULL != (*Buffer))
		{
			ExFreePool((*Buffer));
			*Buffer = NULL;
		}
		return Status;
	}

	if (NULL != FileHandle)
	{
		ZwClose(FileHandle);
		FileHandle = NULL;
	}

	*Length = (ULONG)FileStandInfo.EndOfFile.QuadPart;
	return Status;
}


//获取请求的进程名
BOOLEAN EptGetProcessName(IN PFLT_CALLBACK_DATA Data, IN PUNICODE_STRING ProcessName) 
//ie浏览器会导致UNEXPECTED KERNEL MODE TRAP?
//所以在PreCreate先过滤扩展名，尽量避免trap
//或者以后可以使用遍历EPROCESS，获得进程名
{

	if (NULL == Data)
	{
		DbgPrint("[EptGetProcessName]->Data is NULL.\n");
		return FALSE;
	}


	if (NULL == ProcessName->Buffer)
	{
		DbgPrint("[EptGetProcessName]->ProcessName is NULL.\n");
		return FALSE;
	}

	NTSTATUS Status;
	PEPROCESS eProcess;
	HANDLE hProcess;

	PAGED_CODE();

	if (!pEptQueryInformationProcess) {

		DbgPrint("[EptGetProcessName]->pEptQueryInformationProcess = %p.\n", pEptQueryInformationProcess);
		return FALSE;
	}

	eProcess = FltGetRequestorProcess(Data);

	if (!eProcess) {

		DbgPrint("[EptGetProcessName]->EProcess FltGetRequestorProcess failed.\n.");
		return FALSE;
	}

	Status = ObOpenObjectByPointer(eProcess, OBJ_KERNEL_HANDLE, NULL, 0, 0, KernelMode, &hProcess);

	if (NT_SUCCESS(Status)) {

		Status = pEptQueryInformationProcess(hProcess, ProcessImageFileName, ProcessName, ProcessName->MaximumLength, NULL);

		if (NT_SUCCESS(Status)) {

			//DbgPrint("DfGetProcessName = %ws, Length = %d.\n", ProcessName->Buffer, ProcessName->Length);
			if (NULL != hProcess)
			{
				ZwClose(hProcess);
				hProcess = NULL;
			}
			return TRUE;
		}
		else if (Status == STATUS_INFO_LENGTH_MISMATCH) {

			DbgPrint("[EptGetProcessName]->pDfQueryInformationProcess buffer too small.\n");
		}

		if (NULL != hProcess)
		{
			ZwClose(hProcess);
			hProcess = NULL;
		}
		
	}

	return FALSE;

}


//判断是否为加密进程
NTSTATUS EptIsTargetProcess(IN PFLT_CALLBACK_DATA Data)
{

	if (NULL == Data)
	{
		DbgPrint("[EptIsTargetProcess]->Data is NULL.\n");
		return STATUS_INVALID_PARAMETER;
	}

	NTSTATUS Status;
	char Buffer[PAGE_SIZE * sizeof(WCHAR) + sizeof(UNICODE_STRING)], Temp[260];
	RtlZeroMemory(Buffer, sizeof(Buffer));
	RtlZeroMemory(Temp, sizeof(Temp));

	PUNICODE_STRING ProcessName = (PUNICODE_STRING)Buffer;
	ProcessName->Buffer = (WCHAR*)(Buffer + sizeof(UNICODE_STRING));
	ProcessName->Length = 0;
	ProcessName->MaximumLength = PAGE_SIZE;

	ANSI_STRING AnisProcessName = { 0 };
	CHAR* p = NULL;

	if (!EptGetProcessName(Data, ProcessName)) {

		DbgPrint("[EptIsTargetProcess]->EptGetProcessName failed.\n");
		return FALSE;
	}


	//TRUE为AnsiProcessName分配内存
	Status = RtlUnicodeStringToAnsiString(&AnisProcessName, ProcessName, TRUE);

	if (!NT_SUCCESS(Status)) {

		DbgPrint("[EptIsTargetProcess]->AnisProcessName RtlUnicodeStringToAnsiString failed. Status = %x\n", Status);
		return Status;
	}


	//找到进程名
	p = AnisProcessName.Buffer + AnisProcessName.Length;

	while (*p != '\\' && p > AnisProcessName.Buffer)
	{
		p--;
	}

	if (p != AnisProcessName.Buffer)
		p++;

	//DbgPrint("[EptIsTargetProcess]->ProcessName = %s.\n", p);

	//遍历链表，取出ProcessName，并比较
	EPT_PROCESS_RULES ProcessRules = { 0 };
	RtlMoveMemory(ProcessRules.TargetProcessName, p, strlen(p));
	
	Status = EptIsPRInLinkedList(&ProcessRules);
			
	if (EPT_STATUS_TARGET_MATCH == Status)
	{
		//CheckHash = TRUE，进入if
		if (ProcessRules.IsCheckHash)
		{
			PUCHAR ReadBuffer = NULL;
			ULONG Length;
			Status = EptReadProcessFile(*ProcessName, &ReadBuffer, &Length);

			if (!NT_SUCCESS(Status))
			{
				DbgPrint("[EptIsTargetProcess]->EptReadProcessFile failed. error code = %x\n", Status);
				return Status;
			}

			if (EptVerifyHash(ReadBuffer, Length, ProcessRules.Hash))
			{
				Status = EPT_STATUS_TARGET_MATCH;
			}
			else
			{
				Status = EPT_STATUS_TARGET_DONT_MATCH;
			}

			if (ReadBuffer != NULL)
			{
				ExFreePool(ReadBuffer);
				ReadBuffer = NULL;
			}
		}
		else
		{
			Status = EPT_STATUS_TARGET_MATCH;
		}
	}

	if (EPT_STATUS_TARGET_MATCH == Status)
	{
		Status = ProcessRules.Access;
	}

	
	if (NULL != AnisProcessName.Buffer)
	{
		RtlFreeAnsiString(&AnisProcessName);
		AnisProcessName.Buffer = NULL;
	}

	return Status;

}


//判断文件扩展名
NTSTATUS EptIsTargetExtension(IN PFLT_CALLBACK_DATA Data)
{

	if (NULL == Data)
	{
		DbgPrint("[EptIsTargetExtension]->Data is NULL.\n");
		return STATUS_INVALID_PARAMETER;
	}

	NTSTATUS Status;
	PFLT_FILE_NAME_INFORMATION FileNameInfo;

	char* lpExtension;
	int count = 0;
	char TempExtension[10];
	ANSI_STRING AnsiTempExtension;
	UNICODE_STRING Extension;


	//判断文件后缀，避免进程本身需要的操作被拦截
	Status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &FileNameInfo);

	if (!NT_SUCCESS(Status)) {

		//DbgPrint("[EptIsTargetExtension]->FltGetFileNameInformation failed. Status = %x\n", Status);
		return Status;
	}

	FltParseFileNameInformation(FileNameInfo);


	//遍历链表，取出Extension，并比较
	PEPT_PROCESS_RULES ProcessRules;
	PLIST_ENTRY pListEntry = ProcessRulesListHead.Flink;

	KeEnterCriticalRegion();
	ExAcquireResourceSharedLite(&ProcessRulesListResource, TRUE);

	while (pListEntry != &ProcessRulesListHead)
	{
		ProcessRules = CONTAINING_RECORD(pListEntry, EPT_PROCESS_RULES, ListEntry);

		lpExtension = ProcessRules->TargetExtension;

		//将后缀按','分割开并比较
		for (int i = 0; i < ProcessRules->count; i++)
		{
			memset(TempExtension, 0, sizeof(TempExtension));
			count = 0;

			while (strncmp(lpExtension, ",", 1) != 0)
			{
				TempExtension[count++] = *lpExtension;
				//DbgPrint("lpExtension = %s.\n", lpExtension);
				lpExtension++;
			}

			//DbgPrint("TempExtension = %s.\n", TempExtension);

			RtlInitAnsiString(&AnsiTempExtension, TempExtension);
			AnsiTempExtension.MaximumLength = sizeof(TempExtension);

			if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&Extension, &AnsiTempExtension, TRUE)))
			{
				if (RtlEqualUnicodeString(&FileNameInfo->Extension, &Extension, TRUE))
				{
					//DbgPrint("[EptIsTargetExtension] Extension is same %ws.\n", Extension.Buffer);

					Status = EPT_STATUS_TARGET_MATCH;

					if (NULL != Extension.Buffer)
					{
						RtlFreeUnicodeString(&Extension);
						Extension.Buffer = NULL;
					}

					break;
				}
				else
				{
					Status = EPT_STATUS_TARGET_DONT_MATCH;
				}
				
				if (NULL != Extension.Buffer)
				{
					RtlFreeUnicodeString(&Extension);
					Extension.Buffer = NULL;
				}
			}

			//跳过逗号
			lpExtension++;
		}


		pListEntry = pListEntry->Flink;
	}

	ExReleaseResourceLite(&ProcessRulesListResource);
	KeLeaveCriticalRegion();


	if (NULL != FileNameInfo)
	{
		FltReleaseFileNameInformation(FileNameInfo);
		FileNameInfo = NULL;
	}
	
	return Status;
}
