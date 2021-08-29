
#include "processverify.h"
#include <bcrypt.h>

LIST_ENTRY ListHead;
BOOLEAN CheckHash;

VOID EptListCleanUp()
{
	PEPT_PROCESS_RULES ProcessRules;
	PLIST_ENTRY pListEntry;

	while (!IsListEmpty(&ListHead))
	{
		pListEntry = RemoveTailList(&ListHead);

		ProcessRules = CONTAINING_RECORD(pListEntry, EPT_PROCESS_RULES, ListEntry);
		DbgPrint("Remove list node TargetProcessName = %s", ProcessRules->TargetProcessName);

		ExFreePool(ProcessRules);
	}

}


NTSTATUS ComputeHash(PUCHAR Data, ULONG DataLength, PUCHAR* DataDigestPointer, ULONG* DataDigestLengthPointer)
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


BOOLEAN EptVerifyHash(
	PUCHAR Buffer, 
	ULONG Length,
	PUCHAR	OrigHash
	)
{
	if (OrigHash == NULL)
	{
		DbgPrint("Please input the hash of the confidential process\n");
		return TRUE;
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
			//DbgPrint("Hash is match.\n");
			ExFreePool(Hash);
			return TRUE;
		}

		ExFreePool(Hash);
	}

	return FALSE;
}


NTSTATUS EptReadProcessFile(
	UNICODE_STRING ProcessName,
	PUCHAR* Buffer,
	PULONG Length
	)
//换一下代码风格
{
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
		DbgPrint("EptReadProcessFile ZwOpenFile failed Status = %X.\n", Status);
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
		DbgPrint("EptReadProcessFile ZwQueryInformationFile failed.\n");
		ZwClose(FileHandle);
		return Status;
	}

	(*Buffer) = ExAllocatePoolWithTag(
		PagedPool, 
		FileStandInfo.EndOfFile.QuadPart, 
		PROCESS_FILE_BUFFER_TAG);

	if (!(*Buffer))
	{
		DbgPrint("EptReadProcessFile ExAllocatePoolWithTag Buffer failed.\n");
		ZwClose(FileHandle);
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
		DbgPrint("EptReadProcessFile ZwReadFile failed.\n");
		ZwClose(FileHandle);
		ExFreePool((*Buffer));
		return Status;
	}

	*Length = (ULONG)FileStandInfo.EndOfFile.QuadPart;
	return Status;
}


//获取请求的进程名
BOOLEAN EptGetProcessName(
	PFLT_CALLBACK_DATA Data, 
	PUNICODE_STRING ProcessName
	) 
//ie浏览器会导致UNEXPECTED KERNEL MODE TRAP?
//所以在PreCreate先过滤扩展名，尽量避免trap
//或者以后可以使用遍历EPROCESS，获得进程名
{

	NTSTATUS Status;
	PEPROCESS eProcess;
	HANDLE hProcess;

	PAGED_CODE();

	if (!pEptQueryInformationProcess) {

		DbgPrint("pEptQueryInformationProcess = %p.\n", pEptQueryInformationProcess);
		return FALSE;
	}

	eProcess = FltGetRequestorProcess(Data);

	if (!eProcess) {

		DbgPrint("EProcess FltGetRequestorProcess failed.\n.");
		return FALSE;
	}

	Status = ObOpenObjectByPointer(eProcess, OBJ_KERNEL_HANDLE, NULL, 0, 0, KernelMode, &hProcess);

	if (NT_SUCCESS(Status)) {

		Status = pEptQueryInformationProcess(hProcess, ProcessImageFileName, ProcessName, ProcessName->MaximumLength, NULL);

		if (NT_SUCCESS(Status)) {

			//DbgPrint("DfGetProcessName = %ws, Length = %d.\n", ProcessName->Buffer, ProcessName->Length);
			ZwClose(hProcess);
			return TRUE;
		}
		else if (Status == STATUS_INFO_LENGTH_MISMATCH) {

			DbgPrint("pDfQueryInformationProcess buffer too small.\n");
		}

		ZwClose(hProcess);
	}

	return FALSE;

}


//判断是否为加密进程
BOOLEAN EptIsTargetProcess(PFLT_CALLBACK_DATA Data) {

	PAGED_CODE();

	NTSTATUS Status;
	char Buffer[PAGE_SIZE * sizeof(WCHAR) + sizeof(UNICODE_STRING)], Temp[260];
	RtlZeroMemory(Buffer, sizeof(Buffer));
	RtlZeroMemory(Temp, sizeof(Temp));

	PUNICODE_STRING ProcessName = (PUNICODE_STRING)Buffer;
	ProcessName->Buffer = (WCHAR*)(Buffer + sizeof(UNICODE_STRING));
	ProcessName->Length = 0;
	ProcessName->MaximumLength = PAGE_SIZE;

	ANSI_STRING AnisProcessName;
	CHAR* p;

	if (!EptGetProcessName(Data, ProcessName)) {

		DbgPrint("EptGetProcessName failed.\n");
		return FALSE;
	}


	//TRUE为AnsiProcessName分配内存
	Status = RtlUnicodeStringToAnsiString(&AnisProcessName, ProcessName, TRUE);

	if (!NT_SUCCESS(Status)) {

		DbgPrint("AnisProcessName RtlUnicodeStringToAnsiString failed.\n");
		return FALSE;
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
	PEPT_PROCESS_RULES ProcessRules;
	PLIST_ENTRY pListEntry = ListHead.Flink;

	while (pListEntry != &ListHead)
	{

		ProcessRules = CONTAINING_RECORD(pListEntry, EPT_PROCESS_RULES, ListEntry);

		//大写便于比较
		RtlZeroMemory(Temp, 260);
		RtlMoveMemory(Temp, ProcessRules->TargetProcessName, strlen(ProcessRules->TargetProcessName));

		RtlMoveMemory(AnisProcessName.Buffer, _strupr(AnisProcessName.Buffer), strlen(AnisProcessName.Buffer));
		RtlMoveMemory(Temp, _strupr(Temp), strlen(Temp));

		if (strcmp(p, Temp) == 0) {

			RtlFreeAnsiString(&AnisProcessName);
			//DbgPrint("EptIsTargetProcess hit Process Name = %s.\n", p);

			//如果是在PreCreate中调用EptIsTargetProcess
			//CheckHash = TRUE，进入if
			if(CheckHash)
			{
				PUCHAR ReadBuffer = NULL;
				ULONG Length;
				Status = EptReadProcessFile(*ProcessName, &ReadBuffer, &Length);

				if (NT_SUCCESS(Status))
				{
					
					if (EptVerifyHash(ReadBuffer, Length, ProcessRules->Hash))
					{
						if (ReadBuffer)
							ExFreePool(ReadBuffer);
						CheckHash = FALSE;
						return TRUE;
					}
					else
					{
						if (ReadBuffer)
							ExFreePool(ReadBuffer);
						CheckHash = FALSE;
						return FALSE;
					}

				}
				return FALSE;
			}


			return TRUE;
		}

		pListEntry = pListEntry->Flink;

	}
	

	RtlFreeAnsiString(&AnisProcessName);

	return FALSE;

}


//判断文件扩展名
BOOLEAN EptIsTargetExtension(PFLT_CALLBACK_DATA Data) {

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

		//DbgPrint("EptIsTargetExtension FltGetFileNameInformation failed.\n");
		return FALSE;
	}

	FltParseFileNameInformation(FileNameInfo);


	//遍历链表，取出Extension，并比较
	PEPT_PROCESS_RULES ProcessRules;
	PLIST_ENTRY pListEntry = ListHead.Flink;

	while (pListEntry != &ListHead)
	{
		ProcessRules = CONTAINING_RECORD(pListEntry, EPT_PROCESS_RULES, ListEntry);

		lpExtension = ProcessRules->TargetExtension;

		//将后缀分割开并比较
		for (int i = 0; i < ProcessRules->count; i++)
		{
			memset(TempExtension, 0, sizeof(TempExtension));
			count = 0;

			while (strncmp(lpExtension, ",", 1))
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
					FltReleaseFileNameInformation(FileNameInfo);
					//DbgPrint("[EptIsTargetExtension] Extension is same %ws.\n", Extension);
					RtlFreeUnicodeString(&Extension);
					return TRUE;
				}

				RtlFreeUnicodeString(&Extension);
			}

			//跳过逗号
			lpExtension++;
		}


		pListEntry = pListEntry->Flink;
	}


	FltReleaseFileNameInformation(FileNameInfo);
	return FALSE;
}