
#include "processidentity.h"

LIST_ENTRY ListHead;

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

//获取请求的进程名
//ie浏览器会导致UNEXPECTED KERNEL MODE TRAP?
//所以在PreCreate先过滤扩展名，尽量避免trap
//或者以后可以使用遍历EPROCESS，获得进程名
BOOLEAN EptGetProcessName(PFLT_CALLBACK_DATA Data, PUNICODE_STRING ProcessName) {

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

	//DbgPrint("ProcessName = %s.\n", p);

	//遍历链表，取出ProcessName，并比较
	PEPT_PROCESS_RULES ProcessRules;
	PLIST_ENTRY pListEntry = ListHead.Flink;

	while (pListEntry != &ListHead)
	{

		ProcessRules = CONTAINING_RECORD(pListEntry, EPT_PROCESS_RULES, ListEntry);

		//大写便于比较
		RtlMoveMemory(Temp, ProcessRules->TargetProcessName, strlen(ProcessRules->TargetProcessName));

		RtlMoveMemory(AnisProcessName.Buffer, _strupr(AnisProcessName.Buffer), strlen(AnisProcessName.Buffer));
		RtlMoveMemory(Temp, _strupr(Temp), strlen(Temp));

		if (strcmp(p, Temp) == 0) {

			RtlFreeAnsiString(&AnisProcessName);
			//DbgPrint("EptIsTargetProcess hit Process Name = %s.\n", Temp);
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
					RtlFreeUnicodeString(&Extension);
					//DbgPrint("EptIsTargetExtension hit.\n");
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