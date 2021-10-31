
#include "LinkedList.h"


NTSTATUS EptIsPRInLinkedList(IN OUT PEPT_PROCESS_RULES ProcessRules)
{
	if (NULL == ProcessRules)
	{
		DbgPrint("EptIsProcessInLinkedList->ProcessRules is NULL.\n");
		return EPT_NULL_POINTER;
	}

	CHAR CapTargetName[260] = { 0 };
	RtlMoveMemory(CapTargetName, ProcessRules->TargetProcessName, strlen(ProcessRules->TargetProcessName));
	RtlMoveMemory(CapTargetName, _strupr(CapTargetName), strlen(_strupr(CapTargetName)));


	CHAR ListCapName[260] = { 0 };

	PEPT_PROCESS_RULES TempProcessRules = NULL;
	PLIST_ENTRY pListEntry = ProcessRulesListHead.Flink;
	

	KeEnterCriticalRegion();
	ExAcquireResourceSharedLite(&ProcessRulesListResource, TRUE);

	while (pListEntry != &ProcessRulesListHead)
	{

		TempProcessRules = CONTAINING_RECORD(pListEntry, EPT_PROCESS_RULES, ListEntry);

		RtlZeroMemory(ListCapName, sizeof(ListCapName));
		RtlMoveMemory(ListCapName, TempProcessRules->TargetProcessName, strlen(TempProcessRules->TargetProcessName));
		RtlMoveMemory(ListCapName, _strupr(ListCapName), strlen(_strupr(ListCapName)));

		if (!strncmp(CapTargetName, ListCapName, strlen(ListCapName)))
		{
			ExReleaseResourceLite(&ProcessRulesListResource);
			KeLeaveCriticalRegion();

			RtlZeroMemory(ProcessRules, sizeof(EPT_PROCESS_RULES));
			RtlMoveMemory(ProcessRules, TempProcessRules, sizeof(EPT_PROCESS_RULES));

			//DbgPrint("EptIsProcessInLinkedList->EPT_STATUS_TARGET_MATCH.\n");

			return EPT_STATUS_TARGET_MATCH;
		}

		
		pListEntry = pListEntry->Flink;
		RtlZeroMemory(ListCapName, sizeof(ListCapName));
	}

	ExReleaseResourceLite(&ProcessRulesListResource);
	KeLeaveCriticalRegion();

	//DbgPrint("EptIsProcessInLinkedList->EPT_STATUS_TARGET_DONT_MATCH.\n");
	ProcessRules = NULL;
	return EPT_STATUS_TARGET_DONT_MATCH;
}


NTSTATUS EptReplacePRInLinkedList(IN EPT_PROCESS_RULES ProcessRules)
{

	if (NULL == ProcessRules.TargetProcessName)
	{
		DbgPrint("EptIsProcessInLinkedList->ProcessRules is NULL.\n");
		return EPT_NULL_POINTER;
	}

	CHAR CapTargetName[260] = { 0 };
	RtlMoveMemory(CapTargetName, ProcessRules.TargetProcessName, strlen(ProcessRules.TargetProcessName));
	RtlMoveMemory(CapTargetName, _strupr(CapTargetName), strlen(_strupr(CapTargetName)));


	CHAR ListCapName[260] = { 0 };

	PEPT_PROCESS_RULES TempProcessRules = NULL;
	PLIST_ENTRY pListEntry = ProcessRulesListHead.Flink;


	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&ProcessRulesListResource, TRUE);

	while (pListEntry != &ProcessRulesListHead)
	{

		TempProcessRules = CONTAINING_RECORD(pListEntry, EPT_PROCESS_RULES, ListEntry);

		RtlZeroMemory(ListCapName, sizeof(ListCapName));
		RtlMoveMemory(ListCapName, TempProcessRules->TargetProcessName, strlen(TempProcessRules->TargetProcessName));
		RtlMoveMemory(ListCapName, _strupr(ListCapName), strlen(_strupr(ListCapName)));

		if (!strncmp(CapTargetName, ListCapName, strlen(ListCapName)))
		{
			ExReleaseResourceLite(&ProcessRulesListResource);
			KeLeaveCriticalRegion();

			RtlMoveMemory(TempProcessRules->TargetExtension, ProcessRules.TargetExtension, sizeof(TempProcessRules->TargetExtension));
			RtlMoveMemory(TempProcessRules->Hash, ProcessRules.Hash, sizeof(TempProcessRules->Hash));
			TempProcessRules->IsCheckHash = ProcessRules.IsCheckHash;
			TempProcessRules->count = ProcessRules.count;

			return STATUS_SUCCESS;
		}


		pListEntry = pListEntry->Flink;
		RtlZeroMemory(ListCapName, sizeof(ListCapName));
	}

	ExReleaseResourceLite(&ProcessRulesListResource);
	KeLeaveCriticalRegion();

	return STATUS_UNSUCCESSFUL;
}


VOID EptListCleanUp()
{
	PEPT_PROCESS_RULES ProcessRules;
	PLIST_ENTRY pListEntry;

	ExDeleteResourceLite(&ProcessRulesListResource);

	while (!IsListEmpty(&ProcessRulesListHead))
	{

		pListEntry = ExInterlockedRemoveHeadList(&ProcessRulesListHead, &ProcessRulesListSpinLock);

		ProcessRules = CONTAINING_RECORD(pListEntry, EPT_PROCESS_RULES, ListEntry);

		DbgPrint("[EptListCleanUp]->Remove list node TargetProcessName = %s.\n", ProcessRules->TargetProcessName);

		if (NULL != ProcessRules)
		{
			ExFreePool(ProcessRules);
			ProcessRules = NULL;
		}

	}

}