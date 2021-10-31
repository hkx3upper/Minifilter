#pragma once

#include "global.h"

#define PROCESS_RULES_BUFFER_TAG 'prBT'
#define PROCESS_RULES_HASH_TAG 'prHT'
#define PROCESS_FILE_BUFFER_TAG 'pfBT'


typedef NTSTATUS(*EptQueryInformationProcess) (
	_In_      HANDLE,
	_In_      PROCESSINFOCLASS,
	_Out_     PVOID,
	_In_      ULONG,
	_Out_opt_ PULONG
	);

extern EptQueryInformationProcess pEptQueryInformationProcess;


NTSTATUS ComputeHash(IN PUCHAR Data, IN ULONG DataLength, IN OUT PUCHAR* DataDigestPointer, IN OUT ULONG* DataDigestLengthPointer);

NTSTATUS EptIsTargetProcess(IN PFLT_CALLBACK_DATA Data);

NTSTATUS EptIsTargetExtension(IN PFLT_CALLBACK_DATA Data);