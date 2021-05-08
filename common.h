#pragma once

#include "global.h"

#define FILE_FLAG_SIZE 0x1000
#define FILE_FLAG	"ENCRYPTION"


typedef NTSTATUS(*EptQueryInformationProcess) (
	_In_      HANDLE,
	_In_      PROCESSINFOCLASS,
	_Out_     PVOID,
	_In_      ULONG,
	_Out_opt_ PULONG
	);

extern EptQueryInformationProcess pEptQueryInformationProcess;

VOID EptBreakPointOnce();

BOOLEAN EptIsTargetProcess(PFLT_CALLBACK_DATA Data, CHAR* TargetName);

BOOLEAN EptIsTargetExtension(PFLT_CALLBACK_DATA Data);

BOOLEAN EptIsTargetFile(PCFLT_RELATED_OBJECTS FltObjects);

BOOLEAN EptWriteFileHeader(PFLT_CALLBACK_DATA* Data, PCFLT_RELATED_OBJECTS FltObjects);

VOID EptFileCacheClear(PFILE_OBJECT pFileObject);