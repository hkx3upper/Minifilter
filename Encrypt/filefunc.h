#pragma once

#include "global.h"
#include "context.h"

#define FILE_FLAG_SIZE 0x1000
#define FILE_FLAG	"ENCRYPTION"

VOID EptBreakPointOnce();

ULONG EptGetFileSize(IN PCFLT_RELATED_OBJECTS FltObjects);

NTSTATUS EptIsTargetFile(IN PCFLT_RELATED_OBJECTS FltObjects);

NTSTATUS EptWriteEncryptHeader(IN OUT PFLT_CALLBACK_DATA* Data, IN PCFLT_RELATED_OBJECTS FltObjects);

NTSTATUS EptAppendEncryptHeader(IN PCFLT_RELATED_OBJECTS FltObjects, IN OUT PEPT_STREAM_CONTEXT StreamContext);

VOID EptFileCacheClear(IN PFILE_OBJECT pFileObject);