#pragma once

#include "global.h"

#define FILE_FLAG_SIZE 0x1000
#define FILE_FLAG	"ENCRYPTION"

VOID EptBreakPointOnce();

ULONG EptGetFileSize(IN PCFLT_RELATED_OBJECTS FltObjects);

BOOLEAN EptIsTargetFile(IN PCFLT_RELATED_OBJECTS FltObjects);

BOOLEAN EptWriteFileHeader(IN OUT PFLT_CALLBACK_DATA* Data, IN PCFLT_RELATED_OBJECTS FltObjects);

VOID EptFileCacheClear(IN PFILE_OBJECT pFileObject);