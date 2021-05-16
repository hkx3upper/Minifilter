#pragma once

#include "global.h"

#define FILE_FLAG_SIZE 0x1000
#define FILE_FLAG	"ENCRYPTION"

VOID EptBreakPointOnce();

ULONG EptGetFileSize(PCFLT_RELATED_OBJECTS FltObjects);

BOOLEAN EptIsTargetFile(PCFLT_RELATED_OBJECTS FltObjects);

BOOLEAN EptWriteFileHeader(PFLT_CALLBACK_DATA* Data, PCFLT_RELATED_OBJECTS FltObjects);

VOID EptFileCacheClear(PFILE_OBJECT pFileObject);