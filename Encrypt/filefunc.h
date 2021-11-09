#pragma once

#include "global.h"
#include "context.h"

#define FILE_FLAG_SIZE 0x1000
#define FILE_FLAG	"ENCRYPTION"

#define EPT_READ_BUFFER_FLAG	'rbFL'


ULONG EptGetFileSize(IN PFLT_INSTANCE Instance, IN PFILE_OBJECT FileObject);

NTSTATUS EptSetFileEOF(IN PFLT_INSTANCE Instance, IN PFILE_OBJECT FileObject, LONGLONG FileSize);

NTSTATUS EptIsTargetFile(IN PCFLT_RELATED_OBJECTS FltObjects);

NTSTATUS EptWriteEncryptHeader(IN OUT PFLT_CALLBACK_DATA* Data, IN PCFLT_RELATED_OBJECTS FltObjects);

NTSTATUS EptRemoveEncryptHeaderAndDecrypt(IN PWCHAR FileName);

NTSTATUS EptAppendEncryptHeaderAndEncryptEx(IN PWCHAR FileName);

VOID EptFileCacheClear(IN PFILE_OBJECT pFileObject);