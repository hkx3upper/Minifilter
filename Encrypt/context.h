#pragma once

#include "global.h"

typedef struct EPT_STREAM_CONTEXT {

	LONG FlagExist;
	LONGLONG FileSize;

}EPT_STREAM_CONTEXT, * PEPT_STREAM_CONTEXT;

typedef struct EPT_STREAMHANDLE_CONTEXT {

	LONG IsTargetProcess;

}EPT_STREAMHANDLE_CONTEXT, * PEPT_STREAMHANDLE_CONTEXT;

typedef struct VOLUME_CONTEXT {

	//UNICODE_STRING Name;
	ULONG SectorSize;

}VOLUME_CONTEXT, * PVOLUME_CONTEXT;

#define VOLUME_CONTEXT_TAG 'vlCX'

#define STREAM_CONTEXT_TAG 'stCX'

VOID EptSetFlagInContext(IN LONG* Flag, IN BOOLEAN Set);

BOOLEAN EptCreateContext(IN OUT PFLT_CONTEXT* CompletionContext, IN FLT_CONTEXT_TYPE ContextType);

BOOLEAN EptGetOrSetContext(IN PFLT_CALLBACK_DATA Data, IN PCFLT_RELATED_OBJECTS FltObjects, IN OUT PEPT_STREAM_CONTEXT* CompletionContext, IN FLT_CONTEXT_TYPE ContextType);