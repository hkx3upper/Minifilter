#pragma once

#include "global.h"

typedef struct EPT_STREAM_CONTEXT {

	LONG FlagExist;

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

VOID EptSetFlagInContext(LONG* Flag, BOOLEAN Set);

BOOLEAN EptCreateContext(PFLT_CONTEXT* CompletionContext, FLT_CONTEXT_TYPE ContextType);

BOOLEAN EptGetOrSetContext(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PEPT_STREAM_CONTEXT* CompletionContext, FLT_CONTEXT_TYPE ContextType, BOOLEAN* AlreadyDefined);