#pragma once

#include "global.h"

#define SWAP_WRITE_CONTEXT_TAG 'swCT'
#define SWAP_WRITE_BUFFER_TAG 'swBF'
#define SWAP_READ_CONTEXT_TAG 'srCT'
#define SWAP_READ_BUFFER_TAG 'srBF'

BOOLEAN PreWriteSwapBuffers(PFLT_CALLBACK_DATA* Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);

BOOLEAN PreReadSwapBuffers(PFLT_CALLBACK_DATA* Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);

BOOLEAN PostReadSwapBuffers(PFLT_CALLBACK_DATA* Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext);