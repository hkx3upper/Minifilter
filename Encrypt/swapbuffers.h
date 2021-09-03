#pragma once

#include "global.h"

typedef struct SWAP_BUFFER_CONTEXT {

	//  Since the post-operation parameters always receive the "original"
	//  parameters passed to the operation, we need to pass our new destination
	//  buffer to our post operation routine so we can free it.

	PVOID NewBuffer;
	PMDL NewMdlAddress;

	//PVOLUME_CONTEXT pVolumeContext;

}SWAP_BUFFER_CONTEXT, * PSWAP_BUFFER_CONTEXT;

#define SWAP_WRITE_CONTEXT_TAG 'swCT'
#define SWAP_WRITE_BUFFER_TAG 'swBF'
#define SWAP_READ_CONTEXT_TAG 'srCT'
#define SWAP_READ_BUFFER_TAG 'srBF'

BOOLEAN PreWriteSwapBuffers(IN OUT PFLT_CALLBACK_DATA* Data, IN PCFLT_RELATED_OBJECTS FltObjects, OUT PVOID* CompletionContext);

BOOLEAN PreReadSwapBuffers(IN OUT PFLT_CALLBACK_DATA* Data, IN PCFLT_RELATED_OBJECTS FltObjects, OUT PVOID* CompletionContext);

BOOLEAN PostReadSwapBuffers(IN OUT PFLT_CALLBACK_DATA* Data, IN PCFLT_RELATED_OBJECTS FltObjects, IN PVOID CompletionContext, IN FLT_POST_OPERATION_FLAGS Flags);