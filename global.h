#pragma once

#include <fltKernel.h>
#include <dontuse.h>

extern PFLT_FILTER gFilterHandle;

typedef struct VOLUME_CONTEXT {

	//UNICODE_STRING Name;
	ULONG SectorSize;

}VOLUME_CONTEXT, * PVOLUME_CONTEXT;

typedef struct SWAP_BUFFER_CONTEXT {

	//  Since the post-operation parameters always receive the "original"
	//  parameters passed to the operation, we need to pass our new destination
	//  buffer to our post operation routine so we can free it.

	PVOID NewBuffer;
	PMDL NewMdlAddress;

	//PVOLUME_CONTEXT pVolumeContext;

}SWAP_BUFFER_CONTEXT, * PSWAP_BUFFER_CONTEXT;


#define VOLUME_CONTEXT_TAG 'vlCX'
