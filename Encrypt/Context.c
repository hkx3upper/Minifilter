

#include "context.h"


VOID EptSetFlagInContext(LONG* Flag, BOOLEAN Set) {

	if (Set) {

		InterlockedIncrement(Flag);
	}

}


BOOLEAN EptCreateContext(PFLT_CONTEXT* CompletionContext, FLT_CONTEXT_TYPE ContextType) {

	NTSTATUS Status;
	PFLT_CONTEXT Context = NULL;

	switch (ContextType) {

	case FLT_STREAM_CONTEXT:
	{
		Status = FltAllocateContext(gFilterHandle, FLT_STREAM_CONTEXT, sizeof(EPT_STREAM_CONTEXT), NonPagedPool, &Context);

		if (!NT_SUCCESS(Status)) {

			DbgPrint("EptCreateStreamContext FltAllocateContext FLT_STREAM_CONTEXT failed.\n");
			return FALSE;
		}

		RtlZeroMemory(Context, sizeof(EPT_STREAM_CONTEXT));

		break;
	}
	case FLT_STREAMHANDLE_CONTEXT:
	{
		Status = FltAllocateContext(gFilterHandle, FLT_STREAMHANDLE_CONTEXT, sizeof(EPT_STREAMHANDLE_CONTEXT), NonPagedPool, &Context);

		if (!NT_SUCCESS(Status)) {

			DbgPrint("EptCreateStreamContext FltAllocateContext FLT_STREAMHANDLE_CONTEXT failed.\n");
			return FALSE;
		}

		RtlZeroMemory(Context, sizeof(EPT_STREAMHANDLE_CONTEXT));

		break;
	}

	}
	

	*CompletionContext = Context;

	return TRUE;

}


BOOLEAN EptGetOrSetContext(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PEPT_STREAM_CONTEXT* CompletionContext, FLT_CONTEXT_TYPE ContextType) {

	NTSTATUS Status = 0;
	PFLT_CONTEXT NewContext = NULL, OldContext = NULL;

	ASSERT(CompletionContext != NULL);
	
	NewContext = *CompletionContext;

	
	switch (ContextType) {

	case FLT_STREAM_CONTEXT:
	{
		Status = FltGetStreamContext(FltObjects->Instance, FltObjects->FileObject, &OldContext);
		break;
	}
	case FLT_STREAMHANDLE_CONTEXT:
	{
		Status = FltGetStreamHandleContext(FltObjects->Instance, Data->Iopb->TargetFileObject, &OldContext);
		break;
	}

	}



	if (Status == STATUS_NOT_FOUND) {

		//进入FltSetStream/HandleContext
	}
	else if (!NT_SUCCESS(Status)) {

		DbgPrint("EptGetOrSetStreamCtx FltGetStreamContext failed.\n");
		return FALSE;
	}
	else {

		//找到已经设置的context

		if (NewContext != NULL) {

			FltReleaseContext(NewContext);
		}

		*CompletionContext = OldContext;


		return TRUE;
	}
	
	
	switch (ContextType) {

	case FLT_STREAM_CONTEXT:
	{
		Status = FltSetStreamContext(FltObjects->Instance, Data->Iopb->TargetFileObject, FLT_SET_CONTEXT_KEEP_IF_EXISTS, NewContext, &OldContext);
		break;
	}
	case FLT_STREAMHANDLE_CONTEXT:
	{
		Status = FltSetStreamHandleContext(FltObjects->Instance, Data->Iopb->TargetFileObject, FLT_SET_CONTEXT_KEEP_IF_EXISTS, NewContext, &OldContext);
		break;
	}

	}



	if (!NT_SUCCESS(Status)) {

		FltReleaseContext(NewContext);

		if (Status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {

			//  We're racing with some other call which managed to set the
			//  context before us. We will return that context instead, which
			//  will be in oldContext.

			*CompletionContext = OldContext;


			return TRUE;
		}

		DbgPrint("EptGetOrSetContext failed twice.\n");
		*CompletionContext = NULL;
		return FALSE;
	}

	*CompletionContext = NewContext;

	return TRUE;

	
}