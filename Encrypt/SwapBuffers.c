
#include "swapbuffers.h"
#include "filefunc.h"
#include "context.h"
#include "cryptography.h"


FLT_POSTOP_CALLBACK_STATUS PostReadSwapBuffersWhenSafe(IN PFLT_CALLBACK_DATA Data, IN PCFLT_RELATED_OBJECTS FltObjects, IN PVOID CompletionContext, IN FLT_POST_OPERATION_FLAGS Flags);


BOOLEAN PreWriteSwapBuffers(IN OUT PFLT_CALLBACK_DATA* Data, IN PCFLT_RELATED_OBJECTS FltObjects, OUT PVOID* CompletionContext)
{

    if (NULL == Data)
    {
        DbgPrint("[PreWriteSwapBuffers]->Data is NULL.\n");
        return FALSE;
    }

    if (NULL == FltObjects)
    {
        DbgPrint("[PreWriteSwapBuffers]->FltObjects is NULL.\n");
        return FALSE;
    }


    NTSTATUS Status = FLT_PREOP_SUCCESS_WITH_CALLBACK;

    PVOLUME_CONTEXT VolumeContext;

    PSWAP_BUFFER_CONTEXT SwapWriteContext = NULL;
    PUCHAR NewBuffer = NULL, OrigBuffer = NULL;
    PMDL NewMdl = NULL;
    ULONG WriteLength = (*Data)->Iopb->Parameters.Write.Length;

    try
    {
        //获取原来的WriteBuffer地址
        if ((*Data)->Iopb->Parameters.Write.MdlAddress != NULL) {

            OrigBuffer = MmGetSystemAddressForMdlSafe((*Data)->Iopb->Parameters.Write.MdlAddress, NormalPagePriority | MdlMappingNoExecute);
            if (OrigBuffer == NULL) {
                DbgPrint("[PreWriteSwapBuffers]->MmGetSystemAddressForMdlSafe OrigBuffer failed!\n");
                Status = FLT_PREOP_SUCCESS_NO_CALLBACK;
                leave;
            }
        }
        else {

            OrigBuffer = (*Data)->Iopb->Parameters.Write.WriteBuffer;
        }

        //获得加密后数据的大小
        if (!EptAesEncrypt(FltObjects, OrigBuffer, &WriteLength, TRUE))
        {
            DbgPrint("[PreWriteSwapBuffers]->EptAesEncrypt get buffer encrypted size failed.\n");
            return FALSE;
        }
        

        //获得WriteBuffer真正的大小，防止内存越界
        Status = FltGetVolumeContext(FltObjects->Filter, FltObjects->Volume, &VolumeContext);

        if (!NT_SUCCESS(Status)) {
            DbgPrint("[PreWriteSwapBuffers]->VolumeContext FltGetVolumeContext failed!. Status = %x\n", Status);
            Status = FLT_PREOP_SUCCESS_NO_CALLBACK;
            leave;
        }

        if (FlagOn((*Data)->Iopb->IrpFlags, IRP_NOCACHE)) {

            WriteLength = ROUND_TO_SIZE(WriteLength, VolumeContext->SectorSize);
        }

        if (NULL != VolumeContext)
        {
            FltReleaseContext(VolumeContext);
            VolumeContext = NULL;
        }
        

        //为新WriteBuffer,MdlAddress分配暂存空间
        SwapWriteContext = ExAllocatePoolWithTag(NonPagedPool, sizeof(SWAP_BUFFER_CONTEXT), SWAP_WRITE_CONTEXT_TAG);
        if (SwapWriteContext == NULL) {
            DbgPrint("[PreWriteSwapBuffers]->SwapWriteContext ExAllocatePoolWithTag failed!\n");
            Status = FLT_PREOP_SUCCESS_NO_CALLBACK;
            leave;
        }

        RtlZeroMemory(SwapWriteContext, sizeof(SWAP_BUFFER_CONTEXT));

        //只需要为noncached IO分配内存，但这里简化
        NewBuffer = FltAllocatePoolAlignedWithTag(FltObjects->Instance, NonPagedPool, WriteLength, SWAP_WRITE_BUFFER_TAG);
        if (NewBuffer == NULL) {
            DbgPrint("[PreWriteSwapBuffers]->NewBuffer FltAllocatePoolAlignedWithTag failed!\n");
            Status = FLT_PREOP_SUCCESS_NO_CALLBACK;
            leave;
        }

        RtlZeroMemory(NewBuffer, WriteLength);


        //只需要为IRP操作建立MDL，不需要为FASTIO操作
        if (FlagOn((*Data)->Flags, FLTFL_CALLBACK_DATA_IRP_OPERATION)) {

            NewMdl = IoAllocateMdl(NewBuffer, WriteLength, FALSE, FALSE, NULL);
            if (NULL == NewMdl) {
                DbgPrint("[PreWriteSwapBuffers]->NewMDL IoAllocateMdl failed!\n");
                Status = FLT_PREOP_SUCCESS_NO_CALLBACK;
                leave;
            }

            MmBuildMdlForNonPagedPool(NewMdl);
        }

    }
    except(EXCEPTION_EXECUTE_HANDLER)
    {
        (*Data)->IoStatus.Status = Status;
        (*Data)->IoStatus.Information = 0;
        Status = FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //  Copy the memory, we must do this inside the try/except because we
    //  may be using a users buffer address
    try
    {
        RtlCopyMemory(NewBuffer, OrigBuffer, WriteLength);
    }
    except(EXCEPTION_EXECUTE_HANDLER)
    {
        (*Data)->IoStatus.Status = GetExceptionCode();
        (*Data)->IoStatus.Information = 0;
        Status = FLT_PREOP_SUCCESS_NO_CALLBACK;
    }


    SwapWriteContext->NewMdlAddress = NewMdl;
    SwapWriteContext->NewBuffer = NewBuffer;

    (*Data)->Iopb->Parameters.Write.MdlAddress = NewMdl;
    (*Data)->Iopb->Parameters.Write.WriteBuffer = NewBuffer;


    *CompletionContext = SwapWriteContext;
    //加密函数

    DbgPrint("[PreWriteSwapBuffers]->OrigBuffer content = %s.\n", NewBuffer);

    //这里WriteLength作为NewBuffer的大小传入，作为LengthReturned传出
    if (!EptAesEncrypt(FltObjects, NewBuffer, &WriteLength, FALSE))
    {
        DbgPrint("[PreWriteSwapBuffers]->EptAesEncrypt encrypte buffer failed.\n");
    }

    DbgPrint("[PreWriteSwapBuffers]->Encrypted content = %s.\n", NewBuffer);


    //cleanup
    if (Status != FLT_PREOP_SUCCESS_WITH_CALLBACK) {

        if (SwapWriteContext != NULL)
            ExFreePool(SwapWriteContext);

        if (NewBuffer != NULL)
            FltFreePoolAlignedWithTag(FltObjects->Instance, NewBuffer, SWAP_WRITE_BUFFER_TAG);

        if (NewMdl != NULL)
            IoFreeMdl(NewMdl);

        return FALSE;
    }

    return TRUE;

}


BOOLEAN PreReadSwapBuffers(IN OUT PFLT_CALLBACK_DATA* Data, IN PCFLT_RELATED_OBJECTS FltObjects, OUT PVOID* CompletionContext) 
{

    if (NULL == Data)
    {
        DbgPrint("[PreReadSwapBuffers]->Data is NULL.\n");
        return FALSE;
    }

    if (NULL == FltObjects)
    {
        DbgPrint("[PreReadSwapBuffers]->FltObjects is NULL.\n");
        return FALSE;
    }

    NTSTATUS Status = FLT_PREOP_SUCCESS_WITH_CALLBACK;

    PVOLUME_CONTEXT VolumeContext;

    PSWAP_BUFFER_CONTEXT SwapReadContext = NULL;
    PUCHAR NewBuffer = NULL;
    PMDL NewMdl = NULL;
    ULONG ReadLength = (*Data)->Iopb->Parameters.Read.Length;

    PAGED_CODE();

    Status = FltGetVolumeContext(FltObjects->Filter, FltObjects->Volume, &VolumeContext);

    if (!NT_SUCCESS(Status))
    {
        DbgPrint("VolumeContext FltGetVolumeContext failed!.\n");
        return FALSE;
    }

    if (FlagOn((*Data)->Iopb->IrpFlags, IRP_NOCACHE))
    {
        ReadLength = ROUND_TO_SIZE(ReadLength, VolumeContext->SectorSize);
    }

    if (NULL != VolumeContext)
    {
        FltReleaseContext(VolumeContext);
        VolumeContext = NULL;
    }


    SwapReadContext = ExAllocatePoolWithTag(NonPagedPool, sizeof(SWAP_BUFFER_CONTEXT), SWAP_READ_CONTEXT_TAG);
    if (SwapReadContext == NULL)
    {
        DbgPrint("[PreReadSwapBuffers]->SwapReadContext ExAllocatePoolWithTag failed!\n");
        return FALSE;
    }

    RtlZeroMemory(SwapReadContext, sizeof(SWAP_BUFFER_CONTEXT));

    //只需要为noncached IO分配内存，但这里简化
    NewBuffer = FltAllocatePoolAlignedWithTag(FltObjects->Instance, NonPagedPool, ReadLength, SWAP_READ_BUFFER_TAG);
    if (NewBuffer == NULL)
    {
        DbgPrint("[PreReadSwapBuffers]->NewBuffer FltAllocatePoolAlignedWithTag failed!\n");
        if (NULL != SwapReadContext)
        {
            ExFreePool(SwapReadContext);
            SwapReadContext = NULL;
        }
        return FALSE;
    }

    RtlZeroMemory(NewBuffer, ReadLength);



    //只需要为IRP操作建立MDL，不需要为FASTIO操作
    if (FlagOn((*Data)->Flags, FLTFL_CALLBACK_DATA_IRP_OPERATION)) {

        NewMdl = IoAllocateMdl(NewBuffer, ReadLength, FALSE, FALSE, NULL);
        if (NewMdl == NULL)
        {
            DbgPrint("[PreReadSwapBuffers]->NewMDL IoAllocateMdl failed!\n");
            if (NULL != SwapReadContext)
            {
                ExFreePool(SwapReadContext);
                SwapReadContext = NULL;
            }

            if (NULL != NewBuffer)
            {
                FltFreePoolAlignedWithTag(FltObjects->Instance, NewBuffer, SWAP_READ_BUFFER_TAG);
                NewBuffer = NULL;
            }
            return FALSE;
        }

        MmBuildMdlForNonPagedPool(NewMdl);
    }


    SwapReadContext->NewMdlAddress = NewMdl;
    SwapReadContext->NewBuffer = NewBuffer;

    (*Data)->Iopb->Parameters.Read.MdlAddress = NewMdl;
    (*Data)->Iopb->Parameters.Read.ReadBuffer = NewBuffer;

    *CompletionContext = SwapReadContext;

    return TRUE;
}


BOOLEAN PostReadSwapBuffers(IN OUT PFLT_CALLBACK_DATA* Data, IN PCFLT_RELATED_OBJECTS FltObjects, IN PVOID CompletionContext, IN FLT_POST_OPERATION_FLAGS Flags)
{

    if (NULL == Data)
    {
        DbgPrint("[PostReadSwapBuffers]->Data is NULL.\n");
        return FALSE;
    }

    if (NULL == FltObjects)
    {
        DbgPrint("[PostReadSwapBuffers]->FltObjects is NULL.\n");
        return FALSE;
    }

    if (NULL == CompletionContext)
    {
        DbgPrint("[PostReadSwapBuffers]->CompletionContext is NULL.\n");
        return FALSE;
    }

    UNREFERENCED_PARAMETER(Flags);

    PVOID OrigBuffer = NULL;
    PUCHAR NewBuffer;
    ULONG ReadLength;
    PSWAP_BUFFER_CONTEXT SwapReadContext = CompletionContext;

    if ((*Data)->Iopb->Parameters.Read.MdlAddress != NULL)
    {
        OrigBuffer = MmGetSystemAddressForMdlSafe((*Data)->Iopb->Parameters.Read.MdlAddress, NormalPagePriority | MdlMappingNoExecute);
        if (OrigBuffer == NULL)
        {
            (*Data)->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            (*Data)->IoStatus.Information = 0;
            DbgPrint("[PostReadSwapBuffers]->OrigBuffer MmGetSystemAddressForMdlSafe failed!\n");
        }
    }
    else if(FlagOn((*Data)->Flags, FLTFL_CALLBACK_DATA_SYSTEM_BUFFER) || FlagOn((*Data)->Flags, FLTFL_CALLBACK_DATA_FAST_IO_OPERATION))
    {
        OrigBuffer = (*Data)->Iopb->Parameters.Read.ReadBuffer;
    }
    else
    {
        //  They don't have a MDL and this is not a system buffer
            //  or a fastio so this is probably some arbitrary user
            //  buffer.  We can not do the processing at DPC level so
            //  try and get to a safe IRQL so we can do the processing.
            //
        FLT_POSTOP_CALLBACK_STATUS retValue;
        if (FltDoCompletionProcessingWhenSafe(*Data, FltObjects, CompletionContext, Flags, PostReadSwapBuffersWhenSafe, &retValue)) {

            //
            //  This operation has been moved to a safe IRQL, the called
            //  routine will do (or has done) the freeing so don't do it
            //  in our routine.
        }
        else 
        {
            (*Data)->IoStatus.Status = STATUS_UNSUCCESSFUL;
            (*Data)->IoStatus.Information = 0;
        }


    }


    //解密函数
    NewBuffer = SwapReadContext->NewBuffer;
    ReadLength = (ULONG)(*Data)->IoStatus.Information;

    if (!EptAesDecrypt(NewBuffer, ReadLength))
    {
        DbgPrint("[PostReadSwapBuffers]->EptAesDecrypt Buffer failed!\n");

        if (NULL != SwapReadContext->NewBuffer)
        {
            FltFreePoolAlignedWithTag(FltObjects->Instance, SwapReadContext->NewBuffer, SWAP_READ_BUFFER_TAG);
            SwapReadContext->NewBuffer = NULL;
        }

        if (NULL != SwapReadContext)
        {
            ExFreePool(SwapReadContext);
            SwapReadContext = NULL;
        }

        return FALSE;
    }
   



    try
    {
        if (SwapReadContext->NewBuffer && OrigBuffer)
            RtlCopyMemory(OrigBuffer, SwapReadContext->NewBuffer, (*Data)->IoStatus.Information);
    }
    except(EXCEPTION_EXECUTE_HANDLER)
    {
        (*Data)->IoStatus.Status = GetExceptionCode();
        (*Data)->IoStatus.Information = 0;
    }

    if (NULL != SwapReadContext->NewBuffer)
    {
        FltFreePoolAlignedWithTag(FltObjects->Instance, SwapReadContext->NewBuffer, SWAP_READ_BUFFER_TAG);
        SwapReadContext->NewBuffer = NULL;
    }
       
    if (NULL != SwapReadContext) 
    {
        ExFreePool(SwapReadContext);
        SwapReadContext = NULL;
    }

    return TRUE;
}


FLT_POSTOP_CALLBACK_STATUS PostReadSwapBuffersWhenSafe(IN PFLT_CALLBACK_DATA Data, IN PCFLT_RELATED_OBJECTS FltObjects, IN PVOID CompletionContext, IN FLT_POST_OPERATION_FLAGS Flags)
{

    if (NULL == Data)
    {
        DbgPrint("[PostReadSwapBuffersWhenSafe]->Data is NULL.\n");
        return FALSE;
    }

    if (NULL == CompletionContext)
    {
        DbgPrint("[PostReadSwapBuffersWhenSafe]->CompletionContext is NULL.\n");
        return FALSE;
    }

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    NTSTATUS Status;
    PVOID OrigBuffer;
    PUCHAR NewBuffer;
    ULONG ReadLength;
    PSWAP_BUFFER_CONTEXT SwapReadContext = CompletionContext;

    DbgPrint("[PostReadSwapBuffersWhenSafe]->hit.\n");

    Status = FltLockUserBuffer(Data);

    if (!NT_SUCCESS(Status))
    {
        Data->IoStatus.Status = Status;
        Data->IoStatus.Information = 0;
    }
    else
    {
        OrigBuffer = MmGetSystemAddressForMdlSafe(Data->Iopb->Parameters.Read.MdlAddress, NormalPagePriority | MdlMappingNoExecute);
        if (OrigBuffer == NULL)
        {
            Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            Data->IoStatus.Information = 0;
            DbgPrint("[PostReadSwapBuffersWhenSafe]->OrigBuffer MmGetSystemAddressForMdlSafe failed!\n");
        }

        //解密函数
        NewBuffer = SwapReadContext->NewBuffer;
        ReadLength = (ULONG)Data->IoStatus.Information;

        DbgPrint("[PostReadSwapBuffersWhenSafe]->Encrypted content = %s ReadLength = %d Length = %d.\n", NewBuffer, ReadLength, Data->Iopb->Parameters.Read.Length);
     
        if (!EptAesDecrypt(NewBuffer, ReadLength))
        {
            DbgPrint("[PostReadSwapBuffersWhenSafe]->EptAesDecrypt Buffer failed!\n");

            if (NULL != SwapReadContext->NewBuffer)
            {
                FltFreePoolAlignedWithTag(FltObjects->Instance, SwapReadContext->NewBuffer, SWAP_READ_BUFFER_TAG);
                SwapReadContext->NewBuffer = NULL;
            }

            if (NULL != SwapReadContext)
            {
                ExFreePool(SwapReadContext);
                SwapReadContext = NULL;
            }

            return FALSE;
        }

        DbgPrint("[PostReadSwapBuffersWhenSafe]Decrypted content = %s.\n", NewBuffer);

        if (SwapReadContext->NewBuffer)
            RtlCopyMemory(OrigBuffer, SwapReadContext->NewBuffer, Data->IoStatus.Information);

    }

    if (NULL != SwapReadContext->NewBuffer)
    {
        FltFreePoolAlignedWithTag(FltObjects->Instance, SwapReadContext->NewBuffer, SWAP_READ_BUFFER_TAG);
        SwapReadContext->NewBuffer = NULL;
    }

    if (NULL != SwapReadContext)
    {
        ExFreePool(SwapReadContext);
        SwapReadContext = NULL;
    }

    DbgPrint("\n");

    return FLT_POSTOP_FINISHED_PROCESSING;

}