
#include "swapbuffers.h"
#include "common.h"
#include "context.h"
#include "cryptography.h"


FLT_POSTOP_CALLBACK_STATUS PostReadSwapBuffersWhenSafe(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags);


BOOLEAN PreWriteSwapBuffers(PFLT_CALLBACK_DATA* Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{

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
                DbgPrint("OrigBuffer MmGetSystemAddressForMdlSafe failed!\n");
                Status = FLT_PREOP_SUCCESS_NO_CALLBACK;
                leave;
            }
        }
        else {

            OrigBuffer = (*Data)->Iopb->Parameters.Write.WriteBuffer;
        }

        //获得加密后数据的大小
        EptAesEncrypt(FltObjects, OrigBuffer, &WriteLength, TRUE);
        //DbgPrint("WriteLength = %d.\n", WriteLength);

        //获得WriteBuffer真正的大小，防止内存越界
        Status = FltGetVolumeContext(FltObjects->Filter, FltObjects->Volume, &VolumeContext);

        if (!NT_SUCCESS(Status)) {
            DbgPrint("VolumeContext FltGetVolumeContext failed!.\n");
            Status = FLT_PREOP_SUCCESS_NO_CALLBACK;
            leave;
        }

        if (FlagOn((*Data)->Iopb->IrpFlags, IRP_NOCACHE)) {

            WriteLength = ROUND_TO_SIZE(WriteLength, VolumeContext->SectorSize);
        }

        FltReleaseContext(VolumeContext);


        //为新WriteBuffer,MdlAddress分配暂存空间
        SwapWriteContext = ExAllocatePoolWithTag(NonPagedPool, sizeof(SWAP_BUFFER_CONTEXT), SWAP_WRITE_CONTEXT_TAG);
        if (SwapWriteContext == NULL) {
            DbgPrint("SwapWriteContext ExAllocatePoolWithTag failed!\n");
            Status = FLT_PREOP_SUCCESS_NO_CALLBACK;
            leave;
        }

        RtlZeroMemory(SwapWriteContext, sizeof(SWAP_BUFFER_CONTEXT));

        //只需要为noncached IO分配内存，但这里简化
        NewBuffer = FltAllocatePoolAlignedWithTag(FltObjects->Instance, NonPagedPool, WriteLength, SWAP_WRITE_BUFFER_TAG);
        if (NewBuffer == NULL) {
            DbgPrint("NewBuffer FltAllocatePoolAlignedWithTag failed!\n");
            Status = FLT_PREOP_SUCCESS_NO_CALLBACK;
            leave;
        }

        RtlZeroMemory(NewBuffer, WriteLength);


        //只需要为IRP操作建立MDL，不需要为FASTIO操作
        if (FlagOn((*Data)->Flags, FLTFL_CALLBACK_DATA_IRP_OPERATION)) {

            NewMdl = IoAllocateMdl(NewBuffer, WriteLength, FALSE, FALSE, NULL);
            if (NewMdl == NULL) {
                DbgPrint("NewMDL IoAllocateMdl failed!\n");
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

    DbgPrint("PreWrite NewBuffer content = %s.\n", NewBuffer);

    //for (ULONG i = 0; i < WriteLength; i++)
    //{
    //    NewBuffer[i] ^= 0x77;
    //}
    //这里WriteLength作为NewBuffer的大小传入，作为LengthReturned传出
    EptAesEncrypt(FltObjects, NewBuffer, &WriteLength, FALSE);
    (*Data)->Iopb->Parameters.Write.Length = WriteLength;

    DbgPrint("PreWrite Encrypted content = %s.\n", NewBuffer);

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


BOOLEAN PreReadSwapBuffers(PFLT_CALLBACK_DATA* Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) 
{

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

    FltReleaseContext(VolumeContext);


    SwapReadContext = ExAllocatePoolWithTag(NonPagedPool, sizeof(SWAP_BUFFER_CONTEXT), SWAP_READ_CONTEXT_TAG);
    if (SwapReadContext == NULL)
    {
        DbgPrint("SwapReadContext ExAllocatePoolWithTag failed!\n");
        return FALSE;
    }

    RtlZeroMemory(SwapReadContext, sizeof(SWAP_BUFFER_CONTEXT));

    //只需要为noncached IO分配内存，但这里简化
    NewBuffer = FltAllocatePoolAlignedWithTag(FltObjects->Instance, NonPagedPool, ReadLength, SWAP_READ_BUFFER_TAG);
    if (NewBuffer == NULL)
    {
        DbgPrint("NewBuffer FltAllocatePoolAlignedWithTag failed!\n");
        ExFreePool(SwapReadContext);
        return FALSE;
    }

    RtlZeroMemory(NewBuffer, ReadLength);



    //只需要为IRP操作建立MDL，不需要为FASTIO操作
    if (FlagOn((*Data)->Flags, FLTFL_CALLBACK_DATA_IRP_OPERATION)) {

        NewMdl = IoAllocateMdl(NewBuffer, ReadLength, FALSE, FALSE, NULL);
        if (NewMdl == NULL)
        {
            DbgPrint("NewMDL IoAllocateMdl failed!\n");
            ExFreePool(SwapReadContext);
            FltFreePoolAlignedWithTag(FltObjects->Instance, NewBuffer, SWAP_READ_BUFFER_TAG);
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


BOOLEAN PostReadSwapBuffers(PFLT_CALLBACK_DATA* Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{

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
            DbgPrint("OrigBuffer MmGetSystemAddressForMdlSafe failed!\n");
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

    DbgPrint("PostRead Encrypted content = %s ReadLength = %d Length = %d.\n", NewBuffer, ReadLength, (*Data)->Iopb->Parameters.Read.Length);

    //for (ULONG i = 0; i < ReadLength; i++)
    //{
    //    NewBuffer[i] ^= 0x77;
    //}

    EptAesDecrypt(NewBuffer, ReadLength);

    DbgPrint("PostRead Decrypted content = %s.\n", NewBuffer);


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

    if (SwapReadContext->NewBuffer != NULL)
        FltFreePoolAlignedWithTag(FltObjects->Instance, SwapReadContext->NewBuffer, SWAP_READ_BUFFER_TAG);


    if (SwapReadContext != NULL) {
        ExFreePool(SwapReadContext);
    }

    return TRUE;
}


FLT_POSTOP_CALLBACK_STATUS PostReadSwapBuffersWhenSafe(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    NTSTATUS Status;
    PVOID OrigBuffer;
    PUCHAR NewBuffer;
    ULONG ReadLength;
    PSWAP_BUFFER_CONTEXT SwapReadContext = CompletionContext;

    DbgPrint("PostReadSwapBuffersWhenSafe hit.\n");

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
            DbgPrint("OrigBuffer MmGetSystemAddressForMdlSafe failed!\n");
        }

        //解密函数
        NewBuffer = SwapReadContext->NewBuffer;
        ReadLength = (ULONG)Data->IoStatus.Information;

        DbgPrint("PostRead Encrypted content = %s ReadLength = %d Length = %d.\n", NewBuffer, ReadLength, Data->Iopb->Parameters.Read.Length);

        //for (ULONG i = 0; i < ReadLength; i++)
        //{
        //    NewBuffer[i] ^= 0x77;
        //}

        EptAesDecrypt(NewBuffer, ReadLength);

        DbgPrint("PostRead Decrypted content = %s.\n", NewBuffer);

        if (SwapReadContext->NewBuffer)
            RtlCopyMemory(OrigBuffer, SwapReadContext->NewBuffer, Data->IoStatus.Information);

    }

    if (SwapReadContext->NewBuffer != NULL)
        FltFreePoolAlignedWithTag(FltObjects->Instance, SwapReadContext->NewBuffer, SWAP_READ_BUFFER_TAG);


    if (SwapReadContext != NULL) {
        ExFreePool(SwapReadContext);
    }

    DbgPrint("\n");

    return FLT_POSTOP_FINISHED_PROCESSING;

}