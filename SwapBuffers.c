
#include "swapbuffers.h"
#include "common.h"


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
        NewBuffer = FltAllocatePoolAlignedWithTag(FltObjects->Instance, NonPagedPool, WriteLength + 1, SWAP_WRITE_BUFFER_TAG);
        if (NewBuffer == NULL) {
            DbgPrint("NewBuffer FltAllocatePoolAlignedWithTag failed!\n");
            Status = FLT_PREOP_SUCCESS_NO_CALLBACK;
            leave;
        }

        RtlZeroMemory(NewBuffer, WriteLength + 1);


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

    for (ULONG i = 0; i < WriteLength; i++)
    {
        NewBuffer[i] ^= 0x77;
    }

    //DbgPrint输出需要加上EOF
    RtlCopyMemory(&NewBuffer[WriteLength], "\0", 1);
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


BOOLEAN PostReadSwapBuffers(PFLT_CALLBACK_DATA* Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext)
{

    PVOID OrigBuffer;
    PUCHAR NewBuffer;
    ULONG ReadLength;
    PSWAP_BUFFER_CONTEXT SwapReadContext = CompletionContext;

    if ((*Data)->Iopb->Parameters.Read.MdlAddress != NULL)
    {
        OrigBuffer = MmGetSystemAddressForMdlSafe((*Data)->Iopb->Parameters.Read.MdlAddress, NormalPagePriority | MdlMappingNoExecute);
        if (OrigBuffer == NULL)
        {
            OrigBuffer = (*Data)->Iopb->Parameters.Read.ReadBuffer;
            DbgPrint("OrigBuffer MmGetSystemAddressForMdlSafe failed!\n");
        }
    }
    //暂时不处理其他选项
    else
    {
        OrigBuffer = (*Data)->Iopb->Parameters.Read.ReadBuffer;
    }


    //解密函数
    NewBuffer = SwapReadContext->NewBuffer;
    ReadLength = (ULONG)(*Data)->IoStatus.Information;

    DbgPrint("PostRead Encrypted content = %s.\n", NewBuffer);

    for (ULONG i = 0; i < ReadLength; i++)
    {
        NewBuffer[i] ^= 0x77;
    }

    DbgPrint("PostRead Decrypted content = %s.\n", NewBuffer);


    try
    {
        if (SwapReadContext->NewBuffer)
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