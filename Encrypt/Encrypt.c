/*++

Module Name:

    Encrypt.c

Abstract:

    This is the main module of the Encrypt miniFilter driver.

Environment:

    Kernel mode

--*/

#include "global.h"
#include "filefunc.h"
#include "context.h"
#include "swapbuffers.h"
#include "commport.h"
#include "cryptography.h"
#include "processverify.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;
EptQueryInformationProcess pEptQueryInformationProcess = NULL;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))


//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, EncryptUnload)
#pragma alloc_text(PAGE, EncryptInstanceQueryTeardown)
#pragma alloc_text(PAGE, EncryptInstanceSetup)
#pragma alloc_text(PAGE, EncryptInstanceTeardownStart)
#pragma alloc_text(PAGE, EncryptInstanceTeardownComplete)
#endif

//
//  operation registration
//

CONST FLT_CONTEXT_REGISTRATION Context[] = {

    { FLT_VOLUME_CONTEXT,
      0,
      NULL,
      sizeof(VOLUME_CONTEXT),
      VOLUME_CONTEXT_TAG 
    },

    { FLT_STREAM_CONTEXT,
      0,
      NULL,
      sizeof(EPT_STREAM_CONTEXT),
      STREAM_CONTEXT_TAG 
    },

    { FLT_CONTEXT_END }

};

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

    { IRP_MJ_CREATE,
      0,
      EncryptPreCreate,
      EncryptPostCreate 
    },

    { IRP_MJ_READ,
      0,
      EncryptPreRead,
      EncryptPostRead
    },

    { IRP_MJ_WRITE,
      0,
      EncryptPreWrite,
      EncryptPostWrite 
    },

    { IRP_MJ_QUERY_INFORMATION,
      0,
      EncryptPreQueryInformation,
      EncryptPostQueryInformation
    },

    { IRP_MJ_SET_INFORMATION,
      0,
      EncryptPreSetInformation,
      EncryptPostSetInformation
    },
        
    { IRP_MJ_CLEANUP,
      0,
      EncryptPreCleanUp,
      EncryptPostCleanUp
    },

    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    Context,                               //  Context
    Callbacks,                          //  Operation callbacks

    EncryptUnload,                           //  MiniFilterUnload

    EncryptInstanceSetup,                    //  InstanceSetup
    EncryptInstanceQueryTeardown,            //  InstanceQueryTeardown
    EncryptInstanceTeardownStart,            //  InstanceTeardownStart
    EncryptInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};



NTSTATUS
EncryptInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
{
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );


    NTSTATUS Status;
    PVOLUME_CONTEXT VolumeContext = NULL;
    ULONG LengthReturned;
    UCHAR VolPropBuffer[sizeof(FLT_VOLUME_PROPERTIES) + 512];
    PFLT_VOLUME_PROPERTIES VolProp = (PFLT_VOLUME_PROPERTIES)VolPropBuffer;

    PAGED_CODE();

    try {

        Status = FltAllocateContext(gFilterHandle, FLT_VOLUME_CONTEXT, sizeof(VOLUME_CONTEXT), NonPagedPool, &VolumeContext);

        if (!NT_SUCCESS(Status)) {

            DbgPrint("pVolumeContext FltAllocateContext failed!.\n");
            leave;
        }

        RtlZeroMemory(VolumeContext, sizeof(VOLUME_CONTEXT));


        Status = FltGetVolumeProperties(FltObjects->Volume, VolProp, sizeof(VolPropBuffer), &LengthReturned);

        if (!NT_SUCCESS(Status)) {

            DbgPrint("VolProp FltGetVolumeProperties failed!.\n");
            leave;
        }

        //  we will pick a minimum sector size if a sector size is not
        //  specified. MIN_SECTOR_SIZE = 0x200.
        VolumeContext->SectorSize = max(VolProp->SectorSize, 0x200);

        FltSetVolumeContext(FltObjects->Volume, FLT_SET_CONTEXT_KEEP_IF_EXISTS, VolumeContext, NULL);

        Status = STATUS_SUCCESS;

    }
    finally {

        if (VolumeContext) {

            FltReleaseContext(VolumeContext);
        }

    }


    return Status;
}


NTSTATUS
EncryptInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Encrypt!EncryptInstanceQueryTeardown: Entered\n") );

    return STATUS_SUCCESS;
}


VOID
EncryptInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Encrypt!EncryptInstanceTeardownStart: Entered\n") );
}


VOID
EncryptInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Encrypt!EncryptInstanceTeardownComplete: Entered\n") );
}


/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver.  This
    registers with FltMgr and initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Routine can return non success error codes.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( RegistryPath );


    //得到ZwQueryInformationProcess()函数指针
    UNICODE_STRING FuncName;
    RtlInitUnicodeString(&FuncName, L"ZwQueryInformationProcess");
    pEptQueryInformationProcess = (EptQueryInformationProcess)(ULONG_PTR)MmGetSystemRoutineAddress(&FuncName);

    InitializeListHead(&ListHead);

    /*这里先初始化一个规则*/
    PEPT_PROCESS_RULES ProcessRules;
    ProcessRules = ExAllocatePoolWithTag(PagedPool, sizeof(EPT_PROCESS_RULES), PROCESS_RULES_BUFFER_TAG);
    if (!ProcessRules)
    {
        DbgPrint("[DriverEntry]->ExAllocatePoolWithTag ProcessRules failed.\n");
        return 0;
    }

    RtlZeroMemory(ProcessRules, sizeof(EPT_PROCESS_RULES));
    RtlMoveMemory(ProcessRules->TargetProcessName, "notepad.exe", sizeof("notepad.exe"));
    RtlMoveMemory(ProcessRules->TargetExtension, "txt,", sizeof("txt,"));
    ProcessRules->count = 1;

    ULONGLONG Hash[4];
    Hash[0] = 0xa28438e1388f272a;
    Hash[1] = 0x52559536d99d65ba;
    Hash[2] = 0x15b1a8288be1200e;
    Hash[3] = 0x249851fdf7ee6c7e;

    ULONGLONG TempHash;
    RtlZeroMemory(ProcessRules->Hash, sizeof(ProcessRules->Hash));
    
    for (ULONG i = 0; i < 4; i++)
    {
        TempHash = Hash[i];
        for (ULONG j = 0; j < 8; j++)
        {
            ProcessRules->Hash[8 * (i + 1) - 1 - j] = TempHash % 256;
            TempHash = TempHash / 256;
        }

    }

    InsertTailList(&ListHead, &ProcessRules->ListEntry);


    PEPT_PROCESS_RULES ProcessRules2;

    ProcessRules2 = ExAllocatePoolWithTag(PagedPool, sizeof(EPT_PROCESS_RULES), PROCESS_RULES_BUFFER_TAG);
    if (!ProcessRules2)
    {
        DbgPrint("[DriverEntry]->ExAllocatePoolWithTag ProcessRules2 failed.\n");
        return 0;
    }

    RtlZeroMemory(ProcessRules2, sizeof(EPT_PROCESS_RULES));
    RtlMoveMemory(ProcessRules2->TargetProcessName, "notepad++.exe", sizeof("notepad++.exe"));
    RtlMoveMemory(ProcessRules2->TargetExtension, "txt,", sizeof("txt,"));
    ProcessRules2->count = 1;


    InsertTailList(&ListHead, &ProcessRules2->ListEntry);



    //
    //  Register with FltMgr to tell it our callback routines
    //

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );

    FLT_ASSERT( NT_SUCCESS( status ) );

    if (NT_SUCCESS( status )) {

        //
        //  Start filtering i/o
        //

        status = FltStartFiltering( gFilterHandle );

        if (!NT_SUCCESS( status )) {

            FltUnregisterFilter( gFilterHandle );
        }

        if (!EptInitCommPort())
        {
            FltUnregisterFilter(gFilterHandle);
        }

        AesInitVar.Flag = EptAesInithKey();

        if (!AesInitVar.Flag)
        {
            FltUnregisterFilter(gFilterHandle);
            EptCloseCommPort();
        }

    }

    return status;
}

NTSTATUS
EncryptUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Encrypt!EncryptUnload: Entered\n") );

    EptCloseCommPort();

    if (gFilterHandle)
    {
        FltUnregisterFilter(gFilterHandle);
    }

    EptAesCleanUp();

    EptListCleanUp();

    return STATUS_SUCCESS;
}


/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
EncryptPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    ) 
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PAGED_CODE();

    PEPT_STREAM_CONTEXT StreamContext;

    if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) 
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //判断是否为目标扩展名，进一步筛选，减少后续操作
    if (!EptIsTargetExtension(Data)) 
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //只要在PreCreate中检查Hash就可以了
    CheckHash = FALSE;
    if (!EptIsTargetProcess(Data)) 
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //DbgPrint("[EncryptPreCreate]->hit.\n");

    if (!EptCreateContext(&StreamContext, FLT_STREAM_CONTEXT)) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    *CompletionContext = StreamContext;

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}


FLT_POSTOP_CALLBACK_STATUS
EncryptPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    PEPT_STREAM_CONTEXT StreamContext;

    StreamContext = CompletionContext;


    //判断是否为新建的文件，且有写入数据的倾向，有则写入加密标识头
    //如果既不是新建有加密头，又不是已有加密头，说明是目标进程打开的普通文件，结束处理
    if (!EptWriteFileHeader(&Data, FltObjects) && !EptIsTargetFile(FltObjects)) {

        if (NULL != StreamContext)
        {
            FltReleaseContext(StreamContext);
            StreamContext = NULL;
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //DbgPrint("[EncryptPostCreate]->hit.\n");

    if (!EptGetOrSetContext(Data, FltObjects, &StreamContext, FLT_STREAM_CONTEXT)) {

        if (NULL != StreamContext)
        {
            FltReleaseContext(StreamContext);
            StreamContext = NULL;
        }
        DbgPrint("[EncryptPostCreate]->EptGetOrSetContext failed.\n");;
    }


    //到这里说明文件有加密标识头，设置StreamContext标识位
    EptSetFlagInContext(&StreamContext->FlagExist, TRUE);
    DbgPrint("[EncryptPostCreate]->Set StreamContext->FlagExist\n");
    
    if (NULL != StreamContext)
    {
        FltReleaseContext(StreamContext);
        StreamContext = NULL;
    }
    
    //DbgPrint("\n");

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
EncryptPreRead(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PEPT_STREAM_CONTEXT StreamContext;

    if (FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_FAST_IO_OPERATION))
    {
        return FLT_PREOP_DISALLOW_FASTIO;
    }

    if (Data->Iopb->Parameters.Read.Length == 0)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PAGED_CODE();

    if (!EptCreateContext(&StreamContext, FLT_STREAM_CONTEXT)) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!EptGetOrSetContext(Data, FltObjects, &StreamContext, FLT_STREAM_CONTEXT)) {

        if (NULL != StreamContext)
        {
            FltReleaseContext(StreamContext);
            StreamContext = NULL;
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!StreamContext->FlagExist) 
    {
        if (NULL != StreamContext)
        {
            FltReleaseContext(StreamContext);
            StreamContext = NULL;
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (NULL != StreamContext)
    {
        FltReleaseContext(StreamContext);
        StreamContext = NULL;
    }

    if (!EptIsTargetProcess(Data))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!FlagOn(Data->Iopb->IrpFlags, (IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO | IRP_NOCACHE)))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }


    DbgPrint("[EncryptPreRead]->hit.\n");

    PreReadSwapBuffers(&Data, FltObjects, CompletionContext);

    Data->Iopb->Parameters.Read.ByteOffset.QuadPart += FILE_FLAG_SIZE;
    FltSetCallbackDataDirty(Data);

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}


FLT_POSTOP_CALLBACK_STATUS
EncryptPostRead(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    DbgPrint("[EncryptPostRead]->hit.\n");

    PostReadSwapBuffers(&Data, FltObjects, CompletionContext, Flags);


    DbgPrint("\n");

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
EncryptPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{

    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    
    PEPT_STREAM_CONTEXT StreamContext;

    if (FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_FAST_IO_OPERATION))
    {
        return FLT_PREOP_DISALLOW_FASTIO;
    }

    if (Data->Iopb->Parameters.Write.Length == 0)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PAGED_CODE();

    if (!EptCreateContext(&StreamContext, FLT_STREAM_CONTEXT)) {
    
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!EptGetOrSetContext(Data, FltObjects, &StreamContext, FLT_STREAM_CONTEXT)) {

        if (NULL != StreamContext)
        {
            FltReleaseContext(StreamContext);
            StreamContext = NULL;
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!StreamContext->FlagExist) {

        if (NULL != StreamContext)
        {
            FltReleaseContext(StreamContext);
            StreamContext = NULL;
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (NULL != StreamContext)
    {
        FltReleaseContext(StreamContext);
        StreamContext = NULL;
    }

    if (!EptIsTargetProcess(Data))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!FlagOn(Data->Iopb->IrpFlags, (IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO | IRP_NOCACHE)))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    DbgPrint("[EncryptPreWrite]->hit.\n");

    PreWriteSwapBuffers(&Data, FltObjects, CompletionContext);

    FltSetCallbackDataDirty(Data);

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}


FLT_POSTOP_CALLBACK_STATUS
EncryptPostWrite (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    DbgPrint("[EncryptPostWrite]->hit.\n");

    PSWAP_BUFFER_CONTEXT SwapWriteContext = CompletionContext;

    if (SwapWriteContext->NewBuffer != NULL)
        FltFreePoolAlignedWithTag(FltObjects->Instance, SwapWriteContext->NewBuffer, SWAP_WRITE_BUFFER_TAG);

    //if (SwapWriteContext->NewMdlAddress != NULL)
    //    IoFreeMdl(SwapWriteContext->NewMdlAddress);

    if (SwapWriteContext != NULL) {
        ExFreePool(SwapWriteContext);
    }


    DbgPrint("\n");
    
    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
EncryptPreQueryInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{

    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PEPT_STREAM_CONTEXT StreamContext;

    if (FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_FAST_IO_OPERATION))
    {
        return FLT_PREOP_DISALLOW_FASTIO;
    }

    if (!EptCreateContext(&StreamContext, FLT_STREAM_CONTEXT)) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    *CompletionContext = StreamContext;

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;

}


FLT_POSTOP_CALLBACK_STATUS
EncryptPostQueryInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PEPT_STREAM_CONTEXT StreamContext;
    LONGLONG FileOffset = 0;

    StreamContext = CompletionContext;

    if (!EptGetOrSetContext(Data, FltObjects, &StreamContext, FLT_STREAM_CONTEXT)) 
    {
        if (NULL != StreamContext)
        {
            FltReleaseContext(StreamContext);
            StreamContext = NULL;
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!StreamContext->FlagExist) 
    {
        if (NULL != StreamContext)
        {
            FltReleaseContext(StreamContext);
            StreamContext = NULL;
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!EptIsTargetProcess(Data))
    {
        if (NULL != StreamContext)
        {
            FltReleaseContext(StreamContext);
            StreamContext = NULL;
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    DbgPrint("[EncryptPostQueryInformation]->FileInformationClass = %d.\n", Data->Iopb->Parameters.QueryFileInformation.FileInformationClass);

    PVOID InfoBuffer = Data->Iopb->Parameters.QueryFileInformation.InfoBuffer;

    if (StreamContext->FileSize > 0 &&(StreamContext->FileSize % AES_BLOCK_SIZE != 0))
    {
        FileOffset = (StreamContext->FileSize / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE - StreamContext->FileSize;
    }
    else if (StreamContext->FileSize > 0 && (StreamContext->FileSize % AES_BLOCK_SIZE == 0))
    {
        FileOffset = 0;
    }

    DbgPrint("[EncryptPostQueryInformation]->FileOffset = %d.\n", FileOffset);

    switch (Data->Iopb->Parameters.QueryFileInformation.FileInformationClass) {

    case FileStandardInformation:
    {
        PFILE_STANDARD_INFORMATION Info = (PFILE_STANDARD_INFORMATION)InfoBuffer;
        Info->AllocationSize.QuadPart -= FILE_FLAG_SIZE;
        Info->EndOfFile.QuadPart = Info->EndOfFile.QuadPart - FILE_FLAG_SIZE - FileOffset;
        break;
    }
    case FileAllInformation:
    {
        PFILE_ALL_INFORMATION Info = (PFILE_ALL_INFORMATION)InfoBuffer;
        if (Data->IoStatus.Information >=
            sizeof(FILE_BASIC_INFORMATION) +
            sizeof(FILE_STANDARD_INFORMATION))
        {
            if (Info->StandardInformation.AllocationSize.QuadPart > FILE_FLAG_SIZE)
            {
                Info->StandardInformation.AllocationSize.QuadPart -= FILE_FLAG_SIZE;
            }
            
            Info->StandardInformation.EndOfFile.QuadPart = Info->StandardInformation.EndOfFile.QuadPart - FILE_FLAG_SIZE - FileOffset;

            if (Data->IoStatus.Information >=
                sizeof(FILE_BASIC_INFORMATION) +
                sizeof(FILE_STANDARD_INFORMATION) +
                sizeof(FILE_EA_INFORMATION) +
                sizeof(FILE_ACCESS_INFORMATION) +
                sizeof(FILE_POSITION_INFORMATION))
            {

                if (Info->PositionInformation.CurrentByteOffset.QuadPart > FILE_FLAG_SIZE)
                {
                    Info->PositionInformation.CurrentByteOffset.QuadPart -= FILE_FLAG_SIZE;
                    //DbgPrint("CurrentByteOffset = %d.\n", Info->PositionInformation.CurrentByteOffset.QuadPart);
                }

            }
        }
        break;
    }
    case FileAllocationInformation:
    {
        PFILE_ALLOCATION_INFORMATION Info = (PFILE_ALLOCATION_INFORMATION)InfoBuffer;
        Info->AllocationSize.QuadPart -= FILE_FLAG_SIZE;
        //DbgPrint("AllocationSize = %d.\n", Info->AllocationSize.QuadPart);
        break;
    }
    case FileValidDataLengthInformation:
    {
        PFILE_VALID_DATA_LENGTH_INFORMATION Info = (PFILE_VALID_DATA_LENGTH_INFORMATION)InfoBuffer;
        Info->ValidDataLength.QuadPart -= FILE_FLAG_SIZE;
        break;
    }
    case FileEndOfFileInformation:
    {
        PFILE_END_OF_FILE_INFORMATION Info = (PFILE_END_OF_FILE_INFORMATION)InfoBuffer;
        Info->EndOfFile.QuadPart = Info->EndOfFile.QuadPart - FILE_FLAG_SIZE - FileOffset;
        break;
    }
    case FilePositionInformation:
    {
        PFILE_POSITION_INFORMATION Info = (PFILE_POSITION_INFORMATION)InfoBuffer;
        if (Info->CurrentByteOffset.QuadPart > FILE_FLAG_SIZE)
        {
            Info->CurrentByteOffset.QuadPart -= FILE_FLAG_SIZE;
            //DbgPrint("EncryptPostQueryInformation FilePositionInformation CurrentByteOffset hit.\n");
        }

        break;
    }
    case FileStreamInformation:
    {
        PFILE_STREAM_INFORMATION Info = (PFILE_STREAM_INFORMATION)InfoBuffer;
        Info->StreamAllocationSize.QuadPart -= FILE_FLAG_SIZE;
        Info->StreamSize.QuadPart -= FILE_FLAG_SIZE;
        break;
    }
    case FileNetworkOpenInformation:
    {
        PFILE_NETWORK_OPEN_INFORMATION  Info = (PFILE_NETWORK_OPEN_INFORMATION)InfoBuffer;
        Info->EndOfFile.QuadPart = Info->EndOfFile.QuadPart - FILE_FLAG_SIZE - FileOffset;
        Info->AllocationSize.QuadPart -= FILE_FLAG_SIZE;;
    }
    default:
    {
        break;
    }
    }

    FltSetCallbackDataDirty(Data);


    if (NULL != StreamContext)
    {
        FltReleaseContext(StreamContext);
        StreamContext = NULL;
    }
    //DbgPrint("\n");

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
EncryptPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_FAST_IO_OPERATION))
    {
        return FLT_PREOP_DISALLOW_FASTIO;
    }

    PEPT_STREAM_CONTEXT StreamContext;

    PAGED_CODE();

    if (!EptCreateContext(&StreamContext, FLT_STREAM_CONTEXT)) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!EptGetOrSetContext(Data, FltObjects, &StreamContext, FLT_STREAM_CONTEXT)) {

        if (NULL != StreamContext)
        {
            FltReleaseContext(StreamContext);
            StreamContext = NULL;
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!StreamContext->FlagExist) 
    {
        if (NULL != StreamContext)
        {
            FltReleaseContext(StreamContext);
            StreamContext = NULL;
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!EptIsTargetProcess(Data))
    {
        if (NULL != StreamContext)
        {
            FltReleaseContext(StreamContext);
            StreamContext = NULL;
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    DbgPrint("[EncryptPreSetInformation]->FileInformationClass = %d.\n", Data->Iopb->Parameters.SetFileInformation.FileInformationClass);

    // 4096 -> 3->16      956

    PVOID InfoBuffer = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;

    switch (Data->Iopb->Parameters.QueryFileInformation.FileInformationClass)
    {

    case FileEndOfFileInformation:
    {
        PFILE_END_OF_FILE_INFORMATION Info = (PFILE_END_OF_FILE_INFORMATION)InfoBuffer;
        if (Info->EndOfFile.QuadPart % AES_BLOCK_SIZE != 0)
        {
            StreamContext->FileSize = Info->EndOfFile.QuadPart - FILE_FLAG_SIZE;
            Info->EndOfFile.QuadPart = (Info->EndOfFile.QuadPart / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
        }
        else
        {
            StreamContext->FileSize = Info->EndOfFile.QuadPart - FILE_FLAG_SIZE;
        }
        
        DbgPrint("[EncryptPreSetInformation]->FileEndOfFileInformation EndOfFile = %d.\n", Info->EndOfFile.QuadPart);
        break;
    }
    case FileAllocationInformation:
    {
        PFILE_END_OF_FILE_INFORMATION Info = (PFILE_END_OF_FILE_INFORMATION)InfoBuffer;
        if (Info->EndOfFile.QuadPart % AES_BLOCK_SIZE != 0)
        {
            StreamContext->FileSize = Info->EndOfFile.QuadPart - FILE_FLAG_SIZE;
            Info->EndOfFile.QuadPart = (Info->EndOfFile.QuadPart / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
        }
        else
        {
            StreamContext->FileSize = Info->EndOfFile.QuadPart - FILE_FLAG_SIZE;
        }

        DbgPrint("EncryptPreSetInformation FileAllocationInformation EndOfFile = %d.\n", Info->EndOfFile.QuadPart);
        break;
    }

    }


    if (NULL != StreamContext)
    {
        FltReleaseContext(StreamContext);
        StreamContext = NULL;
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
EncryptPostSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
EncryptPreCleanUp(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PAGED_CODE();


    PEPT_STREAM_CONTEXT StreamContext;

    if (!EptCreateContext(&StreamContext, FLT_STREAM_CONTEXT)) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!EptGetOrSetContext(Data, FltObjects, &StreamContext, FLT_STREAM_CONTEXT)) 
    {
        if (NULL != StreamContext)
        {
            FltReleaseContext(StreamContext);
            StreamContext = NULL;
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!StreamContext->FlagExist) 
    {
        if (NULL != StreamContext)
        {
            FltReleaseContext(StreamContext);
            StreamContext = NULL;
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (NULL != StreamContext)
    {
        FltReleaseContext(StreamContext);
        StreamContext = NULL;
    }

    if (!EptIsTargetProcess(Data))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //DbgPrint("[EncryptPreCleanUp]->hit.\n");
    EptFileCacheClear(FltObjects->FileObject);
    
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;

}


FLT_POSTOP_CALLBACK_STATUS
EncryptPostCleanUp(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    //DbgPrint("[EncryptPostCleanUp]->hit.\n");
    //DbgPrint("\n");

    return FLT_POSTOP_FINISHED_PROCESSING;
}

