#pragma warning(disable:4996)

#include "filefunc.h"
#include "commport.h"
#include "cryptography.h"


ULONG BreakPointFlag = 1;

#define FILE_CLEAR_CACHE_USE_ORIGINAL_LOCK  1


//自定义断点，单次，获取系统时间，输出后等待1秒，断点
VOID EptBreakPointOnce() {

	LARGE_INTEGER SystemTime;
	LARGE_INTEGER LocalTime;
	TIME_FIELDS  TimeFiled;
	KEVENT Event;
	ULONG MircoSecond = 1000000;

	if (BreakPointFlag) {

		BreakPointFlag--;

		//获取当前时间
		KeQuerySystemTime(&SystemTime);
		ExSystemTimeToLocalTime(&SystemTime, &LocalTime);
		RtlTimeToTimeFields(&LocalTime, &TimeFiled);

		DbgPrint("\n-----------------------------------------------------\n\n");
		DbgPrint("Ept DbgBreakPoint once. Test time = %d-%02d-%02d %02d:%02d.\n"
			, TimeFiled.Year
			, TimeFiled.Month
			, TimeFiled.Day
			, TimeFiled.Hour
			, TimeFiled.Minute);
		DbgPrint("\n-----------------------------------------------------\n");

		//初始化一个事件内核对象, 并初始化为非触发态
		KeInitializeEvent(&Event, NotificationEvent, FALSE);
		//设置等待时间
		LARGE_INTEGER TimeOut = RtlConvertUlongToLargeInteger(-10 * MircoSecond);
		//等待事件对象1秒
		KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, &TimeOut);

		DbgBreakPoint();

		return;

	}
}


VOID EptReadWriteCallbackRoutine(
    PFLT_CALLBACK_DATA CallbackData,
    PFLT_CONTEXT Context
)
{
    UNREFERENCED_PARAMETER(CallbackData);
    KeSetEvent((PRKEVENT)Context, IO_NO_INCREMENT, FALSE);
}


//获得文件大小，非重入
ULONG EptGetFileSize(IN PCFLT_RELATED_OBJECTS FltObjects)
{
    ASSERT(FltObjects != NULL);

    FILE_STANDARD_INFORMATION StandardInfo;
    ULONG LengthReturned;

    FltQueryInformationFile(FltObjects->Instance, FltObjects->FileObject, &StandardInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation, &LengthReturned);

    return (ULONG)StandardInfo.EndOfFile.QuadPart;
}


//判断是否为带有加密标记的文件
NTSTATUS EptIsTargetFile(IN PCFLT_RELATED_OBJECTS FltObjects) 
{
    ASSERT(FltObjects != NULL);

	NTSTATUS Status;
	PFLT_VOLUME Volume;
	FLT_VOLUME_PROPERTIES VolumeProps;

    KEVENT Event;

	PVOID ReadBuffer;
	LARGE_INTEGER ByteOffset = { 0 };
	ULONG Length;


	//根据FltReadFile对于Length的要求，Length必须是扇区大小的整数倍
	Status = FltGetVolumeFromInstance(FltObjects->Instance, &Volume);

	if (!NT_SUCCESS(Status)) {

		DbgPrint("[EptIsTargetFile]->FltGetVolumeFromInstance failed. Stattus = %x\n", Status);
		return FALSE;
	}

	Status = FltGetVolumeProperties(Volume, &VolumeProps, sizeof(VolumeProps), &Length);

	if (NT_ERROR(Status)) {

        if (NULL != Volume)
        {
            FltObjectDereference(Volume);
            Volume = NULL;
        }
		DbgPrint("[DEptIsTargetFile]->FltGetVolumeProperties failed.\n");
		return FALSE;
	}

	//DbgPrint("VolumeProps.SectorSize = %d.\n", VolumeProps.SectorSize);

	Length = FILE_FLAG_SIZE;
	Length = ROUND_TO_SIZE(Length, VolumeProps.SectorSize);

	//为FltReadFile分配内存，之后在Buffer中查找Flag
	ReadBuffer = FltAllocatePoolAlignedWithTag(FltObjects->Instance, PagedPool, Length, 'itRB');

	if (!ReadBuffer) {

        if (NULL != Volume)
        {
            FltObjectDereference(Volume);
            Volume = NULL;
        }
		DbgPrint("[EptIsTargetFile]->FltAllocatePoolAlignedWithTag ReadBuffer failed.\n");
		return FALSE;
	}

	RtlZeroMemory(ReadBuffer, Length);

    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

    //将文件读入缓冲区
    ByteOffset.QuadPart = 0;
    Status = FltReadFile(FltObjects->Instance, FltObjects->FileObject, &ByteOffset, Length, ReadBuffer,
        FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, NULL, EptReadWriteCallbackRoutine, &Event);

    KeWaitForSingleObject(&Event, Executive, KernelMode, TRUE, 0);

   
	if (!NT_SUCCESS(Status)) {

        //STATUS_PENDING
		DbgPrint("EptIsTargetFile FltReadFile failed. Status = %X.\n", Status);
        if (NULL != Volume)
        {
            FltObjectDereference(Volume);
            Volume = NULL;
        }
        if (NULL != ReadBuffer)
        {
            FltFreePoolAlignedWithTag(FltObjects->Instance, ReadBuffer, 'itRB');
            ReadBuffer = NULL;
        }
		
		return FALSE;

	}

	//DbgPrint("EptIsTargetFile Buffer = %p file content = %s.\n", ReadBuffer, (CHAR*)ReadBuffer);

	if (strncmp(FILE_FLAG, ReadBuffer, strlen(FILE_FLAG)) == 0) {

        if (NULL != Volume)
        {
            FltObjectDereference(Volume);
            Volume = NULL;
        }
        if (NULL != ReadBuffer)
        {
            FltFreePoolAlignedWithTag(FltObjects->Instance, ReadBuffer, 'itRB');
            ReadBuffer = NULL;
        }
		DbgPrint("[EptIsTargetFile]->TargetFile is match.\n");
		return EPT_ALREADY_HAVE_ENCRYPT_HEADER;
	}

    if (NULL != Volume)
    {
        FltObjectDereference(Volume);
        Volume = NULL;
    }

    if (NULL != ReadBuffer)
    {
        FltFreePoolAlignedWithTag(FltObjects->Instance, ReadBuffer, 'itRB');
        ReadBuffer = NULL;
    }
	return FALSE;
}


//如果是新建的文件，且有写入数据的倾向，写入加密标记头
NTSTATUS EptWriteEncryptHeader(IN OUT PFLT_CALLBACK_DATA* Data, IN PCFLT_RELATED_OBJECTS FltObjects) {

    ASSERT(Data != NULL);
    ASSERT(FltObjects != NULL);

	NTSTATUS Status;
    FILE_STANDARD_INFORMATION StandardInfo = { 0 };

	PFLT_VOLUME Volume;
	FLT_VOLUME_PROPERTIES VolumeProps;

    KEVENT Event;

	PVOID Buffer;
	LARGE_INTEGER ByteOffset;
	ULONG Length, LengthReturned;


	////查询文件大小
	Status = FltQueryInformationFile(FltObjects->Instance, FltObjects->FileObject, &StandardInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation, &LengthReturned);

	if (!NT_SUCCESS(Status) || Status == STATUS_VOLUME_DISMOUNTED) 
    {
		//DbgPrint("[EptWriteFileHeader]->FltQueryInformationFile failed. Status = %x\n", Status);
		return Status;
	}

    //根据FltWriteFile对于Length的要求，Length必须是扇区大小的整数倍
    Status = FltGetVolumeFromInstance(FltObjects->Instance, &Volume);

    if (!NT_SUCCESS(Status)) {

        DbgPrint("[EptWriteFileHeader]->FltGetVolumeFromInstance failed. Status = %x\n", Status);
        return Status;
    }

    Status = FltGetVolumeProperties(Volume, &VolumeProps, sizeof(VolumeProps), &Length);

    if (NULL != Volume)
    {
        FltObjectDereference(Volume);
        Volume = NULL;
    }


	//分配文件头FILE_FLAG_SIZE大小，写入文件flag
	if (StandardInfo.EndOfFile.QuadPart == 0
		&& ((*Data)->Iopb->Parameters.Create.SecurityContext->DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA))) {

        Length = max(sizeof(FILE_FLAG), FILE_FLAG_SIZE);
        Length = ROUND_TO_SIZE(Length, VolumeProps.SectorSize);

		Buffer = ExAllocatePoolWithTag(NonPagedPool, Length, 'wiBF');
		if (!Buffer) {

			DbgPrint("EptWriteEncryptHeader->ExAllocatePoolWithTag Buffer failed.\n");
			return Status;
		}

		RtlZeroMemory(Buffer, Length);

		if (Length >= sizeof(FILE_FLAG))
			RtlMoveMemory(Buffer, FILE_FLAG, sizeof(FILE_FLAG));


        KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

		//写入加密标记头
		ByteOffset.QuadPart = 0;
		Status = FltWriteFile(FltObjects->Instance, FltObjects->FileObject, &ByteOffset, Length, Buffer,
			FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, NULL, EptReadWriteCallbackRoutine, &Event);

        KeWaitForSingleObject(&Event, Executive, KernelMode, TRUE, 0);


		if (!NT_SUCCESS(Status)) {

			DbgPrint("EptWriteEncryptHeader->NULL FltWriteFile failed. Status = %x\n", Status);
            if (NULL != Buffer)
            {
                ExFreePool(Buffer);
                Buffer = NULL;
            }
			return Status;
		}

        if (NULL != Buffer)
        {
            ExFreePool(Buffer);
            Buffer = NULL;
        }

        DbgPrint("EptWriteEncryptHeader->EOF=NULL FltWriteFile success.\n");

        return EPT_WRITE_ENCRYPT_HEADER;

	}
    else if((*Data)->Iopb->Parameters.Create.SecurityContext->DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA))
    {
        return EPT_TO_APPEND_ENCRYPT_HEADER;
    }

	return EPT_FINISHED_PROCESSING;
}


//手动打开文件，获得句柄
NTSTATUS FileCreateForHeaderWriting(IN PFLT_INSTANCE Instance, IN PUNICODE_STRING uFileName, OUT HANDLE* phFileHandle)
{

    OBJECT_ATTRIBUTES oaObjectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;

    NTSTATUS Status;


    InitializeObjectAttributes(
        &oaObjectAttributes,
        uFileName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);


    Status = FltCreateFile(
        gFilterHandle,
        Instance,
        phFileHandle,
        FILE_READ_DATA | FILE_WRITE_DATA,
        &oaObjectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN_IF,
        FILE_NON_DIRECTORY_FILE,
        NULL,
        0,
        IO_IGNORE_SHARE_ACCESS_CHECK);

    if (!NT_SUCCESS(Status))
    {
        DbgPrint("FileCreateForHeaderWriting->FltCreateFile failed Status = 0x%x.\n", Status);
        return Status;
    }

    return Status;
}


//对于已经被写过数据的文件，当有写入的倾向时，在PostCreate中记录文件相关数据，在PreClose中重新加入加密头
NTSTATUS EptAppendEncryptHeader(IN PCFLT_RELATED_OBJECTS FltObjects, IN OUT PEPT_STREAM_CONTEXT StreamContext)
{

    NTSTATUS Status;

    PFLT_VOLUME Volume;
    FLT_VOLUME_PROPERTIES VolumeProps;

    LARGE_INTEGER ByteOffset;
    ULONG ReadLength, LengthReturned, WriteLength, ErrorLength;

    HANDLE hFile = NULL;
    PFILE_OBJECT FileObject = { 0 };

    //这里因为是PreClose，文件已经关闭了，需要重新手动打开
    Status = FileCreateForHeaderWriting(FltObjects->Instance, &StreamContext->FileName, &hFile);

    if (!NT_SUCCESS(Status))
    {
        DbgPrint("EptAppendEncryptHeader->FileCreateForHeaderWriting failed. Status = %x\n", Status);
        return Status;
    }

    Status = ObReferenceObjectByHandle(hFile, STANDARD_RIGHTS_ALL, *IoFileObjectType, KernelMode, (PVOID*)&FileObject, NULL);

    //不知道为何，这里读出的数据 = 原始数据 + 原始数据 + 后写入的数据，所以用偏移把开头的原始数据去掉了
    ErrorLength = EptGetFileSize(FltObjects);

    //根据FltWriteFile， FltReadFile对于Length的要求，Length必须是扇区大小的整数倍
    Status = FltGetVolumeFromInstance(FltObjects->Instance, &Volume);

    if (!NT_SUCCESS(Status)) {

        DbgPrint("EptAppendEncryptHeader->FltGetVolumeFromInstance failed. Status = %x\n", Status);
        if (NULL != hFile)
        {
            FltClose(hFile);
            hFile = NULL;
        }
        return Status;
    }

    Status = FltGetVolumeProperties(Volume, &VolumeProps, sizeof(VolumeProps), &ReadLength);

    if (NULL != Volume)
    {
        FltObjectDereference(Volume);
        Volume = NULL;
    }

    PCHAR ReadBuffer, TempEncryptBuffer;

    ReadLength = ErrorLength - (LONG)StreamContext->FileSize;
    ReadLength = ROUND_TO_SIZE(ReadLength, VolumeProps.SectorSize);

    //为FltReadFile分配内存
    ReadBuffer = FltAllocatePoolAlignedWithTag(FltObjects->Instance, PagedPool, ReadLength, 'itRB');

    if (!ReadBuffer)
    {
        DbgPrint("EptAppendEncryptHeader->FltAllocatePoolAlignedWithTag ReadBuffer failed.\n");

        if (NULL != hFile)
        {
            FltClose(hFile);
            hFile = NULL;
        }
        return STATUS_UNSUCCESSFUL;
    }

    RtlZeroMemory(ReadBuffer, ReadLength);


    //将文件读入缓冲区
    ByteOffset.QuadPart = StreamContext->FileSize;      //去掉原始数据
    Status = FltReadFile(FltObjects->Instance, FileObject, &ByteOffset, (ULONG)ReadLength, (PVOID)ReadBuffer,
        FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET | FLTFL_IO_OPERATION_NON_CACHED, NULL, NULL, NULL);
    

    if (!NT_SUCCESS(Status)) 
    {
        //STATUS_PENDING
        DbgPrint("EptAppendEncryptHeader->Append FltReadFile failed. Status = %X.\n", Status);
        if (NULL != ReadBuffer)
        {
            FltFreePoolAlignedWithTag(FltObjects->Instance, ReadBuffer, 'itRB');
            ReadBuffer = NULL;
        }
        if (NULL != hFile)
        {
            FltClose(hFile);
            hFile = NULL;
        }
        return Status;
    }


    //获得加密后数据的大小
    if (!EptAesEncrypt(FltObjects, (PUCHAR)ReadBuffer, &LengthReturned, TRUE))
    {
        DbgPrint("EptAppendEncryptHeader->EptAesEncrypt get buffer encrypted size failed.\n");
        return FALSE;
    }

    WriteLength = LengthReturned + FILE_FLAG_SIZE;
    WriteLength = ROUND_TO_SIZE(WriteLength, VolumeProps.SectorSize);

    TempEncryptBuffer = FltAllocatePoolAlignedWithTag(FltObjects->Instance, PagedPool, WriteLength, 'itRB');

    if (!TempEncryptBuffer)
    {
        DbgPrint("EptAppendEncryptHeader->FltAllocatePoolAlignedWithTag TempEncryptBuffer failed.\n");

        if (NULL != ReadBuffer)
        {
            FltFreePoolAlignedWithTag(FltObjects->Instance, ReadBuffer, 'itRB');
            ReadBuffer = NULL;
        }

        if (NULL != hFile)
        {
            FltClose(hFile);
            hFile = NULL;
        }
        return STATUS_UNSUCCESSFUL;
    }

    RtlZeroMemory(TempEncryptBuffer, WriteLength);
    RtlMoveMemory(TempEncryptBuffer, FILE_FLAG, strlen(FILE_FLAG));
    RtlMoveMemory(TempEncryptBuffer + FILE_FLAG_SIZE, ReadBuffer, ReadLength);

    //加密整体的数据
    WriteLength -= FILE_FLAG_SIZE;
    if (!EptAesEncrypt(FltObjects, (PUCHAR)TempEncryptBuffer + FILE_FLAG_SIZE, &WriteLength, FALSE))
    {
        DbgPrint("EptAppendEncryptHeader->EptAesEncrypt encrypte buffer failed.\n");
    }

    //DbgPrint("EptAppendEncryptHeader->Encrypted content = %s.\n", TempEncryptBuffer + FILE_FLAG_SIZE);

    //修改文件大小，这个会在PostQueryInfo中修改EOF
    ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);
    StreamContext->FileSize = ErrorLength - (LONG)StreamContext->FileSize;
    ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);

    //为写入文件开辟大小
    FILE_END_OF_FILE_INFORMATION EOF = { 0 };
    EOF.EndOfFile.QuadPart = ErrorLength - (LONG)StreamContext->FileSize + FILE_FLAG_SIZE;
    Status = FltSetInformationFile(FltObjects->Instance, FileObject, &EOF, sizeof(FILE_END_OF_FILE_INFORMATION), FileEndOfFileInformation);

    //DbgPrint("filesize %d EOF %d\n", ErrorLength - (LONG)StreamContext->FileSize, EOF.EndOfFile.QuadPart);


    //写入带加密标记头的数据
    ByteOffset.QuadPart = 0;
    Status = FltWriteFile(FltObjects->Instance, FileObject, &ByteOffset, (ULONG)WriteLength + FILE_FLAG_SIZE, TempEncryptBuffer,
        FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, NULL, NULL, NULL);


    if (!NT_SUCCESS(Status)) {

        DbgPrint("EptAppendEncryptHeader->Append FltWriteFile failed. Status = %x\n", Status);

        if (NULL != ReadBuffer)
        {
            FltFreePoolAlignedWithTag(FltObjects->Instance, ReadBuffer, 'itRB');
            ReadBuffer = NULL;
        }

        if (NULL != TempEncryptBuffer)
        {
            FltFreePoolAlignedWithTag(FltObjects->Instance, TempEncryptBuffer, 'itRB');
            TempEncryptBuffer = NULL;
        }

        if (NULL != hFile)
        {
            FltClose(hFile);
            hFile = NULL;
        }
        return Status;
    }

    if (NULL != ReadBuffer)
    {
        FltFreePoolAlignedWithTag(FltObjects->Instance, ReadBuffer, 'itRB');
        ReadBuffer = NULL;
    }

    if (NULL != TempEncryptBuffer)
    {
        FltFreePoolAlignedWithTag(FltObjects->Instance, TempEncryptBuffer, 'itRB');
        TempEncryptBuffer = NULL;
    }

    if (NULL != hFile) 
    {
        FltClose(hFile);
        hFile = NULL;
    }

    DbgPrint("EptAppendEncryptHeader->Append FltWriteFile success.\n");

    return EPT_APPEND_ENCRYPT_HEADER;
}


//清除文件缓冲，https://github.com/SchineCompton/Antinvader
VOID EptFileCacheClear(IN PFILE_OBJECT pFileObject)
{
    // FCB
    PFSRTL_COMMON_FCB_HEADER pFcb;

    // 睡眠时间 用于KeDelayExecutionThread
    LARGE_INTEGER liInterval;

    // 是否需要释放资源
    BOOLEAN bNeedReleaseResource = FALSE;

    // 是否需要释放分页资源
    BOOLEAN bNeedReleasePagingIoResource = FALSE;

    // IRQL
    KIRQL irql;

    // 循环时是否跳出
    BOOLEAN bBreak = TRUE;

    // 是否资源被锁定
    BOOLEAN bLockedResource = FALSE;

    // 是否是分页资源被锁定
    BOOLEAN bLockedPagingIoResource = FALSE;

    // Resource 和 PagingIoResource 资源的锁的先后顺序
    BOOLEAN isPagingIoResourceLockedFirst = FALSE;

    //
    // 获取FCB
    //
    pFcb = (PFSRTL_COMMON_FCB_HEADER)pFileObject->FsContext;

    //
    // 如果没有FCB 直接返回
    //
    if (pFcb == NULL) {
        /*
        #ifdef DBG
                __asm int 3
        #endif*/
        return;
    }

    //
    // 保证当前IRQL <= APC_LEVEL
    //

    irql = KeGetCurrentIrql();

    if (irql > APC_LEVEL) {
#if defined(DBG) && !defined(_WIN64)
        __asm int 3
#endif
        return;
    }

    //
    // 设置睡眠时间
    //
    liInterval.QuadPart = -1 * (LONGLONG)50;

    //
    // 进入文件系统
    //
    FsRtlEnterFileSystem();

    isPagingIoResourceLockedFirst = FALSE;

    //
    // FILE_CLEAR_CACHE_USE_ORIGINAL_LOCK, 注意: 该宏定义在 AntinvaderDef.h 头文件里
    //
#if defined(FILE_CLEAR_CACHE_USE_ORIGINAL_LOCK) && (FILE_CLEAR_CACHE_USE_ORIGINAL_LOCK != 0)
    //
    // 循环拿锁, 一定要拿锁, 否则可能损坏数据.
    //
    for (;;) {
        //
        // 初始化参数
        //
        bBreak = TRUE;
        bNeedReleaseResource = FALSE;
        bNeedReleasePagingIoResource = FALSE;
        bLockedResource = FALSE;
        bLockedPagingIoResource = FALSE;

        //
        // 从FCB中拿锁
        //
        if (pFcb->PagingIoResource) {
            if (bLockedPagingIoResource == FALSE) {
                bLockedPagingIoResource = ExIsResourceAcquiredExclusiveLite(pFcb->PagingIoResource);
                if (bLockedPagingIoResource) {
                    if (bLockedResource == FALSE)
                        isPagingIoResourceLockedFirst = TRUE;
                    bNeedReleasePagingIoResource = TRUE;
                }
            }
        }

        //
        // 使劲拿, 必须拿, 一定拿.....
        //
        if (pFcb->Resource) {
            if (bLockedResource == FALSE) {
                //
                // 先尝试拿一下资源
                //
                if (ExIsResourceAcquiredExclusiveLite(pFcb->Resource) == FALSE) {
                    //
                    // 没拿到资源, 再来一次.
                    //
                    if (bLockedPagingIoResource) {
                        if (ExAcquireResourceExclusiveLite(pFcb->Resource, FALSE) == FALSE) {
                            bBreak = FALSE;
                            bLockedResource = FALSE;
                            bNeedReleaseResource = FALSE;
                        }
                        else {
                            bLockedResource = TRUE;
                            bNeedReleaseResource = TRUE;
                        }
                    }
                    else {
                        if (bLockedResource == FALSE) {
                            ExAcquireResourceExclusiveLite(pFcb->Resource, TRUE);
                            bLockedResource = TRUE;
                            bNeedReleaseResource = TRUE;
                            isPagingIoResourceLockedFirst = FALSE;
                        }
                    }
                }
                else {
                    bLockedResource = TRUE;
                    bNeedReleaseResource = TRUE;
                }
            }
        }

        if (pFcb->PagingIoResource) {
            if (bLockedPagingIoResource == FALSE) {
                //
                // 尝试拿 PagingIoResource 锁资源
                //
                if (bLockedResource) {
                    if (ExAcquireResourceExclusiveLite(pFcb->PagingIoResource, FALSE) == FALSE) {
                        bBreak = FALSE;
                        bLockedPagingIoResource = FALSE;
                        bNeedReleasePagingIoResource = FALSE;
                    }
                    else {
                        if (bLockedResource == FALSE)
                            isPagingIoResourceLockedFirst = TRUE;
                        bLockedPagingIoResource = TRUE;
                        bNeedReleasePagingIoResource = TRUE;
                    }
                }
                else {
                    if (bLockedPagingIoResource == FALSE) {
                        ExAcquireResourceExclusiveLite(pFcb->PagingIoResource, TRUE);
                        if (bLockedResource == FALSE)
                            isPagingIoResourceLockedFirst = TRUE;
                        bLockedPagingIoResource = TRUE;
                        bNeedReleasePagingIoResource = TRUE;
                    }
                }
            }
        }

        if (bLockedResource && bLockedPagingIoResource) {
            break;
        }

        if (bBreak) {
            break;
        }

#if defined(FILE_CLEAR_CACHE_USE_ORIGINAL_LOCK) && (FILE_CLEAR_CACHE_USE_ORIGINAL_LOCK != 0)
        if (isPagingIoResourceLockedFirst) {
            if (bNeedReleasePagingIoResource) {
                if (pFcb->PagingIoResource)
                    ExReleaseResourceLite(pFcb->PagingIoResource);
                bLockedPagingIoResource = FALSE;
                bNeedReleasePagingIoResource = FALSE;
            }
            if (bNeedReleaseResource) {
                if (pFcb->Resource)
                    ExReleaseResourceLite(pFcb->Resource);
                bLockedResource = TRUE;
                bNeedReleaseResource = TRUE;
            }
        }
        else {
            if (bNeedReleaseResource) {
                if (pFcb->Resource)
                    ExReleaseResourceLite(pFcb->Resource);
                bLockedResource = TRUE;
                bNeedReleaseResource = TRUE;
            }
            if (bNeedReleasePagingIoResource) {
                if (pFcb->PagingIoResource)
                    ExReleaseResourceLite(pFcb->PagingIoResource);
                bLockedPagingIoResource = FALSE;
                bNeedReleasePagingIoResource = FALSE;
            }
        }
        isPagingIoResourceLockedFirst = FALSE;
#endif

        /*
        if (irql == PASSIVE_LEVEL) {
//          FsRtlExitFileSystem();
            KeDelayExecutionThread(KernelMode, FALSE, &liInterval);
        }
        else {
            KEVENT waitEvent;
            KeInitializeEvent(&waitEvent, NotificationEvent, FALSE);
            KeWaitForSingleObject(&waitEvent, Executive, KernelMode, FALSE, &liInterval);
        }
        */
    }

#else // !FILE_CLEAR_CACHE_USE_ORIGINAL_LOCK

    if (pFcb->PagingIoResource) {
        ExAcquireResourceExclusiveLite(pFcb->PagingIoResource, TRUE);
        bLockedPagingIoResource = TRUE;
    }

#endif // FILE_CLEAR_CACHE_USE_ORIGINAL_LOCK

    //
    // 终于拿到锁了
    //
    if (pFileObject->SectionObjectPointer) {
        IO_STATUS_BLOCK ioStatus;
        IoSetTopLevelIrp((PIRP)FSRTL_FSP_TOP_LEVEL_IRP);
        CcFlushCache(pFileObject->SectionObjectPointer, NULL, 0, &ioStatus);

        if (pFileObject->SectionObjectPointer->ImageSectionObject) {
            MmFlushImageSection(pFileObject->SectionObjectPointer, MmFlushForWrite); // MmFlushForDelete()
        }

        CcPurgeCacheSection(pFileObject->SectionObjectPointer, NULL, 0, FALSE);
        IoSetTopLevelIrp(NULL);
    }

#if defined(FILE_CLEAR_CACHE_USE_ORIGINAL_LOCK) && (FILE_CLEAR_CACHE_USE_ORIGINAL_LOCK != 0)
    if (isPagingIoResourceLockedFirst) {
        if (bNeedReleasePagingIoResource) {
            if (pFcb->PagingIoResource)
                ExReleaseResourceLite(pFcb->PagingIoResource);
        }
        if (bNeedReleaseResource) {
            if (pFcb->Resource)
                ExReleaseResourceLite(pFcb->Resource);
        }
    }
    else {
        if (bNeedReleaseResource) {
            if (pFcb->Resource)
                ExReleaseResourceLite(pFcb->Resource);
        }
        if (bNeedReleasePagingIoResource) {
            if (pFcb->PagingIoResource)
                ExReleaseResourceLite(pFcb->PagingIoResource);
        }
    }
#else // !FILE_CLEAR_CACHE_USE_ORIGINAL_LOCK
    if (bLockedPagingIoResource == TRUE) {
        if (pFcb->PagingIoResource != NULL) {
            ExReleaseResourceLite(pFcb->PagingIoResource);
        }
        bLockedPagingIoResource = FALSE;
    }
#endif // FILE_CLEAR_CACHE_USE_ORIGINAL_LOCK

    FsRtlExitFileSystem();
    /*
    Acquire:
        FsRtlEnterFileSystem();

        if (Fcb->Resource)
            ResourceAcquired = ExAcquireResourceExclusiveLite(Fcb->Resource, TRUE);
        if (Fcb->PagingIoResource)
            PagingIoResourceAcquired = ExAcquireResourceExclusive(Fcb->PagingIoResource, FALSE);
        else
            PagingIoResourceAcquired = TRUE ;
        if (!PagingIoResourceAcquired) {
            if (Fcb->Resource)  ExReleaseResource(Fcb->Resource);
            FsRtlExitFileSystem();
            KeDelayExecutionThread(KernelMode,FALSE,&Delay50Milliseconds);
            goto Acquire;
        }

        if (FileObject->SectionObjectPointer) {
            IoSetTopLevelIrp( (PIRP)FSRTL_FSP_TOP_LEVEL_IRP);

            if (bIsFlushCache) {
                CcFlushCache( FileObject->SectionObjectPointer, FileOffset, Length, &IoStatus);
            }

            if (FileObject->SectionObjectPointer->ImageSectionObject) {
                MmFlushImageSection(
                    FileObject->SectionObjectPointer,
                    MmFlushForWrite);
            }

            if (FileObject->SectionObjectPointer->DataSectionObject) {
                PurgeRes = CcPurgeCacheSection(FileObject->SectionObjectPointer,
                    NULL,
                    0,
                    FALSE);
            }

            IoSetTopLevelIrp(NULL);
        }

        if (Fcb->PagingIoResource)
            ExReleaseResourceLite(Fcb->PagingIoResource);

        if (Fcb->Resource)
            ExReleaseResourceLite(Fcb->Resource);

        FsRtlExitFileSystem();
        */
}
