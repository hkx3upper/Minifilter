#pragma warning(disable:4996)

#include "common.h"
#include "commport.h"

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


//获取请求的进程名
//ie浏览器会导致UNEXPECTED KERNEL MODE TRAP?
//所以在PreCreate先过滤扩展名，尽量避免trap
//或者以后可以使用遍历EPROCESS，获得进程名
BOOLEAN EptGetProcessName(PFLT_CALLBACK_DATA Data, PUNICODE_STRING ProcessName) {

	NTSTATUS Status;
	PEPROCESS eProcess;
	HANDLE hProcess;

	PAGED_CODE();

	if (!pEptQueryInformationProcess) {
		
		DbgPrint("pEptQueryInformationProcess = %p.\n", pEptQueryInformationProcess);
		return FALSE;
	}

	eProcess = FltGetRequestorProcess(Data);

	if (!eProcess) {

		DbgPrint("EProcess FltGetRequestorProcess failed.\n.");
		return FALSE;
	}

	Status = ObOpenObjectByPointer(eProcess, OBJ_KERNEL_HANDLE, NULL, 0, 0, KernelMode, &hProcess);

	if (NT_SUCCESS(Status)) {

		Status = pEptQueryInformationProcess(hProcess, ProcessImageFileName, ProcessName, ProcessName->MaximumLength, NULL);

		if (NT_SUCCESS(Status)) {

			//DbgPrint("DfGetProcessName = %ws, Length = %d.\n", ProcessName->Buffer, ProcessName->Length);
			ZwClose(hProcess);
			return TRUE;
		}
		else if (Status == STATUS_INFO_LENGTH_MISMATCH) {

			DbgPrint("pDfQueryInformationProcess buffer too small.\n");
		}

		ZwClose(hProcess);
	}

	return FALSE;

}


//判断是否为加密进程
BOOLEAN EptIsTargetProcess(PFLT_CALLBACK_DATA Data) {

	PAGED_CODE();

	NTSTATUS Status; 
	char Buffer[PAGE_SIZE * sizeof(WCHAR) + sizeof(UNICODE_STRING)], Temp[260];
	RtlZeroMemory(Buffer, sizeof(Buffer));
	RtlZeroMemory(Temp, sizeof(Temp));

	PUNICODE_STRING ProcessName = (PUNICODE_STRING)Buffer;
	ProcessName->Buffer = (WCHAR*)(Buffer + sizeof(UNICODE_STRING));
	ProcessName->Length = 0;
	ProcessName->MaximumLength = PAGE_SIZE;

	ANSI_STRING AnisProcessName;
	CHAR* p;	

	if (!EptGetProcessName(Data, ProcessName)) {

		DbgPrint("EptGetProcessName failed.\n");
		return FALSE;
	}


	//TRUE为AnsiProcessName分配内存
	Status = RtlUnicodeStringToAnsiString(&AnisProcessName, ProcessName, TRUE);

	if (!NT_SUCCESS(Status)) {

		DbgPrint("AnisProcessName RtlUnicodeStringToAnsiString failed.\n");
		return FALSE;
	}


	//找到进程名
	p = AnisProcessName.Buffer + AnisProcessName.Length;

	while (*p != '\\' && p > AnisProcessName.Buffer)
	{
		p--;
	}

	if (p != AnisProcessName.Buffer)
		p++;

	//DbgPrint("ProcessName = %s.\n", p);


	//大写便于比较
	RtlMoveMemory(Temp, ProcessRules.TargetProcessName, strlen(ProcessRules.TargetProcessName));

	RtlMoveMemory(AnisProcessName.Buffer, _strupr(AnisProcessName.Buffer), strlen(AnisProcessName.Buffer));
	RtlMoveMemory(Temp, _strupr(Temp), strlen(Temp));

	if (strcmp(p, Temp) == 0) {

		RtlFreeAnsiString(&AnisProcessName);
		return TRUE;
	}

	RtlFreeAnsiString(&AnisProcessName);

	return FALSE;

}


//判断文件扩展名
BOOLEAN EptIsTargetExtension(PFLT_CALLBACK_DATA Data) {

	NTSTATUS Status;
	PFLT_FILE_NAME_INFORMATION FileNameInfo;

    char* lpExtension = ProcessRules.TargetExtension;
    int count = 0;
    char TempExtension[10];
    ANSI_STRING AnsiTempExtension;
    UNICODE_STRING Extension;


	//判断文件后缀，避免进程本身需要的操作被拦截
	Status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &FileNameInfo);

	if (!NT_SUCCESS(Status)) {

		//DbgPrint("EptIsTargetExtension FltGetFileNameInformation failed.\n");
		return FALSE;
	}

	FltParseFileNameInformation(FileNameInfo);


    for (int i = 0; i < ProcessRules.count; i++)
    {
        memset(TempExtension, 0, sizeof(TempExtension));
        count = 0;

        while (strncmp(lpExtension, ",", 1))
        {
            TempExtension[count++] = *lpExtension;
            //DbgPrint("lpExtension = %s.\n", lpExtension);
            lpExtension++;
        }

        //DbgPrint("TempExtension = %s.\n", TempExtension);

        RtlInitAnsiString(&AnsiTempExtension, TempExtension);
        AnsiTempExtension.MaximumLength = sizeof(TempExtension);

        if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&Extension, &AnsiTempExtension, TRUE)))
        {
            if (RtlEqualUnicodeString(&FileNameInfo->Extension, &Extension, TRUE))
            {
                FltReleaseFileNameInformation(FileNameInfo);
                RtlFreeUnicodeString(&Extension);
                //DbgPrint("EptIsTargetExtension hit.\n");
                return TRUE;
            }

            RtlFreeUnicodeString(&Extension);
        }

        //跳过逗号
        lpExtension++;
    }
    

	FltReleaseFileNameInformation(FileNameInfo);
	return FALSE;
}


VOID EptReadWriteCallbackRoutine(
    PFLT_CALLBACK_DATA CallbackData,
    PFLT_CONTEXT Context
)
{
    UNREFERENCED_PARAMETER(CallbackData);
    KeSetEvent((PRKEVENT)Context, 0, FALSE);
}


//判断是否为带有加密标记的文件
BOOLEAN EptIsTargetFile(PCFLT_RELATED_OBJECTS FltObjects) {

	NTSTATUS Status;
	PFLT_VOLUME Volume;
	FLT_VOLUME_PROPERTIES VolumeProps;

    KEVENT Event;

	PVOID ReadBuffer;
	LARGE_INTEGER ByteOffset = { 0 };
	ULONG BytesRead, Length;

	//根据FltReadFile对于Length的要求，Length必须是扇区大小的整数倍
	Status = FltGetVolumeFromInstance(FltObjects->Instance, &Volume);

	if (!NT_SUCCESS(Status)) {

		DbgPrint("EptIsTargetFile FltGetVolumeFromInstance failed.\n");
		return FALSE;
	}

	Status = FltGetVolumeProperties(Volume, &VolumeProps, sizeof(VolumeProps), &Length);

	/*if (NT_ERROR(Status)) {

		FltObjectDereference(Volume);
		DbgPrint("DEptIsTargetFile FltGetVolumeProperties failed.\n");
		return FALSE;
	}*/

	//DbgPrint("VolumeProps.SectorSize = %d.\n", VolumeProps.SectorSize);

	Length = FILE_FLAG_SIZE;
	Length = ROUND_TO_SIZE(Length, VolumeProps.SectorSize);


	//为FltReadFile分配内存，之后在Buffer中查找Flag
	ReadBuffer = FltAllocatePoolAlignedWithTag(FltObjects->Instance, NonPagedPool, Length, 'itRB');

	if (!ReadBuffer) {

		FltObjectDereference(Volume);
		DbgPrint("EptIsTargetFile ExAllocatePool failed.\n");
		return FALSE;
	}

	RtlZeroMemory(ReadBuffer, Length);


    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

	//将文件读入缓冲区，关闭文件时会发生读取不全，但不影响驱动功能，还是加上KeWaitForSingleObject
    ByteOffset.QuadPart = BytesRead = 0;
    Status = FltReadFile(FltObjects->Instance, FltObjects->FileObject, &ByteOffset, Length, ReadBuffer,
        FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, &BytesRead, EptReadWriteCallbackRoutine, &Event);

    KeWaitForSingleObject(&Event, Executive, KernelMode, TRUE, 0);

	if (!NT_SUCCESS(Status) || (BytesRead == 0)) {

		//DbgPrint("EptIsTargetFile FltReadFile failed. Status = %d BytesRead = %d.\n", Status, BytesRead);
		FltObjectDereference(Volume);
		FltFreePoolAlignedWithTag(FltObjects->Instance, ReadBuffer, 'itRB');
		return FALSE;

	}

	DbgPrint("EptIsTargetFile Buffer = %p file content = %s.\n", ReadBuffer, (CHAR*)ReadBuffer);

	if (strncmp(FILE_FLAG, ReadBuffer, strlen(FILE_FLAG)) == 0) {

		FltObjectDereference(Volume);
		FltFreePoolAlignedWithTag(FltObjects->Instance, ReadBuffer, 'itRB');
		DbgPrint("EptIsTargetFile hit. TargetFile is match.\n");
		return TRUE;
	}

	FltObjectDereference(Volume);
	FltFreePoolAlignedWithTag(FltObjects->Instance, ReadBuffer, 'itRB');
	return FALSE;
}


//如果是新建的文件，且有写入数据的倾向，写入加密标记头
BOOLEAN EptWriteFileHeader(PFLT_CALLBACK_DATA* Data, PCFLT_RELATED_OBJECTS FltObjects) {

	NTSTATUS Status;
	FILE_STANDARD_INFORMATION StandardInfo;
	FILE_END_OF_FILE_INFORMATION FileEOFInfo;

	PFLT_VOLUME Volume;
	FLT_VOLUME_PROPERTIES VolumeProps;

    KEVENT Event;

	PVOID Buffer;
	LARGE_INTEGER ByteOffset;
	ULONG Length, BytesWritten, LengthReturned;

	FILE_POSITION_INFORMATION FilePositionInfo = { 0 };

	//查询文件大小
	Status = FltQueryInformationFile(FltObjects->Instance, FltObjects->FileObject, &StandardInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation, &LengthReturned);

	if (!NT_SUCCESS(Status) || Status == STATUS_VOLUME_DISMOUNTED) {

		DbgPrint("EptWriteFileHeader FltQueryInformationFile failed.\n");
		return FALSE;
	}

	//DbgPrint("LengthReturned = %d FileEOFInfo = %I64d.\n", LengthReturned, StandardInfo.EndOfFile.QuadPart);

	//分配文件头FILE_FLAG_SIZE大小，写入文件flag
	if (StandardInfo.EndOfFile.QuadPart == 0
		&& ((*Data)->Iopb->Parameters.Create.SecurityContext->DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA))) {

		FileEOFInfo.EndOfFile.QuadPart = FILE_FLAG_SIZE;
		Status = FltSetInformationFile(FltObjects->Instance, FltObjects->FileObject, &FileEOFInfo, sizeof(FILE_END_OF_FILE_INFORMATION), FileEndOfFileInformation);

		if (!NT_SUCCESS(Status)) {

			DbgPrint("EptWriteFileHeader FltSetInformationFile failed.\n");
			return FALSE;
		}
		
		//根据FltWriteFile对于Length的要求，Length必须是扇区大小的整数倍
		Status = FltGetVolumeFromInstance(FltObjects->Instance, &Volume);

		if (!NT_SUCCESS(Status)) {

			DbgPrint("EptWriteFileHeader FltGetVolumeFromInstance failed.\n");
			return FALSE;
		}

		Status = FltGetVolumeProperties(Volume, &VolumeProps, sizeof(VolumeProps), &Length);

		Length = max(sizeof(FILE_FLAG), FILE_FLAG_SIZE);
		Length = ROUND_TO_SIZE(Length, VolumeProps.SectorSize);

		FltObjectDereference(Volume);

		Buffer = ExAllocatePoolWithTag(NonPagedPool, Length, 'wiBF');
		if (!Buffer) {

			DbgPrint("EptWriteFileHeader ExAllocatePoolWithTag failed.\n");
			return FALSE;
		}

		RtlZeroMemory(Buffer, Length);

		if (Length >= sizeof(FILE_FLAG))
			RtlMoveMemory(Buffer, FILE_FLAG, sizeof(FILE_FLAG));



        KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

		//写入加密标记头
		ByteOffset.QuadPart = BytesWritten = 0;
		Status = FltWriteFile(FltObjects->Instance, FltObjects->FileObject, &ByteOffset, Length, Buffer,
			FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, &BytesWritten, EptReadWriteCallbackRoutine, &Event);

        KeWaitForSingleObject(&Event, Executive, KernelMode, TRUE, 0);

        DbgPrint("EptWriteFileHeader hit. Write a header into file BytesWritten = %d.\n", BytesWritten);

		if (!NT_SUCCESS(Status)) {

			DbgPrint("EptWriteFileHeader FltWriteFile failed.\n");
			ExFreePool(Buffer);
			return FALSE;
		}

        ExFreePool(Buffer);

        EptFileCacheClear(FltObjects->FileObject);

		//修改文件指针偏移
		FilePositionInfo.CurrentByteOffset.QuadPart = 0;
		Status = FltSetInformationFile(FltObjects->Instance, FltObjects->FileObject, &FilePositionInfo, sizeof(FILE_POSITION_INFORMATION), FilePositionInformation);

		return TRUE;
	}

	return FALSE;
}


//清除文件缓冲，https://github.com/SchineCompton/Antinvader
VOID EptFileCacheClear(PFILE_OBJECT pFileObject)
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