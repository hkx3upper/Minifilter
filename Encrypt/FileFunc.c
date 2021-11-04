#pragma warning(disable:4996)

#include "filefunc.h"
#include "commport.h"
#include "cryptography.h"


#define FILE_CLEAR_CACHE_USE_ORIGINAL_LOCK  1

//读取写入加密头时用，我也不太懂为啥要用事件做同步（这和我理解中事件用于多线程同步的方式不太一样），但不加，会出问题......
VOID EptReadWriteCallbackRoutine(IN PFLT_CALLBACK_DATA CallbackData, IN PFLT_CONTEXT Context)
{
    UNREFERENCED_PARAMETER(CallbackData);
    KeSetEvent((PRKEVENT)Context, IO_NO_INCREMENT, FALSE);
}


//获得文件大小，非重入
ULONG EptGetFileSize(IN PFLT_INSTANCE Instance, IN PFILE_OBJECT FileObject)
{

    FILE_STANDARD_INFORMATION StandardInfo = { 0 };
    ULONG LengthReturned;

    FltQueryInformationFile(Instance, FileObject, &StandardInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation, &LengthReturned);

    return (ULONG)StandardInfo.EndOfFile.QuadPart;
}


//设置文件大小，非重入
NTSTATUS EptSetFileEOF(IN PFLT_INSTANCE Instance, IN PFILE_OBJECT FileObject, LONGLONG FileSize)
{
    NTSTATUS Status;
    FILE_END_OF_FILE_INFORMATION EOF = { 0 };

    EOF.EndOfFile.QuadPart = FileSize;

    Status = FltSetInformationFile(Instance, FileObject, &EOF, sizeof(FILE_END_OF_FILE_INFORMATION), FileEndOfFileInformation);

    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("EptSetFileEOF->FltSetInformationFile failed status = 0x%x.", Status);
        return Status;
    }

    return STATUS_SUCCESS;
}


//获得卷的扇区大小
ULONG EptGetVolumeSectorSize(IN PFLT_INSTANCE Instance)
{
    NTSTATUS Status;
    PFLT_VOLUME Volume = { 0 };
    FLT_VOLUME_PROPERTIES VolumeProps = { 0 };
    ULONG LengthReturned = 0;

    Status = FltGetVolumeFromInstance(Instance, &Volume);

    if (!NT_SUCCESS(Status)) {

        DbgPrint("EptGetVolumeSectorSize->FltGetVolumeFromInstance failed. Status = %x\n", Status);
        goto EXIT;
    }

    Status = FltGetVolumeProperties(Volume, &VolumeProps, sizeof(VolumeProps), &LengthReturned);

    if (!NT_SUCCESS(Status))
    {
        //DbgPrint("EptGetVolumeSectorSize->FltGetVolumeProperties failed. Status = %x\n", Status);
        goto EXIT;
    }

EXIT:
    if (NULL != Volume)
    {
        FltObjectDereference(Volume);
        Volume = NULL;
    }

    return VolumeProps.SectorSize;
}


//判断是否为带有加密标记的文件
NTSTATUS EptIsTargetFile(IN PCFLT_RELATED_OBJECTS FltObjects) 
{
    ASSERT(FltObjects != NULL);

	NTSTATUS Status;
	PFLT_VOLUME Volume;
	FLT_VOLUME_PROPERTIES VolumeProps;

    KEVENT Event;

    PVOID ReadBuffer = NULL;
	LARGE_INTEGER ByteOffset = { 0 };
	ULONG Length;


	//根据FltReadFile对于Length的要求，Length必须是扇区大小的整数倍
	Status = FltGetVolumeFromInstance(FltObjects->Instance, &Volume);

	if (!NT_SUCCESS(Status)) {

		DbgPrint("EptIsTargetFile->FltGetVolumeFromInstance failed. Status = %x\n", Status);
        goto EXIT;
	}

	Status = FltGetVolumeProperties(Volume, &VolumeProps, sizeof(VolumeProps), &Length);

	if (NT_ERROR(Status)) 
    {
		DbgPrint("EptIsTargetFile->FltGetVolumeProperties failed. Status = %x\n", Status);
        goto EXIT;
	}

	//DbgPrint("VolumeProps.SectorSize = %d.\n", VolumeProps.SectorSize);

	Length = FILE_FLAG_SIZE;
	Length = ROUND_TO_SIZE(Length, VolumeProps.SectorSize);

	//为FltReadFile分配内存，之后在Buffer中查找Flag
	ReadBuffer = FltAllocatePoolAlignedWithTag(FltObjects->Instance, NonPagedPool, Length, 'itRB');

	if (!ReadBuffer) 
    {
		DbgPrint("EptIsTargetFile->FltAllocatePoolAlignedWithTag ReadBuffer failed.\n");
        goto EXIT;
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
		DbgPrint("EptIsTargetFile->FltReadFile failed. Status = %X.\n", Status);
		
        goto EXIT;

	}

	//DbgPrint("EptIsTargetFile Buffer = %p file content = %s.\n", ReadBuffer, (CHAR*)ReadBuffer);

	if (strncmp(FILE_FLAG, ReadBuffer, strlen(FILE_FLAG)) == 0) 
    {
		DbgPrint("EptIsTargetFile->TargetFile is match.\n");
		Status = EPT_ALREADY_HAVE_ENCRYPT_HEADER;
    }
    else
    {
        Status = EPT_DONT_HAVE_ENCRYPT_HEADER;
    }



EXIT:
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
	return Status;
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

		Buffer = FltAllocatePoolAlignedWithTag(FltObjects->Instance, NonPagedPool, Length, 'wiBF');
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
                FltFreePoolAlignedWithTag(FltObjects->Instance, Buffer, EPT_READ_BUFFER_FLAG);
                Buffer = NULL;
            }
			return Status;
		}

        if (NULL != Buffer)
        {
            FltFreePoolAlignedWithTag(FltObjects->Instance, Buffer, EPT_READ_BUFFER_FLAG);
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
NTSTATUS EptCreateFileForHeaderWriting(IN PFLT_INSTANCE Instance, IN PUNICODE_STRING uFileName, OUT HANDLE* phFileHandle)
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
        FILE_NON_DIRECTORY_FILE | FILE_NO_INTERMEDIATE_BUFFERING,
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


//文件路径磁盘转为DOS名 https://blog.csdn.net/zyorz/category_6871818.html
NTSTATUS EptQuerySymbolicLink(IN PUNICODE_STRING SymbolicLinkName, OUT PUNICODE_STRING LinkTarget)
//输入\\??\\c:-->\\device\\\harddiskvolume1
//LinkTarget.Buffer注意要释放
{
    OBJECT_ATTRIBUTES   oa = { 0 };
    NTSTATUS            status = 0;
    HANDLE              handle = NULL;

    InitializeObjectAttributes(
        &oa,
        SymbolicLinkName,
        OBJ_CASE_INSENSITIVE,
        0,
        0);

    status = ZwOpenSymbolicLinkObject(&handle, GENERIC_READ, &oa);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    LinkTarget->MaximumLength = 260 * sizeof(WCHAR);
    LinkTarget->Length = 0;
    LinkTarget->Buffer = ExAllocatePoolWithTag(PagedPool, LinkTarget->MaximumLength, 'SOD');
    if (!LinkTarget->Buffer)
    {
        ZwClose(handle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(LinkTarget->Buffer, LinkTarget->MaximumLength);

    status = ZwQuerySymbolicLinkObject(handle, LinkTarget, NULL);
    ZwClose(handle);

    if (!NT_SUCCESS(status))
    {
        ExFreePool(LinkTarget->Buffer);
    }

    return status;
}


//得到对应卷的实例 https://blog.csdn.net/feixi7358/article/details/85039734
PFLT_INSTANCE EptGetVolumeInstance(IN PFLT_FILTER pFilter, IN PUNICODE_STRING pVolumeName)
////获得文件所在盘的实例
//PFLT_INSTANCE fileInstance = NULL;
//UNICODE_STRING  pVolumeNamec;
//RtlInitUnicodeString(&pVolumeNamec, L"\\Device\\HarddiskVolume2");//所在的卷
//fileInstance = XBFltGetVolumeInstance(gFilterHandle, &pVolumeNamec);
{
    NTSTATUS		status;
    PFLT_INSTANCE	pInstance = NULL;
    PFLT_VOLUME		pVolumeList[100];
    ULONG			uRet;
    UNICODE_STRING	uniName = { 0 };
    ULONG 			index = 0;
    WCHAR			wszNameBuffer[260] = { 0 };

    status = FltEnumerateVolumes(pFilter,
        NULL,
        0,
        &uRet);
    if (status != STATUS_BUFFER_TOO_SMALL)
    {
        return NULL;
    }

    status = FltEnumerateVolumes(pFilter,
        pVolumeList,
        uRet,
        &uRet);

    if (!NT_SUCCESS(status))
    {

        return NULL;
    }
    uniName.Buffer = wszNameBuffer;

    if (uniName.Buffer == NULL)
    {
        for (index = 0; index < uRet; index++)
            FltObjectDereference(pVolumeList[index]);

        return NULL;
    }

    uniName.MaximumLength = sizeof(wszNameBuffer);

    for (index = 0; index < uRet; index++)
    {
        uniName.Length = 0;

        status = FltGetVolumeName(pVolumeList[index],
            &uniName,
            NULL);

        if (!NT_SUCCESS(status))
            continue;

        if (RtlCompareUnicodeString(&uniName,
            pVolumeName,
            TRUE) != 0)
            continue;

        status = FltGetVolumeInstanceFromName(pFilter,
            pVolumeList[index],
            NULL,
            &pInstance);

        if (NT_SUCCESS(status))
        {
            FltObjectDereference(pInstance);
            break;
        }
    }

    for (index = 0; index < uRet; index++)
        FltObjectDereference(pVolumeList[index]);
    return pInstance;
}


//特权解密命令对应的执行函数，负责除去加密头，解密数据，修改StreamContext
NTSTATUS EptRemoveEncryptHeaderAndDecrypt(PWCHAR FileName)
{

    NTSTATUS Status;

    UNICODE_STRING uFileName = { 0 };
    HANDLE hFile = NULL;
    PFILE_OBJECT FileObject = { 0 };

    PWCHAR lpFileName = FileName;
    WCHAR wSymbolLinkName[260] = { 0 };
    UNICODE_STRING uSymbolLinkName = { 0 };
    UNICODE_STRING uDosName = { 0 };

    PFLT_INSTANCE Instance = { 0 };
    ULONG FileSize = 0, SectorSize = 0, ReadLength = 0;

    PCHAR ReadBuffer = NULL, EncryptHeader = NULL;
    LARGE_INTEGER ByteOffset;

    PEPT_STREAM_CONTEXT StreamContext = NULL;

    RtlInitUnicodeString(&uFileName, FileName);

    //DbgPrint("EptRemoveEncryptHeaderAndDecrypt->Test FileName = %wZ.\n", uFileName);

    //打开文件，获得hFile，得到FileObject，给FltReadFile/FltWriteFile用
    Status = EptCreateFileForHeaderWriting(NULL, &uFileName, &hFile);

    if (!NT_SUCCESS(Status))
    {
        DbgPrint("EptRemoveEncryptHeaderAndDecrypt->FileCreateForHeaderWriting failed ststus = 0x%x.\n", Status);
        goto EXIT;
    }

    Status = ObReferenceObjectByHandle(hFile, STANDARD_RIGHTS_ALL, *IoFileObjectType, KernelMode, (PVOID*)&FileObject, NULL);

    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("EptRemoveEncryptHeaderAndDecrypt->ObReferenceObjectByHandle failed ststus = 0x%x.\n", Status);
        goto EXIT;
    }


    //由文件的符号链接，找到对应磁盘的DOS名，找到磁盘的Instance
    while (*lpFileName != L':')
    {
        lpFileName++;
    }

    //wSymbolLinkName = L"\\??\\C:"
    RtlMoveMemory(wSymbolLinkName, FileName, (lpFileName - FileName + 1) * sizeof(WCHAR));

    RtlInitUnicodeString(&uSymbolLinkName, wSymbolLinkName);

    Status = EptQuerySymbolicLink(&uSymbolLinkName, &uDosName);

    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("EptRemoveEncryptHeaderAndDecrypt->EptQuerySymbolicLink failed ststus = 0x%x.\n", Status);
        goto EXIT;
    }

    Instance = EptGetVolumeInstance(gFilterHandle, &uDosName);

    if (NULL == Instance)
    {
        DbgPrint("EptRemoveEncryptHeaderAndDecrypt->EptGetVolumeInstance failed.\n");
        goto EXIT;
    }


    //判断是否有加密头
    EncryptHeader = FltAllocatePoolAlignedWithTag(Instance, NonPagedPool, FILE_FLAG_SIZE, EPT_READ_BUFFER_FLAG);

    if (NULL == EncryptHeader)
    {
        DbgPrint("EptRemoveEncryptHeaderAndDecrypt->FltAllocatePoolAlignedWithTag EncryptHeader failed.\n");
        goto EXIT;
    }

    RtlZeroMemory(EncryptHeader, FILE_FLAG_SIZE);

    ByteOffset.QuadPart = 0;
    Status = FltReadFile(Instance, FileObject, &ByteOffset, (ULONG)FILE_FLAG_SIZE, (PVOID)EncryptHeader,
        FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET | FLTFL_IO_OPERATION_NON_CACHED, NULL, NULL, NULL);

    if (!NT_SUCCESS(Status))
    {
        //STATUS_SUCCESS
        DbgPrint("EptRemoveEncryptHeaderAndDecrypt->FltReadFile read encryptheader failed. Status = %X.\n", Status);
        goto EXIT;
    }

    if (strncmp(EncryptHeader, FILE_FLAG, strlen(FILE_FLAG)) != 0)
    {
        DbgPrint("EptRemoveEncryptHeaderAndDecrypt->%ws is an unencrypted file.\n", FileName);
        goto EXIT;
    }


    //这里的文件大小是加密头0x1000+密文对齐后的大小
    FileSize = EptGetFileSize(Instance, FileObject);
    SectorSize = EptGetVolumeSectorSize(Instance);

    ReadLength = ROUND_TO_SIZE(FileSize - FILE_FLAG_SIZE, SectorSize);

    ReadBuffer = FltAllocatePoolAlignedWithTag(Instance, NonPagedPool, ReadLength, EPT_READ_BUFFER_FLAG);

    if (NULL == ReadBuffer)
    {
        DbgPrint("EptRemoveEncryptHeaderAndDecrypt->FltAllocatePoolAlignedWithTag ReadBuffer failed.\n");
        goto EXIT;
    }

    RtlZeroMemory(ReadBuffer, ReadLength);

    //将密文读入缓冲区
    ByteOffset.QuadPart = FILE_FLAG_SIZE;      //去掉加密头
    Status = FltReadFile(Instance, FileObject, &ByteOffset, (ULONG)ReadLength, (PVOID)ReadBuffer,
        FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET | FLTFL_IO_OPERATION_NON_CACHED, NULL, NULL, NULL);

    if (!NT_SUCCESS(Status))
    {
        DbgPrint("EptRemoveEncryptHeaderAndDecrypt->FltReadFile failed. Status = %X.\n", Status);
        goto EXIT;
    }

    //解密
    Status = EptAesDecrypt((PUCHAR)ReadBuffer, FileSize - FILE_FLAG_SIZE);

    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("EptRemoveEncryptHeaderAndDecrypt->EptAesDecrypt failed. Status = %X.\n", Status);
        goto EXIT;
    }

    //设置去掉加密文件头的大小
    Status = EptSetFileEOF(Instance, FileObject, strlen(ReadBuffer));

    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("EptRemoveEncryptHeaderAndDecrypt->EptSetFileEOF failed. Status = %X.\n", Status);
        goto EXIT;
    }

    //写入原始明文
    ByteOffset.QuadPart = 0;
    Status = FltWriteFile(Instance, FileObject, &ByteOffset, (ULONG)strlen(ReadBuffer), ReadBuffer,
        FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, NULL, NULL, NULL);

    if (!NT_SUCCESS(Status))
    {
        //写入失败，恢复EOF
        EptSetFileEOF(Instance, FileObject, FileSize);
        DbgPrint("EptRemoveEncryptHeaderAndDecrypt->FltWriteFile failed. Status = %X.\n", Status);
        goto EXIT;
    }

    if (!EptCreateContext(&StreamContext, FLT_STREAM_CONTEXT)) 
    {
        EptSetFileEOF(Instance, FileObject, FileSize);
        DbgPrint("EptRemoveEncryptHeaderAndDecrypt->EptCreateContext failed.");
        goto EXIT;
    }

    if (!EptGetOrSetContext(Instance, FileObject, &StreamContext, FLT_STREAM_CONTEXT))
    {
        EptSetFileEOF(Instance, FileObject, FileSize);
        DbgPrint("EptRemoveEncryptHeaderAndDecrypt->EptGetOrSetContext failed.");
        goto EXIT;
    }

    ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);
    StreamContext->FlagExist = 0;
    ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);

    //一定要FlushCache
    EptFileCacheClear(FileObject);

    DbgPrint("EptRemoveEncryptHeaderAndDecrypt->success origfile = %s\n", ReadBuffer);

    Status = STATUS_SUCCESS;

EXIT:
    if (NULL != FileObject)
    {
        ObDereferenceObject(FileObject);
        FileObject = NULL;
    }

    if (NULL != hFile)
    {
        FltClose(hFile);
        hFile = NULL;
    }

    if (NULL != uDosName.Buffer)
    {
        ExFreePool(uDosName.Buffer);
        uDosName.Buffer = NULL;
    }

    if (NULL != ReadBuffer)
    {
        FltFreePoolAlignedWithTag(Instance, ReadBuffer, EPT_READ_BUFFER_FLAG);
        ReadBuffer = NULL;
    }

    if (NULL != EncryptHeader)
    {
        FltFreePoolAlignedWithTag(Instance, EncryptHeader, EPT_READ_BUFFER_FLAG);
        EncryptHeader = NULL;
    }

    if (NULL != StreamContext)
    {
        FltReleaseContext(StreamContext);
        StreamContext = NULL;
    }

    return Status;
}


//特权加密命令，给目标文件加上机密头，加密数据，修改StreamContext
NTSTATUS EptAppendEncryptHeaderAndEncryptEx(PWCHAR FileName)
{
    NTSTATUS Status;

    UNICODE_STRING uFileName = { 0 };
    HANDLE hFile = NULL;
    PFILE_OBJECT FileObject = { 0 };

    PWCHAR lpFileName = FileName;
    WCHAR wSymbolLinkName[260] = { 0 };
    UNICODE_STRING uSymbolLinkName = { 0 };
    UNICODE_STRING uDosName = { 0 };

    PFLT_INSTANCE Instance = { 0 };
    ULONG FileSize = 0, SectorSize = 0, ReadLength = 0, EncryptedLength = 0;

    PCHAR ReadBuffer = NULL, EncryptedBuffer = NULL;
    LARGE_INTEGER ByteOffset;

    PEPT_STREAM_CONTEXT StreamContext = NULL;

    RtlInitUnicodeString(&uFileName, FileName);

    //DbgPrint("EptRemoveEncryptHeaderAndDecrypt->Test FileName = %wZ.\n", uFileName);

    //打开文件，获得hFile，得到FileObject，给FltReadFile/FltWriteFile用
    //L"\\??\\C:\\Desktop\\a.txt"
    Status = EptCreateFileForHeaderWriting(NULL, &uFileName, &hFile);

    if (!NT_SUCCESS(Status))
    {
        DbgPrint("EptAppendEncryptHeaderAndEncryptEx->FileCreateForHeaderWriting failed ststus = 0x%x.\n", Status);
        goto EXIT;
    }

    Status = ObReferenceObjectByHandle(hFile, STANDARD_RIGHTS_ALL, *IoFileObjectType, KernelMode, (PVOID*)&FileObject, NULL);

    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("EptAppendEncryptHeaderAndEncryptEx->ObReferenceObjectByHandle failed ststus = 0x%x.\n", Status);
        goto EXIT;
    }


    //由文件的符号链接，找到对应磁盘的DOS名，找到磁盘的Instance
    while (*lpFileName != L':')
    {
        lpFileName++;
    }

    //wSymbolLinkName = L"\\??\\C:"
    RtlMoveMemory(wSymbolLinkName, FileName, (lpFileName - FileName + 1) * sizeof(WCHAR));

    RtlInitUnicodeString(&uSymbolLinkName, wSymbolLinkName);

    Status = EptQuerySymbolicLink(&uSymbolLinkName, &uDosName);

    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("EptAppendEncryptHeaderAndEncryptEx->EptQuerySymbolicLink failed ststus = 0x%x.\n", Status);
        goto EXIT;
    }

    Instance = EptGetVolumeInstance(gFilterHandle, &uDosName);

    if (NULL == Instance)
    {
        DbgPrint("EptAppendEncryptHeaderAndEncryptEx->EptGetVolumeInstance failed.\n");
        goto EXIT;
    }

    FileSize = EptGetFileSize(Instance, FileObject);
    SectorSize = EptGetVolumeSectorSize(Instance);

    ReadLength = ROUND_TO_SIZE(FileSize, SectorSize);

    //对于空文件，要做特殊处理，否则ReadBuffer有脏数据
    if (0 == ReadLength)
    {
        ReadLength += 16;
    }

    ReadBuffer = FltAllocatePoolAlignedWithTag(Instance, NonPagedPool, ReadLength, EPT_READ_BUFFER_FLAG);

    if (NULL == ReadBuffer)
    {
        DbgPrint("EptAppendEncryptHeaderAndEncryptEx->FltAllocatePoolAlignedWithTag ReadBuffer failed.\n");
        goto EXIT;
    }

    RtlZeroMemory(ReadBuffer, ReadLength);

    if (16 == ReadLength && FileSize == 0)
    {
        ReadLength -= 16;
    }

    //将文件读入缓冲区
    ByteOffset.QuadPart = 0;
    Status = FltReadFile(Instance, FileObject, &ByteOffset, (ULONG)ReadLength, (PVOID)ReadBuffer,
        FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET | FLTFL_IO_OPERATION_NON_CACHED, NULL, NULL, NULL);

    if (!NT_SUCCESS(Status))
    {   
        //STATUS_SUCCESS
        DbgPrint("EptAppendEncryptHeaderAndEncryptEx->FltReadFile failed. Status = %X.\n", Status);
        goto EXIT;
    }

    if (strncmp(FILE_FLAG, ReadBuffer, strlen(FILE_FLAG)) == 0)
    {
        DbgPrint("EptAppendEncryptHeaderAndEncryptEx->File has been already encrypted.\n");
        goto EXIT;
    }


    //获取加密后数据的大小
    if (!EptAesEncrypt((PUCHAR)ReadBuffer, &EncryptedLength, TRUE))
    {
        DbgPrint("EptAppendEncryptHeaderAndEncryptEx->EptAesEncrypt count size failed.\n");
        goto EXIT;
    }

    EncryptedBuffer = FltAllocatePoolAlignedWithTag(Instance, NonPagedPool, (LONGLONG)EncryptedLength + FILE_FLAG_SIZE, EPT_READ_BUFFER_FLAG);

    if (NULL == EncryptedBuffer)
    {
        DbgPrint("EptAppendEncryptHeaderAndEncryptEx->FltAllocatePoolAlignedWithTag EncryptedBuffer failed.\n");
        goto EXIT;
    }

    RtlZeroMemory(EncryptedBuffer, (LONGLONG)EncryptedLength + FILE_FLAG_SIZE);

    RtlMoveMemory(EncryptedBuffer + FILE_FLAG_SIZE, ReadBuffer, strlen(ReadBuffer));

    if (!EptAesEncrypt((PUCHAR)EncryptedBuffer + FILE_FLAG_SIZE, &EncryptedLength, FALSE))
    {
        DbgPrint("EptAppendEncryptHeaderAndEncryptEx->EptAesEncrypt encrypte buffer failed.\n");
        goto EXIT;
    }

    RtlMoveMemory(EncryptedBuffer, FILE_FLAG, strlen(FILE_FLAG));
    
    DbgPrint("EncryptedLength = %d FileSize = %d.\n", EncryptedLength, FileSize);

    //设置加上加密文件头的文件大小
    Status = EptSetFileEOF(Instance, FileObject, (LONGLONG)EncryptedLength + FILE_FLAG_SIZE);

    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("EptAppendEncryptHeaderAndEncryptEx->EptSetFileEOF failed. Status = %X.\n", Status);
        goto EXIT;
    }

    //写入加密文件头和密文
    ByteOffset.QuadPart = 0;
    Status = FltWriteFile(Instance, FileObject, &ByteOffset, (ULONG)EncryptedLength + FILE_FLAG_SIZE, EncryptedBuffer,
        FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, NULL, NULL, NULL);

    if (!NT_SUCCESS(Status))
    {
        //写入失败，恢复EOF
        EptSetFileEOF(Instance, FileObject, FileSize);
        DbgPrint("EptAppendEncryptHeaderAndEncryptEx->FltWriteFile failed. Status = %X.\n", Status);
        goto EXIT;
    }

    if (!EptCreateContext(&StreamContext, FLT_STREAM_CONTEXT))
    {
        EptSetFileEOF(Instance, FileObject, FileSize);
        DbgPrint("EptAppendEncryptHeaderAndEncryptEx->EptCreateContext failed.");
        goto EXIT;
    }

    if (!EptGetOrSetContext(Instance, FileObject, &StreamContext, FLT_STREAM_CONTEXT))
    {
        EptSetFileEOF(Instance, FileObject, FileSize);
        DbgPrint("EptAppendEncryptHeaderAndEncryptEx->EptGetOrSetContext failed.");
        goto EXIT;
    }

    ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);
    StreamContext->FlagExist = EPT_ENCRYPT_FLAG_EXIST;
    StreamContext->FileSize = FileSize;
    StreamContext->AppendHeader = EPT_APPEND_ENCRYPT_HEADER;
    ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);

    //一定要FlushCache
    EptFileCacheClear(FileObject);

    DbgPrint("EptAppendEncryptHeaderAndEncryptEx->success origfile = %s\n", ReadBuffer);

    Status = STATUS_SUCCESS;

EXIT:
    if (NULL != FileObject)
    {
        ObDereferenceObject(FileObject);
        FileObject = NULL;
    }

    if (NULL != hFile)
    {
        FltClose(hFile);
        hFile = NULL;
    }

    if (NULL != uDosName.Buffer)
    {
        ExFreePool(uDosName.Buffer);
        uDosName.Buffer = NULL;
    }

    if (NULL != ReadBuffer)
    {
        FltFreePoolAlignedWithTag(Instance, ReadBuffer, EPT_READ_BUFFER_FLAG);
        ReadBuffer = NULL;
    }

    if (NULL != EncryptedBuffer)
    {
        FltFreePoolAlignedWithTag(Instance, EncryptedBuffer, EPT_READ_BUFFER_FLAG);
        EncryptedBuffer = NULL;
    }

    if (NULL != StreamContext)
    {
        FltReleaseContext(StreamContext);
        StreamContext = NULL;
    }

    return Status;
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
