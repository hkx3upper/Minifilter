# Minifilter
参考《Windows内核安全与驱动开发》的加密解密Minifilter

运行环境：
Windows 10 x64
Visual Studio 2019

因为书中是基于传统文件过滤驱动的，用在Minifilter中有很多的出入，因此参考了很多相关的项目，谢谢
https://github.com/microsoft/Windows-driver-samples/tree/master/filesys/miniFilter/swapBuffers
https://github.com/minglinchen/WinKernelDev/tree/master/crypt_file
https://github.com/SchineCompton/Antinvader
https://github.com/shines77/Antinvader2015
https://github.com/comor86/MyMiniEncrypt
https://github.com/xiao70/X70FSD

暂时实现了简单的异或加密解密；写入，识别，对记事本隐藏加密文件头
接下来将会使用比较复杂的加密解密算法，考虑文件缓冲方面的问题


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

以下是主要的步骤：

//按照逐步搭建最小化系统的原则，先根据微软Sample的SwapBuffers实现简单的加密，解密

//首先需要把项目属性Drivers Settings->Target Platform改成Desktop

//比较重要的是，加上IRP_MJ_CLEANUP，在PreCleanUp中清一下缓存，EptFileCacheClear(FltObjects->FileObject);这样才能进到Pre/PostRead中

//在PreRead和PreWrite中过滤掉以下两步
if (!FlagOn(Data->Iopb->IrpFlags, (IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO | IRP_NOCACHE)))
    return FLT_PREOP_SUCCESS_NO_CALLBACK;

//判断是否为目标扩展名，进一步筛选，减少后续操作
if (!EptIsTargetExtension(Data))
    return FLT_PREOP_SUCCESS_NO_CALLBACK;

//然后注意，PostRead中，是在RtlCopyMemory之前解密；PreWrite中，是在RtlCopyMemory之后加密

//但是PreWrite中，iopb->Parameters.Write.Length的大小是0x1000，和真正数据长度是不符的，所以在加密后，如果想要DbgPrint输出一下加密后的密文，需要给字符串加上EOF

//这样基本上就可以了。

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//关于写入，识别，对记事本隐藏加密文件头，这部分完全按照《Windows内核安全与驱动开发》是不合适的
//尤其是以下标记（重要）的步骤是需要补充的，另外不建议直接在上一步的加密解密Sample中添加修改，
//建议另外新建项目，单纯实现写入，识别，对记事本隐藏加密文件头，最后组合在一起

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//写入加密文件头"ENCRYPTION"大小PAGE_SIZE

//分配大小
FileEOFInfo.EndOfFile.QuadPart = FILE_FLAG_SIZE;
Status = FltSetInformationFile(FltObjects->Instance, FltObjects->FileObject, &FileEOFInfo, sizeof(FILE_END_OF_FILE_INFORMATION), FileEndOfFileInformation);

//初始化事件
KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

//写入加密标记头
ByteOffset.QuadPart = BytesWritten = 0;
Status = FltWriteFile(FltObjects->Instance, FltObjects->FileObject, &ByteOffset, Length, Buffer,
	FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, &BytesWritten, EptWriteCallbackRoutine, &Event);

//等待FltWriteFile完成
KeWaitForSingleObject(&Event, Executive, KernelMode, TRUE, 0);

//修改文件指针偏移（重要）
FilePositionInfo.CurrentByteOffset.QuadPart = 0;
Status = FltSetInformationFile(FltObjects->Instance, FltObjects->FileObject, &FilePositionInfo, sizeof(FILE_POSITION_INFORMATION), FilePositionInformation);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//读取加密文件头

//将文件读入缓冲区
ByteOffset.QuadPart = BytesRead = 0;
Status = FltReadFile(FltObjects->Instance, FltObjects->FileObject, &ByteOffset, Length, ReadBuffer,
	FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, &BytesRead, NULL, NULL);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//对记事本隐藏文件头

//Read和Write同理，这里只展示Read

//PreRead:

//忽略以下操作（重要）

if (Data->Iopb->Parameters.Read.Length == 0)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

if (!FlagOn(Data->Iopb->IrpFlags, (IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO | IRP_NOCACHE)))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

//设置偏移加FILE_FLAG_SIZE（重要）
Data->Iopb->Parameters.Read.ByteOffset.QuadPart += FILE_FLAG_SIZE;
FltSetCallbackDataDirty(Data);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//第三步，这里我们把以上两部分组合在一起，实现一个最小化的基本功能的加密解密系统

//这里需要添加的是IRP_MJ_QUERY_INFORMATION和IRP_MJ_SET_INFORMATION

//因为在PreRead和PreWrite中，对Data->Iopb->Parameters.Read.ByteOffset.QuadPart += FILE_FLAG_SIZE;做了调整

//所以需要在PostQueryInformation和PreSetInformation中对相关的选项进行调整，这里不再赘述
