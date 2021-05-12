# Minifilter
参考《Windows内核安全与驱动开发》的加密解密Minifilter

# 运行环境：

Windows 10 x64

Visual Studio 2019

# 更新日志：

2021.5.5   实现了基于SwapBuffers的异或加密解密

2021.5.7   写入、识别加密文件头，对记事本隐藏加密文件头

2021.5.10 实现了应用端到驱动的简单通信

2021.5.12 实现了从客户端传入信任进程和扩展名匹配规则到驱动（将来可以用链表保存）

接下来将会考虑双缓冲方面的问题，考虑使用AES-128（数据分组对齐）

# 参考：
因为书中是基于传统文件过滤驱动的，用在Minifilter中有很多的出入，因此参考了很多相关的资料，谢谢

https://github.com/microsoft/Windows-driver-samples/tree/master/filesys/miniFilter/swapBuffers

https://github.com/minglinchen/WinKernelDev/tree/master/crypt_file

https://github.com/SchineCompton/Antinvader

https://github.com/shines77/Antinvader2015

https://github.com/comor86/MyMiniEncrypt

https://github.com/xiao70/X70FSD

《Windows内核安全与驱动开发》

《Windows NT File System Internals》

# 以下是主要的步骤：

## 按照逐步搭建最小化系统的原则，先根据微软Sample的SwapBuffers实现简单的加密，解密

//首先需要把项目属性Drivers Settings->Target Platform改成Desktop

//关于缓冲方面的问题，加上IRP_MJ_CLEANUP，在PreCleanUp中清一下缓存，EptFileCacheClear(FltObjects->FileObject);

//在PreRead和PreWrite中过滤掉以下两步
```
if (!FlagOn(Data->Iopb->IrpFlags, (IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO | IRP_NOCACHE)))

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
```
//判断是否为目标扩展名，进一步筛选，减少后续操作
```
if (!EptIsTargetExtension(Data))

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
```
//然后注意，PostRead中，是在RtlCopyMemory之前解密；PreWrite中，是在RtlCopyMemory之后加密

//但是PreWrite中，iopb->Parameters.Write.Length的大小是0x1000，和真正数据长度是不符的，所以在加密后，如果想要DbgPrint输出一下加密后的密文，需要给字符串加上EOF

//这样基本上就可以了。

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

## 关于写入，识别，对记事本隐藏加密文件头，这部分完全按照《Windows内核安全与驱动开发》是不合适的

//尤其是以下标记（重要）的步骤是需要补充的，另外不建议直接在上一步的加密解密Sample中添加修改，  
//建议另外新建项目，单纯实现写入，识别，对记事本隐藏加密文件头，最后组合在一起

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//写入加密文件头"ENCRYPTION"大小PAGE_SIZE

//分配大小
```
FileEOFInfo.EndOfFile.QuadPart = FILE_FLAG_SIZE;
Status = FltSetInformationFile(FltObjects->Instance, FltObjects->FileObject, &FileEOFInfo, sizeof(FILE_END_OF_FILE_INFORMATION), FileEndOfFileInformation);
```
//初始化事件
```
KeInitializeEvent(&Event, SynchronizationEvent, FALSE);
```
//写入加密标记头
```
ByteOffset.QuadPart = BytesWritten = 0;
Status = FltWriteFile(FltObjects->Instance, FltObjects->FileObject, &ByteOffset, Length, Buffer,
	FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, &BytesWritten, EptWriteCallbackRoutine, &Event);
```
//等待FltWriteFile完成
```
KeWaitForSingleObject(&Event, Executive, KernelMode, TRUE, 0);
```
//修改文件指针偏移（重要）
```
FilePositionInfo.CurrentByteOffset.QuadPart = 0;
Status = FltSetInformationFile(FltObjects->Instance, FltObjects->FileObject, &FilePositionInfo, sizeof(FILE_POSITION_INFORMATION), FilePositionInformation);
```
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//读取加密文件头  
//将文件读入缓冲区
```
ByteOffset.QuadPart = BytesRead = 0;
Status = FltReadFile(FltObjects->Instance, FltObjects->FileObject, &ByteOffset, Length, ReadBuffer,
	FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, &BytesRead, NULL, NULL);
```
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//对记事本隐藏文件头

//Read和Write同理，这里只展示Read  
//PreRead:

//忽略以下操作（重要）
```
if (Data->Iopb->Parameters.Read.Length == 0)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

if (!FlagOn(Data->Iopb->IrpFlags, (IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO | IRP_NOCACHE)))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
```
//设置偏移加FILE_FLAG_SIZE（重要）
```
Data->Iopb->Parameters.Read.ByteOffset.QuadPart += FILE_FLAG_SIZE;
FltSetCallbackDataDirty(Data);
```
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//第三步，这里我们把以上两部分组合在一起，实现一个最小化的基本功能的加密解密系统

//这里需要添加的是IRP_MJ_QUERY_INFORMATION和IRP_MJ_SET_INFORMATION  
//因为在PreRead和PreWrite中，对Data->Iopb->Parameters.Read.ByteOffset.QuadPart += FILE_FLAG_SIZE;做了调整  
//所以需要在PostQueryInformation和PreSetInformation中对相关的选项进行调整，这里不再赘述

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

## 应用端到驱动的简单通信

//这一步按照《Windows内核安全与驱动开发》就可以了

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

## 从客户端传入信任进程和扩展名匹配规则到驱动

//使用结构体  
//扩展名用 , （英文）分隔，用 , （英文）结束 例如：txt,docx，并在count中记录数量
```
typedef struct EPT_PROCESS_RULES
{
	char TargetProcessName[260];
	char TargetExtension[100];
	int count;
}EPT_PROCESS_RULES, * PEPT_PROCESS_RULES;
```
//客户端发送进程规则
```
memset(Buffer, 0, MESSAGE_SIZE);
MessageHeader.Command = 2;
MessageHeader.Length = MESSAGE_SIZE - sizeof(MessageHeader);
RtlMoveMemory(Buffer, &MessageHeader, sizeof(MessageHeader));

RtlMoveMemory(ProcessRules.TargetProcessName, "notepad.exe", sizeof("notepad.exe"));
RtlMoveMemory(ProcessRules.TargetExtension, "txt,", sizeof("txt,"));
ProcessRules.count = 1;
RtlMoveMemory(Buffer + sizeof(MessageHeader), &ProcessRules, sizeof(EPT_PROCESS_RULES));

if (!EptUserSendMessage(Buffer))
{
	printf("EptUserSendMessage failed.\n");
	return 0;
}
```
//在驱动MessageNotifyCallback函数中接收
```
RtlMoveMemory(&ProcessRules, Buffer + sizeof(EPT_MESSAGE_HEADER), sizeof(EPT_PROCESS_RULES));
```
//将扩展名分隔开，并比较
```
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
```