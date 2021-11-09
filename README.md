# Minifilter
参考《Windows内核安全与驱动开发》的加密解密Minifilter

eg：![框架](https://github.com/hkx3upper/Minifilter/blob/main/Resources/EncryptMinifilter.jpg)

eg：![界面1](https://github.com/hkx3upper/Minifilter/blob/main/Resources/Panel.PNG)

# 简述：

这个项目主要实现了一个简单的DLP(Data leakage prevention)，每当目标进程创建目标扩展名的文件，

且有写入倾向时，会对文件写入加密头，将数据加密，并标记。这样，保证数据在磁盘中是以密文的形式存放的。

以后尝试打开该文件的进程，会根据进程的权限（明文，密文，无权限），进行透明解密或者拒绝访问。

并且，可以通过C#的界面进行进程策略配置，以及对一个非空且未加密文件进行特权加密，

或者对一个已加密文件进行特权解密，这样可以将该文件纳入驱动控制的范围内。

# 运行环境（工具）：

Windows 10 x64

VMware Workstation Pro 16

Visual Studio 2019

Notepad.exe x64

FileSpy.exe x64

# 更新日志：

2021.04.16 项目立项

2021.05.05 实现了基于SwapBuffers的异或加密解密

2021.05.07 写入、识别加密文件头，对记事本隐藏加密文件头

2021.05.10 实现了应用端到驱动的简单通信

2021.05.12 实现了从客户端传入信任进程和扩展名匹配规则到驱动

2021.05.13 大更新，不再使用《Windows内核安全与驱动开发》对于ByteOffset和EndOfFile的处理方式

2021.05.15 使用微软Cryptography API: Next Generation（CNG）库的AES-128 ECB模式

2021.05.16 完善匹配规则，实现双向链表存储

2021.05.19 驱动中实现进程可执行文件的Hash验证（SHA-256）（注释掉了）

2021.05.20 解决BCryptEncrypt自动填充数据，但EOF没有改变，导致文件移动后，加密后的填充数据丢失

2021.08.29 解决链表中进程匹配问题，解决加密解密后EOF问题

2021.09.03 做了代码优化

2021.09.06 双向链表插入移除节点时用了自旋锁，StreamContext加了读写锁，保证多线程下数据的安全

2021.09.11 取消了全局变量CheckHash的使用，将其放入每个链表的节点中

2021.09.12 双向链表遍历时加了共享锁

2021.10.31 处理已存在的未加密文档（有bug未解决），将进程加密策略双向链表操作单独放在了LinkedList.c中，

2021.11.01 进程设置三种权限，增加特权解密功能，特权解密功能

2021.11.03 解决notepad的打开，另存为按钮蓝屏问题：EptIsTargetExtension函数没有拦截到无关操作；  
------------增加特权解密命令首先判断是否存在加密头操作

2021.11.04 代码回滚，去掉了10.31号的处理已存在的未加密文档操作

2021.11.08 新增桌面和内核通信函数封装的dll

2021.11.09 新增C# WPF框架的界面，通过调用dll和内核通信

# 发展方向：

接下来将会考虑双缓冲方面的问题（LayerFsd或者像Dokany一样FUSE用户空间）；

考虑进程策略安全性的问题

对大文件的处理

多线程加解密的问题

桌面到内核数据包加密

密钥安全问题

文件大小记录问题（将StreamContext中的数据导出，或者用链表做同步后存入本地，或者写入加密头中）

# 未修复的bug：

1.复制粘贴已加密文件，有一定几率会先进入PreWrite，造成重复加密，导致数据损坏

2.暂不支持notepad++.exe wps.exe wpp.exe等，notepad++的读写方式和正常的不太一样，

3.已存在的未加密大文件，有写入倾向，重新添加加密头，读取源文件时会导致偏移出错，

这是因为大文件不是全部读入缓冲的，只是一部分源文件头+修改后的部分源文件头的格式

4.没有做特权加解密线程与minifilter线程之间的文件操作保护

# 参考：
因为书中是基于传统文件过滤驱动的，用在Minifilter中有很多的出入，因此参考了很多相关的资料，谢谢

https://github.com/microsoft/Windows-driver-samples/tree/master/filesys/miniFilter/swapBuffers

https://github.com/microsoft/Windows-classic-samples

https://github.com/minglinchen/WinKernelDev/tree/master/crypt_file

https://github.com/SchineCompton/Antinvader

https://github.com/shines77/Antinvader2015

https://github.com/comor86/MyMiniEncrypt

https://github.com/guidoreina/minivers

https://github.com/xiao70/X70FSD

https://github.com/dokan-dev/dokany

《Windows内核安全与驱动开发》

《Windows NT File System Internals》

何明 基于Minifilter微框架的文件加解密系统的设计与实现 2014 年 6 月

刘晗 基于双缓冲过滤驱动的透明加密系统研究与实现 2010 年 4 月

何翔 基于 IBE 和 FUSE 的双向透明文件加密系统的研究与实现 2017 年 4 月

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

//但是PreWrite中，iopb->Parameters.Write.Length的大小是0x1000，和真正数据长度是不符的，

//可以使用FltQueryInformationFile查询EOF获得文件的真正大小

//这样基本上就可以了。

## 关于写入，识别，对记事本隐藏加密文件头，这部分完全按照《Windows内核安全与驱动开发》是不合适的

//写入加密文件头"ENCRYPTION"大小PAGE_SIZE

//这里不需要用FltSetInformationFile分配EOF大小

//初始化事件（重要）
```
KeInitializeEvent(&Event, SynchronizationEvent, FALSE);
```
//写入加密标记头
```
ByteOffset.QuadPart = 0;
Status = FltWriteFile(FltObjects->Instance, FltObjects->FileObject, &ByteOffset, Length, Buffer,
	FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, NULL, EptReadWriteCallbackRoutine, &Event);
```
//等待FltWriteFile完成
```
KeWaitForSingleObject(&Event, Executive, KernelMode, TRUE, 0);
```
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//读取加密文件头  
//将文件读入缓冲区
```
Length = FILE_FLAG_SIZE;（重要）

KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

ByteOffset.QuadPart = 0;
Status = FltReadFile(FltObjects->Instance, FltObjects->FileObject, &ByteOffset, Length, ReadBuffer,
    	FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, NULL, EptReadWriteCallbackRoutine, &Event);

KeWaitForSingleObject(&Event, Executive, KernelMode, TRUE, 0);
```
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//对记事本隐藏文件头

//Read和Write同理，这里只展示Read  
//PreRead:

//忽略以下操作（重要）
```
if (FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_FAST_IO_OPERATION))
{
    return FLT_PREOP_DISALLOW_FASTIO;
}

if (Data->Iopb->Parameters.Read.Length == 0)
{
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

if (!FlagOn(Data->Iopb->IrpFlags, (IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO | IRP_NOCACHE)))
{
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
```
//设置偏移加FILE_FLAG_SIZE，Write不需要修改偏移（重要）
```
Data->Iopb->Parameters.Read.ByteOffset.QuadPart += FILE_FLAG_SIZE;
FltSetCallbackDataDirty(Data);
```
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//第三步，这里我们把以上两部分组合在一起，实现一个最小化的基本功能的加密解密系统

//这里需要添加的是IRP_MJ_QUERY_INFORMATION  
//因为之前加上了PAGE_SIZE大小的文件加密头；所以需要在PostQueryInformation中EOF减掉PAGE_SIZE,  
//否则记事本每次保存都会在数据之后加上PAGE_SIZE的空白  

## 应用端到驱动的简单通信

//这一步按照《Windows内核安全与驱动开发》就可以了  
//使用了如下结构体作为数据头
```
typedef struct EPT_MESSAGE_HEADER
{
	int Command;
	int Length;
}EPT_MESSAGE_HEADER, * PEPT_MESSAGE_HEADER;
```

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

## AES-128 ECB

https://www.microsoft.com/en-us/download/details.aspx?id=30688

//需要在微软官网下载Cryptographic Provider Development Kit，  
//项目->属性的VC++目录的包含目录，库目录设置相应的位置  
//链接器的常规->附加库目录C:\Windows Kits\10\Cryptographic Provider Development Kit\Lib\x64  
//输入->附加依赖项一定要设置为ksecdd.lib  

//按照微软的sample修改，https://docs.microsoft.com/en-us/windows/win32/seccng/encrypting-data-with-cng  
//在DriverEntry中初始化加密的Key，存入全局变量AES_INIT_VARIABLES AesInitVar中，  
//在EncryptUnload中CleanUp相关的Key和分配的内存  
```
typedef struct AES_INIT_VARIABLES
{
    BCRYPT_ALG_HANDLE hAesAlg;
    BCRYPT_KEY_HANDLE hKey;
    PUCHAR pbKeyObject;
    BOOLEAN Flag;
}AES_INIT_VARIABLES, * PAES_INIT_VARIABLES;
```
//因为每次Data->Iopb->Parameters.Write.Length和Data->Iopb->Parameters.Read.Length都是PAGE_SIZE的整数倍  
//又因为加密之后的数据比原始数据大，所以在PostRead中不需要调用BCryptDecrypt获取解密后数据大小  
//但是PreWrite需要调用BCryptEncrypt返回加密后数据的大小，根据这个大小分配之后替换的内存，  
//之后再调用BCryptEncrypt加密数据  
```
if (ReturnLengthFlag)
{

//BCRYPT_BLOCK_PADDING
//Allows the encryption algorithm to pad the data to the next block size. 
//If this flag is not specified, the size of the plaintext specified in the cbInput parameter 
//must be a multiple of the algorithm's block size.

Status = BCryptEncrypt(AesInitVar.hKey, TempBuffer, OrigLength, NULL, NULL, 0, NULL, 0, LengthReturned, 0)

    if (!NT_SUCCESS(Status))
    {
        DbgPrint("EptAesEncrypt BCryptEncrypt failed.\n");
        ExFreePoolWithTag(TempBuffer, ENCRYPT_TEMP_BUFFER);
        return FALSE;
    }

    DbgPrint("PreWrite AesEncrypt Length = %d LengthReturned = %d.\n", Length, *LengthReturned);

    ExFreePoolWithTag(TempBuffer, ENCRYPT_TEMP_BUFFER);
    return TRUE;
}


Status = BCryptEncrypt(AesInitVar.hKey, TempBuffer, OrigLength, NULL, NULL, 0, Buffer, *LengthReturned, LengthReturned, 0)

if (!NT_SUCCESS(Status))
{
    DbgPrint("EptAesEncrypt BCryptEncrypt failed Status = %X.\n", Status);
    ExFreePoolWithTag(TempBuffer, ENCRYPT_TEMP_BUFFER);
    return FALSE;
}
```

## 完善匹配规则，实现双向链表存储

//使用以下结构体
```
typedef struct EPT_PROCESS_RULES
{
	LIST_ENTRY ListEntry;
	char TargetProcessName[260];
	char TargetExtension[100];
	int count;

}EPT_PROCESS_RULES, * PEPT_PROCESS_RULES;
```
//在DriverEntry中InitializeListHead(&ListHead);，在Unload中EptListCleanUp();，释放所有内存
```
VOID EptListCleanUp()
{
PEPT_PROCESS_RULES ProcessRules;
PLIST_ENTRY pListEntry;

while (!IsListEmpty(&ListHead))
{
    pListEntry = ExInterlockedRemoveHeadList(&ListHead, &List_Spin_Lock);

    ProcessRules = CONTAINING_RECORD(pListEntry, EPT_PROCESS_RULES, ListEntry);
    DbgPrint("Remove list node TargetProcessName = %s", ProcessRules->TargetProcessName);

    ExFreePool(ProcessRules);
}

}
```
//在驱动MessageNotifyCallback函数中接收并插入链表
```
PEPT_PROCESS_RULES ProcessRules;
ProcessRules = ExAllocatePoolWithTag(PagedPool, sizeof(EPT_PROCESS_RULES), PROCESS_RULES_BUFFER_TAG);
if (!ProcessRules)
{
    DbgPrint("DriverEntry ExAllocatePoolWithTag ProcessRules failed.\n");
    return 0;
}

RtlZeroMemory(ProcessRules, sizeof(EPT_PROCESS_RULES));

RtlMoveMemory(ProcessRules->TargetProcessName, Buffer + sizeof(EPT_MESSAGE_HEADER), sizeof(EPT_PROCESS_RULES) - sizeof(LIST_ENTRY));

ExInterlockedInsertTailList(&ListHead, &ProcessRules->ListEntry, &List_Spin_Lock);

break;
```
//使用以下方式遍历比较进程名和扩展名
```
PEPT_PROCESS_RULES ProcessRules;
PLIST_ENTRY pListEntry = ListHead.Flink;

while (pListEntry != &ListHead)
{

    ProcessRules = CONTAINING_RECORD(pListEntry, EPT_PROCESS_RULES, ListEntry);

    //比较操作
		
    pListEntry = pListEntry->Flink;

}
```

## 驱动中实现进程可执行文件的Hash验证
```
//这里用到了Windows-classic-samples-master\Samples\Security\SignHashAndVerifySignature
//中的ComputeHash函数计算Hash
NTSTATUS ComputeHash(
	PUCHAR Data, 
	ULONG DataLength, 
	PUCHAR* DataDigestPointer, 
	ULONG* DataDigestLengthPointer)
```
//把exe文件读到Buffer
```
NTSTATUS EptReadProcessFile(
	UNICODE_STRING ProcessName,
	PUCHAR* Buffer,
	PULONG Length
	)
{
	OBJECT_ATTRIBUTES ObjectAttributes;
	NTSTATUS Status;
	HANDLE FileHandle;
	IO_STATUS_BLOCK IoStatusBlock;

	FILE_STANDARD_INFORMATION FileStandInfo;
	LARGE_INTEGER ByteOffset;

	InitializeObjectAttributes(
		&ObjectAttributes, 
		&ProcessName, 
		OBJ_CASE_INSENSITIVE, 
		NULL, 
		NULL);

	Status = ZwOpenFile(
		&FileHandle, 
		GENERIC_READ,
		&ObjectAttributes, 
		&IoStatusBlock, 
		FILE_SHARE_VALID_FLAGS,
		FILE_NON_DIRECTORY_FILE);

	if (!NT_SUCCESS(Status))
	{
		//STATUS_SHARING_VIOLATION
		DbgPrint("EptReadProcessFile ZwOpenFile failed Status = %X.\n", Status);
		return Status;
	}

	//查询文件大小，分配内存
	Status = ZwQueryInformationFile(
		FileHandle, 
		&IoStatusBlock, 
		&FileStandInfo, 
		sizeof(FILE_STANDARD_INFORMATION), 
		FileStandardInformation);

	if (!NT_SUCCESS(Status))
	{
		DbgPrint("EptReadProcessFile ZwQueryInformationFile failed.\n");
		ZwClose(FileHandle);
		return Status;
	}

	(*Buffer) = ExAllocatePoolWithTag(
		PagedPool, 
		FileStandInfo.EndOfFile.QuadPart, 
		PROCESS_FILE_BUFFER_TAG);

	if (!(*Buffer))
	{
		DbgPrint("EptReadProcessFile ExAllocatePoolWithTag Buffer failed.\n");
		ZwClose(FileHandle);
		return Status;
	}

	ByteOffset.QuadPart = 0;
	Status = ZwReadFile(
		FileHandle, 
		NULL, NULL, NULL, 
		&IoStatusBlock, 
		(*Buffer),
		(ULONG)FileStandInfo.EndOfFile.QuadPart, 
		&ByteOffset, 
		NULL);

	if (!NT_SUCCESS(Status))
	{
		DbgPrint("EptReadProcessFile ZwReadFile failed.\n");
		ZwClose(FileHandle);
		ExFreePool((*Buffer));
		return Status;
	}

	*Length = (ULONG)FileStandInfo.EndOfFile.QuadPart;
	return Status;
}
```
//在EptIsTargetProcess函数中判断Hash，CheckHash标志位是全局变量，在PreCreate中时，设为TRUE
```
if(CheckHash)
{
    PUCHAR ReadBuffer = NULL;
    ULONG Length;
    Status = EptReadProcessFile(*ProcessName, &ReadBuffer, &Length);

    if (NT_SUCCESS(Status))
    {
					
        if (EptVerifyHash(ReadBuffer, Length, ProcessRules->Hash))
        {
            if (ReadBuffer)
                ExFreePool(ReadBuffer);
            CheckHash = FALSE;
            return TRUE;
        }
        else
        {
            if (ReadBuffer)
                ExFreePool(ReadBuffer);
            CheckHash = FALSE;
            return FALSE;
        }
    }
    return FALSE;
}
```
//这里在从客户端传入Hash到驱动之前，对Hash进行转换  
//因为ULONGLONG是小端序，  
//而ComputeHash输出的是十六进制的Hash值，是大端序  
//做一下转换
```
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
```

## 解决加密解密后EOF问题

//在PreSetInformation中（这里相当于给txt文件分配内存），将EOF对齐AES_BLOCK_SIZE，并在streamcontext中记录文件原始大小
因为分配内存时，直接分配了16的倍数，所以加解密时不需要再对齐了
```
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
        
        DbgPrint("EncryptPreSetInformation FileEndOfFileInformation EndOfFile = %d.\n", Info->EndOfFile.QuadPart);
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
```
//在EncryptPostQueryInformation中（这里是Read之前，记事本查询所需信息），
调整EOF，因为加密解密时使16字节对齐的，解密后，会有16-原始大小的空白字符，需要调整EOF，
```
 if (StreamContext->FileSize > 0 &&(StreamContext->FileSize % AES_BLOCK_SIZE != 0))
    {
        FileOffset = (StreamContext->FileSize / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE - StreamContext->FileSize;
    }
    else if (StreamContext->FileSize > 0 && (StreamContext->FileSize % AES_BLOCK_SIZE == 0))
    {
        FileOffset = 0;
    }

case FileStandardInformation:
    {
        PFILE_STANDARD_INFORMATION Info = (PFILE_STANDARD_INFORMATION)InfoBuffer;
        Info->AllocationSize.QuadPart -= FILE_FLAG_SIZE;
        Info->EndOfFile.QuadPart = Info->EndOfFile.QuadPart - FILE_FLAG_SIZE - FileOffset;
        break;
    }
   	
```

## 处理已存在的未加密文档（已删除）

对于已经被写过，但是没有加密头的文档，我选择的处理方式是：在PostCreate中记录相关的文件大小，文件名等

在PreClose中把文档全部读入缓冲区，加密，加上加密头，重新写回文件。

这里有点问题，读入的文档有一部分是重复的，所以我直接用偏移略过去了，另外修改了StreamContext中记录的

文件大小,以便于PostQueryInformation中对EOF做相关的处理（这块是因为加密前后数据大小的变化而做的操作）
```
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
```

## 特权解密

这个命令是由客户端传入的，用于把加密的文件，去掉加密头，解密

所以我用事件做了内核线程和PrePost的同步，保证不会同时处理同一个文件（未完成）

因为是自己创的线程，需要自己找到FileObject和Instance，用FltCreateFile打开FileObject，

通过符号链接，找到卷的DOS名，然后找到卷的Instance。

然后读加密的数据，解密，调整EOF，重新写回文件，这里要把StreamContext的Flag去掉，因为已经是正常的文件

最后刷新缓存。主要的功能函数是FileFunc.c的EptRemoveEncryptHeaderAndDecrypt(PWCHAR FileName)

这样就可以完成一个闭环，首先一个加密文件，可以特权解密，然后有写入倾向时，会再写入加密头，加密数据。

## 特权加密

特权加密与特权解密类似，就是对于空文件的处理上加了一步。

主要的功能函数是FileFunc.c的EptAppendEncryptHeaderAndEncryptEx(PWCHAR FileName)

## 2021.11.04

以我现在对于缓冲的理解，还找不到一个合适的位置以及时机，去处理已存在的未加密文档，重新添加加密头，

不同于特权加解密，写入加密头的同时，notepad也正在写入数据，这两块数据的同步，这一块还不懂

而且关于在多线程下的文件操作保护，应该要去操作FCB中的锁，现在还不太懂这块

## 2021.11.08 新增桌面和内核通信函数封装的dll

注意FilterGetMessage的用法，需要加FILTER_MESSAGE_HEADER头，另外注意不要和FltSendMessage造成死锁

还有，这个函数桌面端的返回值，我查不到......

不再在dll的DLL_PROCESS_ATTACH中初始化端口，换到C#中了

## 2021.11.09 新增C# WPF框架的界面，通过调用dll和内核通信

实现了特权加密，特权解密和配置进程策略的功能