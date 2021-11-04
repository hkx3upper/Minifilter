#pragma once
#include "global.h"

typedef struct EPT_ENCRYPTED_FILE
{
	LIST_ENTRY ListEntry;
	CHAR EncryptedFileName[260];
	INT OrigFileName;

}EPT_ENCRYPTED_FILE, * PEPT_ENCRYPTED_FILE;

LIST_ENTRY EncryptedFileListHead;
KSPIN_LOCK EncryptedFileListSpinLock;
ERESOURCE EncryptedFileListResource;


#define EPT_PR_ACCESS_READ_WRITE			0x00000001
#define EPT_PR_ACCESS_BACKUP_RESTORE		0x00000002
#define EPT_PR_ACCESS_NO_ACCESS				0x00000004
#define EPT_PR_NOTEPAD_PLUS_PLUS			0x00000008

//扩展名用 , （英文）分隔，用 , （英文）结束 例如：txt,docx，并在count中记录数量
typedef struct EPT_PROCESS_RULES
{
	LIST_ENTRY ListEntry;
	char TargetProcessName[260];
	char TargetExtension[100];
	int count;
	ULONG Access;
	UCHAR Hash[32];
	BOOLEAN IsCheckHash;

}EPT_PROCESS_RULES, * PEPT_PROCESS_RULES;

LIST_ENTRY ProcessRulesListHead;
KSPIN_LOCK ProcessRulesListSpinLock;
ERESOURCE ProcessRulesListResource;

NTSTATUS EptIsPRInLinkedList(IN OUT PEPT_PROCESS_RULES ProcessRules);

NTSTATUS EptReplacePRInLinkedList(IN EPT_PROCESS_RULES ProcessRules);

VOID EptListCleanUp();;