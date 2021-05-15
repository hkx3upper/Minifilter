#pragma once

#include "global.h"
#include <bcrypt.h>

#define KEY_BOJECT_BUFFER 'kbBF'
#define ENCRYPT_TEMP_BUFFER 'etBF'

#define AES_BLOCK_SIZE 16

typedef struct AES_INIT_VARIABLES
{
	BCRYPT_ALG_HANDLE hAesAlg;
	BCRYPT_KEY_HANDLE hKey;
	PUCHAR pbKeyObject;
	BOOLEAN Flag;

}AES_INIT_VARIABLES, * PAES_INIT_VARIABLES;

extern AES_INIT_VARIABLES AesInitVar;

BOOLEAN EptAesInithKey();

VOID EptAesCleanUp();

BOOLEAN EptAesEncrypt(PCFLT_RELATED_OBJECTS FltObjects, PUCHAR Buffer, ULONG* LengthReturned, BOOLEAN ReturnLengthFlag);

BOOLEAN EptAesDecrypt(PUCHAR Buffer, ULONG Length);