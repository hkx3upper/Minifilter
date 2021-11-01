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

BOOLEAN EptAesEncrypt(IN OUT PUCHAR Buffer, IN OUT ULONG* LengthReturned, IN BOOLEAN ReturnLengthFlag);

NTSTATUS EptAesDecrypt(IN OUT PUCHAR Buffer, IN ULONG Length);