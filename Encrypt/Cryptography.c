
#include "cryptography.h"
#include "common.h"


AES_INIT_VARIABLES AesInitVar;


BOOLEAN EptAesInithKey()
{

	NTSTATUS Status;
	ULONG cbData = 0, cbKeyObject = 0;

	UCHAR rgbAES128Key[] =
	{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
	};

	RtlZeroMemory(&AesInitVar, sizeof(AES_INIT_VARIABLES));

	Status = BCryptOpenAlgorithmProvider(&AesInitVar.hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0);

	if (!NT_SUCCESS(Status))
	{
		DbgPrint("EptAesEncrypt BCryptOpenAlgorithmProvider failed.\n");
		return FALSE;
	}

	Status = BCryptGetProperty(AesInitVar.hAesAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObject, sizeof(ULONG), &cbData, 0);

	if (!NT_SUCCESS(Status))
	{
		DbgPrint("EptAesEncrypt BCryptGetProperty failed.\n");
		BCryptCloseAlgorithmProvider(AesInitVar.hAesAlg, 0);
		return FALSE;
	}

	AesInitVar.pbKeyObject = ExAllocatePoolWithTag(PagedPool, cbKeyObject, KEY_BOJECT_BUFFER);

	if (!AesInitVar.pbKeyObject)
	{
		DbgPrint("EptAesEncrypt ExAllocatePoolWithTag pbKeyObject failed.\n");
		BCryptCloseAlgorithmProvider(AesInitVar.hAesAlg, 0);
		return FALSE;
	}

	Status = BCryptSetProperty(AesInitVar.hAesAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0);

	if (!NT_SUCCESS(Status))
	{
		DbgPrint("EptAesEncrypt BCryptSetProperty failed.\n");
		BCryptCloseAlgorithmProvider(AesInitVar.hAesAlg, 0);
		ExFreePoolWithTag(AesInitVar.pbKeyObject, KEY_BOJECT_BUFFER);
		return FALSE;
	}

	Status = BCryptGenerateSymmetricKey(AesInitVar.hAesAlg, &AesInitVar.hKey, AesInitVar.pbKeyObject, cbKeyObject, rgbAES128Key, sizeof(rgbAES128Key), 0);

	if (!NT_SUCCESS(Status))
	{
		DbgPrint("EptAesEncrypt BCryptGenerateSymmetricKey failed.\n");
		BCryptCloseAlgorithmProvider(AesInitVar.hAesAlg, 0);
		ExFreePoolWithTag(AesInitVar.pbKeyObject, KEY_BOJECT_BUFFER);
		return FALSE;
	}

	return TRUE;
}


VOID EptAesCleanUp()
{

	if (!AesInitVar.Flag)
	{
		return;
	}

	if (AesInitVar.hAesAlg)
	{
		BCryptCloseAlgorithmProvider(AesInitVar.hAesAlg, 0);
	}

	if (AesInitVar.hKey)
	{
		BCryptDestroyKey(AesInitVar.hKey);
	}

	if (AesInitVar.pbKeyObject)
	{
		ExFreePoolWithTag(AesInitVar.pbKeyObject, KEY_BOJECT_BUFFER);
	}

}


BOOLEAN EptAesEncrypt(PCFLT_RELATED_OBJECTS FltObjects, PUCHAR Buffer, ULONG* LengthReturned, BOOLEAN ReturnLengthFlag)
{

	UNREFERENCED_PARAMETER(FltObjects);

	if (!AesInitVar.Flag)
	{
		return FALSE;
	}

	NTSTATUS Status;
	ULONG OrigLength = EptGetFileSize(FltObjects) - FILE_FLAG_SIZE;
	DbgPrint("OrigLength = %d.\n", OrigLength);
	ULONG Length = OrigLength;

	if ((Length % AES_BLOCK_SIZE) != 0)
	{
		Length = (Length / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
	}

	PUCHAR TempBuffer = ExAllocatePoolWithTag(PagedPool, Length, ENCRYPT_TEMP_BUFFER);

	if (!TempBuffer)
	{
		DbgPrint("EptAesEncrypt ExAllocatePoolWithTag TempBuffer failed.\n");
		return FALSE;
	}

	RtlZeroMemory(TempBuffer, Length);
	RtlMoveMemory(TempBuffer, Buffer, OrigLength);

	if (ReturnLengthFlag)
	{
		//BCRYPT_BLOCK_PADDING
		//Allows the encryption algorithm to pad the data to the next block size. 
		//If this flag is not specified, the size of the plaintext specified in the cbInput parameter 
		//must be a multiple of the algorithm's block size.
		
		Status = BCryptEncrypt(AesInitVar.hKey, TempBuffer, OrigLength, NULL, NULL, 0, NULL, 0, LengthReturned, BCRYPT_BLOCK_PADDING);

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


	Status = BCryptEncrypt(AesInitVar.hKey, TempBuffer, OrigLength, NULL, NULL, 0, Buffer, *LengthReturned, LengthReturned, BCRYPT_BLOCK_PADDING);

	if (!NT_SUCCESS(Status))
	{
		DbgPrint("EptAesEncrypt BCryptEncrypt failed Status = %X.\n", Status);
		ExFreePoolWithTag(TempBuffer, ENCRYPT_TEMP_BUFFER);
		return FALSE;
	}

	ExFreePoolWithTag(TempBuffer, ENCRYPT_TEMP_BUFFER);
	return TRUE;
}


BOOLEAN EptAesDecrypt(PUCHAR Buffer, ULONG Length)
{

	if (!AesInitVar.Flag)
	{
		return FALSE;
	}

	NTSTATUS Status;
	ULONG LengthReturned, BufferSize;

	if ((Length % AES_BLOCK_SIZE) != 0)
	{
		Length = (Length / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
	}

	BufferSize = ROUND_TO_SIZE(Length, PAGE_SIZE);

	PUCHAR TempBuffer = ExAllocatePoolWithTag(PagedPool, Length, ENCRYPT_TEMP_BUFFER);

	if (!TempBuffer)
	{
		DbgPrint("EptAesDecrypt ExAllocatePoolWithTag TempBuffer failed.\n");
		return FALSE;
	}

	RtlZeroMemory(TempBuffer, Length);
	RtlMoveMemory(TempBuffer, Buffer, Length);

	Status = BCryptDecrypt(AesInitVar.hKey, TempBuffer, Length, NULL, NULL, 0, Buffer, BufferSize, &LengthReturned, BCRYPT_BLOCK_PADDING);

	if (!NT_SUCCESS(Status))
	{
		//STATUS_BUFFER_TOO_SMALL
		DbgPrint("EptAesDecrypt BCryptDecrypt failed Status = %X.\n", Status);
		ExFreePoolWithTag(TempBuffer, ENCRYPT_TEMP_BUFFER);
		return FALSE;
	}

	ExFreePoolWithTag(TempBuffer, ENCRYPT_TEMP_BUFFER);
	return TRUE;
}