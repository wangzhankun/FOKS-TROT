

#include "cipher.h"
#include "global.h"

AES_INIT_VARIABLES AesInitVar;

NTSTATUS PocInitAesECBKey()
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	ULONG cbData = 0, cbKeyObject = 0;

	UCHAR rgbAES128Key[] =
		{
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

	RtlZeroMemory(&AesInitVar, sizeof(AES_INIT_VARIABLES));

	Status = BCryptOpenAlgorithmProvider(&AesInitVar.hAesAlg, BCRYPT_AES_ALGORITHM, NULL, BCRYPT_PROV_DISPATCH);

	if (!NT_SUCCESS(Status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocInitAesECBKey->BCryptOpenAlgorithmProvider failed. Status = 0x%x.\n", Status));
		goto ERROR;
	}

	/**
	 * NTSTATUS BCryptGetProperty(
		[in]  BCRYPT_HANDLE hObject,
		[in]  LPCWSTR       pszProperty,
		[out] PUCHAR        pbOutput,
		[in]  ULONG         cbOutput,
		[out] ULONG         *pcbResult,
		[in]  ULONG         dwFlags
		);
	 * [in] A handle that represents the CNG object to obtain the property value for.
	 * [in] A pointer to a null-terminated Unicode string that contains the name of the property to retrieve.
	 * [out] The address of a buffer that receives the property value. The cbOutput parameter contains the size of this buffer.
	 * [in] The size, in bytes, of the pbOutput buffer.
	 * [in] A pointer to a ULONG variable that receives the number of bytes that were copied to the pbOutput buffer.
	 * [in] A set of flags that modify the behavior of this function.
	*/
	Status = BCryptGetProperty(AesInitVar.hAesAlg,
							   BCRYPT_OBJECT_LENGTH,
							   (PUCHAR)&cbKeyObject,
							   sizeof(ULONG),
							   &cbData,
							   0);

	if (!NT_SUCCESS(Status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocInitAesECBKey->BCryptGetProperty failed. Status = 0x%x.\n", Status));
		goto ERROR;
	}

	AesInitVar.pbKeyObject = ExAllocatePoolWithTag(NonPagedPool, cbKeyObject, KEY_OBJECT_BUFFER);

	if (NULL == AesInitVar.pbKeyObject)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocInitAesECBKey->ExAllocatePoolWithTag pbKeyObject failed.\n"));
		goto ERROR;
	}

	Status = BCryptSetProperty(AesInitVar.hAesAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0);

	if (!NT_SUCCESS(Status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocInitAesECBKey->BCryptSetProperty failed. Status = 0x%x.\n", Status));
		goto ERROR;
	}

	Status = BCryptGenerateSymmetricKey(AesInitVar.hAesAlg, &AesInitVar.hKey, AesInitVar.pbKeyObject, cbKeyObject, rgbAES128Key, sizeof(rgbAES128Key), 0);

	if (!NT_SUCCESS(Status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocInitAesECBKey->BCryptGenerateSymmetricKey failed. Status = 0x%x.\n", Status));
		goto ERROR;
	}

	Status = STATUS_SUCCESS;
	AesInitVar.Flag = TRUE;
	goto EXIT;

ERROR:
	if (NULL != AesInitVar.hAesAlg)
	{
		BCryptCloseAlgorithmProvider(AesInitVar.hAesAlg, 0);
		AesInitVar.hAesAlg = 0;
	}

	if (NULL != AesInitVar.pbKeyObject)
	{
		ExFreePoolWithTag(AesInitVar.pbKeyObject, KEY_OBJECT_BUFFER);
		AesInitVar.pbKeyObject = NULL;
	}

	if (NULL != AesInitVar.hKey)
	{
		BCryptDestroyKey(AesInitVar.hKey);
		AesInitVar.hKey = NULL;
	}

	AesInitVar.Flag = FALSE;

EXIT:

	return Status;
}

VOID PocAesCleanup()
{
	if (!AesInitVar.Flag)
	{
		return;
	}

	if (NULL != AesInitVar.hAesAlg)
	{
		BCryptCloseAlgorithmProvider(AesInitVar.hAesAlg, 0);
		AesInitVar.hAesAlg = NULL;
	}

	if (NULL != AesInitVar.pbKeyObject)
	{
		ExFreePoolWithTag(AesInitVar.pbKeyObject, KEY_OBJECT_BUFFER);
		AesInitVar.pbKeyObject = NULL;
	}

	if (NULL != AesInitVar.hKey)
	{
		BCryptDestroyKey(AesInitVar.hKey);
		AesInitVar.hKey = NULL;
	}

	AesInitVar.Flag = FALSE;
}

NTSTATUS PocAesECBEncrypt(
	IN PCHAR InBuffer,
	IN ULONG InBufferSize,
	IN OUT PCHAR InOutBuffer,
	IN OUT PULONG LengthReturned)
{
	// LengthReturned�Ǹ��õģ��ڼ���ʱ������ΪInOutBuffer���ڴ��С���룬Ҳ��Ϊ���ܺ����Ĵ�С���

	if (!AesInitVar.Flag)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBEncrypt->AesInitVar.Flag = FALSE.\n"));
		return POC_STATUS_AES_INIT_FAILED;
	}

	if (NULL == InBuffer)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBEncrypt->InBuffer is NULL.\n"));
		return STATUS_INVALID_PARAMETER;
	}

	if (NULL == LengthReturned)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBEncrypt->LengthReturned is NULL.\n"));
		return STATUS_INVALID_PARAMETER;
	}

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	Status = BCryptEncrypt(AesInitVar.hKey,		//[in.out] BCRYPT_KEY_HANDLE  The handle of the key to use to encrypt the data.
						   (PUCHAR)InBuffer,	//[in] PUCHAR The address of a buffer that contains the plaintext to be encrypted.
						   InBufferSize,		//[in] ULONG The number of bytes in the pbInput buffer to encrypt.
						   NULL,				//[in, optional] pPaddingInfo
						   NULL,				//[in, out, optional] pbIV
						   0,					//[in] cbIV
						   (PUCHAR)InOutBuffer, //[out, optional] pbOutput The address of the buffer that receives the ciphertext produced by this function.
						   // The cbOutput parameter contains the size of this buffer. If this parameter is NULL, the BCryptEncrypt function
						   // calculates the size needed for the ciphertext of the data passed in the pbInput parameter.
						   *LengthReturned, //[in] cbOutput The size, in bytes, of the pbOutput buffer. This parameter is ignored if the pbOutput parameter is NULL.
						   LengthReturned,	// [out] pcbResult A pointer to a ULONG variable that receives the number of bytes copied to the pbOutput buffer
						   0);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBEncrypt->BCryptEncrypt encrypt plaintext failed. Status = 0x%x\n", Status));
	}

	return Status;
}

NTSTATUS PocAesECBDecrypt(
	IN PCHAR InBuffer,
	IN ULONG InBufferSize,
	IN OUT PCHAR InOutBuffer,
	IN OUT PULONG LengthReturned)
{

	if (!AesInitVar.Flag)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBDecrypt->AesInitVar.Flag = FALSE.\n"));
		return POC_STATUS_AES_INIT_FAILED;
	}

	if (NULL == InBuffer)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBDecrypt->InBuffer is NULL.\n"));
		return STATUS_INVALID_PARAMETER;
	}

	if (NULL == LengthReturned)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBDecrypt->LengthReturned is NULL.\n"));
		return STATUS_INVALID_PARAMETER;
	}

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	Status = BCryptDecrypt(AesInitVar.hKey,		//[in, out] hKey The handle of the key to use to decrypt the data.
						   (PUCHAR)InBuffer,	//[in] pbInput The address of a buffer that contains the ciphertext to be decrypted.
						   (ULONG)InBufferSize, //[in] ULONG cbInput The number of bytes in the pbInput buffer to decrypt.
						   NULL,
						   NULL,
						   0,
						   (PUCHAR)InOutBuffer, //[out, optional] PUCHAR pbOutput The address of the buffer that receives the plaintext produced by this function.
						   *LengthReturned,		// [in] ULONG cbOutput The size, in bytes, of the pbOutput buffer. This parameter is ignored if the pbOutput parameter is NULL.
						   LengthReturned,		//[out] pcbResult A pointer to a ULONG variable that receives the number of bytes copied to the pbOutput buffer
						   0);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBDecrypt->BCryptDecrypt decrypt ciphertext failed. Status = 0x%x\n", Status));
	}

	return Status;
}

NTSTATUS PocAesECBEncrypt_CiphertextStealing(
	IN PCHAR InBuffer,
	IN ULONG InBufferSize,
	IN OUT PCHAR InOutBuffer)
{
	if (!AesInitVar.Flag)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBEncrypt_CiphertextStealing->AesInitVar.Flag = FALSE.\n"));
		return POC_STATUS_AES_INIT_FAILED;
	}

	if (NULL == InBuffer)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBEncrypt_CiphertextStealing->InBuffer is NULL.\n"));
		return STATUS_INVALID_PARAMETER;
	}

	if (NULL == InOutBuffer)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBEncrypt_CiphertextStealing->InOutBuffer is NULL.\n"));
		return STATUS_INVALID_PARAMETER;
	}

	if (InBufferSize % AES_BLOCK_SIZE == 0 || InBufferSize < AES_BLOCK_SIZE)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBEncrypt_CiphertextStealing->Buffer is aligned with block size.\n"));
		return STATUS_UNSUCCESSFUL;
	}

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	ULONG TailLength = InBufferSize % AES_BLOCK_SIZE;
	ULONG LengthReturned = 0;
	ULONG Pn_1Offset = 0, PnOffset = 0;

	CHAR Pn[AES_BLOCK_SIZE] = {0};
	CHAR Cn_1[AES_BLOCK_SIZE] = {0};
	CHAR Cpadding[AES_BLOCK_SIZE] = {0};

	PCHAR AlignedBuffer = NULL;

	AlignedBuffer = ExAllocatePoolWithTag(NonPagedPool, (SIZE_T)InBufferSize - (SIZE_T)TailLength, WRITE_BUFFER_TAG);

	if (NULL == AlignedBuffer)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBEncrypt_CiphertextStealing->ExAllocatePoolWithTag AlignedBuffer failed.\\n"));
		Status = STATUS_UNSUCCESSFUL;
		goto EXIT;
	}

	RtlZeroMemory(AlignedBuffer, InBufferSize - TailLength);

	RtlMoveMemory(AlignedBuffer, InBuffer, InBufferSize - TailLength);

	LengthReturned = InBufferSize - TailLength;
	Status = PocAesECBEncrypt(
		AlignedBuffer,
		InBufferSize - TailLength,
		InOutBuffer,
		&LengthReturned);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBEncrypt_CiphertextStealing->PocAesECBEncrypt1 failed. Status = 0x%x\n", Status));
		goto EXIT;
	}

	Pn_1Offset = InBufferSize - TailLength - AES_BLOCK_SIZE;
	PnOffset = Pn_1Offset + AES_BLOCK_SIZE;

	// InOutBuffer + Pn_1Offset == Cn
	RtlMoveMemory(InOutBuffer + PnOffset, InOutBuffer + Pn_1Offset, TailLength);

	RtlMoveMemory(Cpadding, InOutBuffer + Pn_1Offset + TailLength, AES_BLOCK_SIZE - TailLength);

	RtlZeroMemory(InOutBuffer + Pn_1Offset, AES_BLOCK_SIZE);

	RtlMoveMemory(Pn, InBuffer + PnOffset, TailLength);
	RtlMoveMemory(Pn + TailLength, Cpadding, AES_BLOCK_SIZE - TailLength);

	LengthReturned = AES_BLOCK_SIZE;
	Status = PocAesECBEncrypt(
		Pn,
		AES_BLOCK_SIZE,
		Cn_1,
		&LengthReturned);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBEncrypt_CiphertextStealing->PocAesECBEncrypt2 failed. Status = 0x%x\n", Status));
		goto EXIT;
	}

	RtlMoveMemory(InOutBuffer + Pn_1Offset, Cn_1, AES_BLOCK_SIZE);

	Status = STATUS_SUCCESS;

EXIT:

	if (NULL != AlignedBuffer)
	{
		ExFreePoolWithTag(AlignedBuffer, WRITE_BUFFER_TAG);
		AlignedBuffer = NULL;
	}

	return Status;
}

NTSTATUS PocAesECBDecrypt_CiphertextStealing(
	IN PCHAR InBuffer,
	IN ULONG InBufferSize,
	IN OUT PCHAR InOutBuffer)
{
	if (!AesInitVar.Flag)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBDecrypt_CiphertextStealing->AesInitVar.Flag = FALSE.\n"));
		return POC_STATUS_AES_INIT_FAILED;
	}

	if (NULL == InBuffer)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBDecrypt_CiphertextStealing->InBuffer is NULL.\n"));
		return STATUS_INVALID_PARAMETER;
	}

	if (NULL == InOutBuffer)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBDecrypt_CiphertextStealing->InOutBuffer is NULL.\n"));
		return STATUS_INVALID_PARAMETER;
	}

	if (InBufferSize % AES_BLOCK_SIZE == 0 || InBufferSize < AES_BLOCK_SIZE)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBDecrypt_CiphertextStealing->Buffer is aligned with block size.\n"));
		return STATUS_UNSUCCESSFUL;
	}

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	ULONG TailLength = InBufferSize % AES_BLOCK_SIZE;
	ULONG LengthReturned = 0;
	ULONG Cn_1Offset = 0, CnOffset = 0;

	CHAR Cn[AES_BLOCK_SIZE] = {0};
	CHAR Pn_1[AES_BLOCK_SIZE] = {0};
	CHAR Cpadding[AES_BLOCK_SIZE] = {0};

	PCHAR AlignedBuffer = NULL;

	AlignedBuffer = ExAllocatePoolWithTag(NonPagedPool, (SIZE_T)InBufferSize - (SIZE_T)TailLength, READ_BUFFER_TAG);

	if (NULL == AlignedBuffer)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBDecrypt_CiphertextStealing->ExAllocatePoolWithTag AlignedBuffer failed.\n"));
		Status = STATUS_UNSUCCESSFUL;
		goto EXIT;
	}

	RtlZeroMemory(AlignedBuffer, InBufferSize - TailLength);

	RtlMoveMemory(AlignedBuffer, InBuffer, InBufferSize - TailLength);

	LengthReturned = InBufferSize - TailLength;
	Status = PocAesECBDecrypt(
		AlignedBuffer,
		InBufferSize - TailLength,
		InOutBuffer,
		&LengthReturned);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBDecrypt_CiphertextStealing->PocAesECBDecrypt1 failed. Status = 0x%x\n", Status));
		goto EXIT;
	}

	Cn_1Offset = InBufferSize - TailLength - AES_BLOCK_SIZE;
	CnOffset = Cn_1Offset + AES_BLOCK_SIZE;

	// InOutBuffer + Cn_1Offset == Pn
	RtlMoveMemory(InOutBuffer + CnOffset, InOutBuffer + Cn_1Offset, TailLength);

	RtlMoveMemory(Cpadding, InOutBuffer + Cn_1Offset + TailLength, AES_BLOCK_SIZE - TailLength);

	RtlZeroMemory(InOutBuffer + Cn_1Offset, AES_BLOCK_SIZE);

	RtlMoveMemory(Cn, InBuffer + CnOffset, TailLength);
	RtlMoveMemory(Cn + TailLength, Cpadding, AES_BLOCK_SIZE - TailLength);

	LengthReturned = AES_BLOCK_SIZE;
	Status = PocAesECBDecrypt(
		Cn,
		AES_BLOCK_SIZE,
		Pn_1,
		&LengthReturned);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBDecrypt_CiphertextStealing->PocAesECBDecrypt2 failed. Status = 0x%x\n", Status));
		goto EXIT;
	}

	RtlMoveMemory(InOutBuffer + Cn_1Offset, Pn_1, AES_BLOCK_SIZE);

	Status = STATUS_SUCCESS;

EXIT:

	if (NULL != AlignedBuffer)
	{
		ExFreePoolWithTag(AlignedBuffer, READ_BUFFER_TAG);
		AlignedBuffer = NULL;
	}

	return Status;
}

NTSTATUS PocStreamModeEncrypt(
	IN PCHAR InBuffer,
	IN ULONG InBufferSize,
	IN OUT PCHAR InOutBuffer)
{

	if (NULL == InBuffer)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocStreamModeEncrypt->InBuffer is NULL.\n"));
		return STATUS_INVALID_PARAMETER;
	}

	if (NULL == InOutBuffer)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocStreamModeEncrypt->InOutBuffer is NULL.\n"));
		return STATUS_INVALID_PARAMETER;
	}

	for (ULONG i = 0; i < InBufferSize; i++)
	{
		*(InOutBuffer + i) = *(InBuffer + i) ^ 0x77;
	}

	return STATUS_SUCCESS;
}

NTSTATUS PocStreamModeDecrypt(
	IN PCHAR InBuffer,
	IN LONGLONG InBufferSize,
	IN OUT PCHAR InOutBuffer)
{

	if (NULL == InBuffer)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocStreamModeDecrypt->InBuffer is NULL.\n"));
		return STATUS_INVALID_PARAMETER;
	}

	if (NULL == InOutBuffer)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocStreamModeDecrypt->InOutBuffer is NULL.\n"));
		return STATUS_INVALID_PARAMETER;
	}

	for (LONGLONG i = 0; i < InBufferSize; i++)
	{
		*(InOutBuffer + i) = *(InBuffer + i) ^ 0x77;
	}

	return STATUS_SUCCESS;
}

NTSTATUS PocComputeHash(
	IN PUCHAR Data,
	IN ULONG DataLength,
	IN OUT PUCHAR *DataDigestPointer,
	IN OUT ULONG *DataDigestLengthPointer)
{

	NTSTATUS Status = 0;

	BCRYPT_ALG_HANDLE HashAlgHandle = NULL;
	BCRYPT_HASH_HANDLE HashHandle = NULL;

	PUCHAR HashDigest = NULL;
	ULONG HashDigestLength = 0;

	ULONG ResultLength = 0;

	*DataDigestPointer = NULL;
	*DataDigestLengthPointer = 0;

	Status = BCryptOpenAlgorithmProvider(
		&HashAlgHandle,
		BCRYPT_SHA256_ALGORITHM,
		NULL,
		0);
	if (!NT_SUCCESS(Status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
					 ("%s->BCryptOpenAlgorithmProvider failed. Status = 0x%x.\n", __FUNCTION__, Status));
		goto cleanup;
	}

	Status = BCryptGetProperty(
		HashAlgHandle,
		BCRYPT_HASH_LENGTH,
		(PUCHAR)&HashDigestLength,
		sizeof(HashDigestLength),
		&ResultLength,
		0);
	if (!NT_SUCCESS(Status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
					 ("%s->BCryptGetProperty failed. Status = 0x%x.\n", __FUNCTION__, Status));
		goto cleanup;
	}

	HashDigest = (PUCHAR)ExAllocatePoolWithTag(PagedPool, HashDigestLength, READ_BUFFER_TAG);

	if (NULL == HashDigest)
	{
		Status = STATUS_NO_MEMORY;
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
					 ("%s->ExAllocatePoolWithTag failed. Status = 0x%x.\n", __FUNCTION__, Status));
		goto cleanup;
	}

	RtlZeroMemory(HashDigest, HashDigestLength);

	Status = BCryptCreateHash(
		HashAlgHandle,
		&HashHandle,
		NULL,
		0,
		NULL,
		0,
		0);
	if (!NT_SUCCESS(Status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
					 ("%s->BCryptCreateHash failed. Status = 0x%x.\n", __FUNCTION__, Status));
		goto cleanup;
	}

	Status = BCryptHashData(
		HashHandle,
		(PUCHAR)Data,
		DataLength,
		0);
	if (!NT_SUCCESS(Status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
					 ("%s->BCryptHashData failed. Status = 0x%x.\n", __FUNCTION__, Status));
		goto cleanup;
	}

	Status = BCryptFinishHash(
		HashHandle,
		HashDigest,
		HashDigestLength,
		0);
	if (!NT_SUCCESS(Status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
					 ("%s->BCryptFinishHash failed. Status = 0x%x.\n", __FUNCTION__, Status));
		goto cleanup;
	}

	*DataDigestPointer = HashDigest;
	HashDigest = NULL;
	*DataDigestLengthPointer = HashDigestLength;

	Status = STATUS_SUCCESS;

cleanup:

	if (NULL != HashDigest)
	{
		ExFreePool(HashDigest);
		HashDigest = NULL;
	}

	if (NULL != HashHandle)
	{
		Status = BCryptDestroyHash(HashHandle);
		HashHandle = NULL;
	}

	if (NULL != HashAlgHandle)
	{
		BCryptCloseAlgorithmProvider(HashAlgHandle, 0);
		HashAlgHandle = NULL;
	}

	return Status;
}
