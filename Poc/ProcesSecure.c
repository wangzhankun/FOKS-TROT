#pragma warning(disable:4996)

#include "processecure.h"
#include "process.h"
#include "utils.h"
#include "ldrreloc.h"
#include "cipher.h"

HANDLE gObjectHandle = NULL;

KSTART_ROUTINE PocProcessIntegrityCheckThread;


NTSTATUS PocProcessIntegrityCheck(
	IN PEPROCESS EProcess)
/*
* �Խ��̵Ĵ���ν���У��
*/
{

	if (NULL == EProcess)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->EProcess is NULL.\n", __FUNCTION__));
		return STATUS_INVALID_PARAMETER;
	}


	NTSTATUS Status = 0;

	PUNICODE_STRING uProcessName = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };

	HANDLE FileHandle = NULL;
	IO_STATUS_BLOCK IoStatus = { 0 };

	FILE_STANDARD_INFORMATION FileStandInfo;

	PCHAR ProcessBuffer = NULL;
	LARGE_INTEGER ByteOffset;

	PCHAR ProcessImage = NULL;
	PIMAGE_NT_HEADERS pHeaders = NULL;
	LONGLONG SizeOfProcessImage = 0;

	SIZE_T TextSectionVA = { 0 };
	SIZE_T TextSectionSize = { 0 };

	KAPC_STATE Apc;
	PCHAR OriginProcessImageBase = NULL;
	PPEB Peb = NULL;
	PPEB32 Peb32 = NULL;
	HANDLE hProcess = NULL;
	ULONG OldProt = 0;

	ULONG LengthReturned = 0;//���ڱ����ϣ�ĳ��ȣ��������
	PUCHAR Hash1 = NULL, Hash2 = NULL;


	Status = SeLocateProcessImageName(EProcess, &uProcessName);

	if (!NT_SUCCESS(Status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->SeLocateProcessImageName EProcess = %p failed. Status = 0x%x.\n",
				__FUNCTION__, EProcess, Status));

		goto EXIT;
	}

	/*
	* �����￪ʼ���ȶ��������еĽ����ļ�������ProcessBuffer��
	*/


	InitializeObjectAttributes(
		&ObjectAttributes, 
		uProcessName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, 
		NULL, 
		NULL);

	Status = ZwOpenFile(
		&FileHandle,
		FILE_GENERIC_READ,
		&ObjectAttributes,
		&IoStatus,
		FILE_SHARE_READ | FILE_SHARE_DELETE,
		FILE_NO_INTERMEDIATE_BUFFERING | FILE_SYNCHRONOUS_IO_NONALERT);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->ZwOpenFile failed. Status = 0x%x.", __FUNCTION__, Status));
		goto EXIT;
	}


	Status = ZwQueryInformationFile(
		FileHandle,
		&IoStatus,
		&FileStandInfo,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->ZwQueryInformationFile failed. Status = 0x%x.", __FUNCTION__, Status));
		goto EXIT;
	}

	ProcessBuffer = ExAllocatePoolWithTag(
		PagedPool,
		FileStandInfo.EndOfFile.QuadPart,
		READ_BUFFER_TAG);

	if (NULL == ProcessBuffer)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, 
			("%s->ExAllocatePoolWithTag ProcessBuffer failed.\n", __FUNCTION__));
		Status = STATUS_UNSUCCESSFUL;
		goto EXIT;
	}

	RtlZeroMemory(ProcessBuffer, FileStandInfo.EndOfFile.QuadPart);

	ByteOffset.QuadPart = 0;
	Status = ZwReadFile(
		FileHandle,
		NULL, 
		NULL, 
		NULL,
		&IoStatus,//[out] PIO_STATUS_BLOCK IoStatusBlock, Pointer to an IO_STATUS_BLOCK structure that receives the final completion status and information about the requested read operation.
		ProcessBuffer,//[out] PVOID Buffer, Pointer to the buffer that receives the data read from a file.
		(ULONG)FileStandInfo.EndOfFile.LowPart,//[in] ULONG Length, Specifies the number of bytes to read from the file.
		&ByteOffset,
		NULL);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->ZwReadFile failed. Status = 0x%x.", __FUNCTION__, Status));
		goto EXIT;
	}


	/*
	* ���ڰ�ȫ�ԵĿ��ǣ��������Դ����еĽ����ļ���һ�������У�飬��֤��֤ǩ��ɶ��
	* ��ʱû��
	*/


	/*
	* �Ѵ����еĽ����ļ�ProcessBuffer�����ڶ���ӳ�䵽ProcessImage��
	*/

	pHeaders= RtlImageNtHeader(ProcessBuffer);

	SizeOfProcessImage = HEADER_VAL_T(pHeaders, SizeOfImage);

	ProcessImage = ExAllocatePoolWithTag(
		PagedPool,
		HEADER_VAL_T(pHeaders, SizeOfImage),
		READ_BUFFER_TAG);

	if (NULL == ProcessImage)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->ExAllocatePoolWithTag ProcessImage failed.\n", __FUNCTION__));
		Status = STATUS_UNSUCCESSFUL;
		goto EXIT;
	}

	RtlZeroMemory(ProcessImage, HEADER_VAL_T(pHeaders, SizeOfImage));


	RtlCopyMemory(ProcessImage, ProcessBuffer, HEADER_VAL_T(pHeaders, SizeOfHeaders));




	PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHeaders + 1);
	if (IMAGE32(pHeaders))
		pFirstSection = (PIMAGE_SECTION_HEADER)((PIMAGE_NT_HEADERS32)pHeaders + 1);

	for (PIMAGE_SECTION_HEADER pSection = pFirstSection;
		pSection < pFirstSection + pHeaders->FileHeader.NumberOfSections;
		pSection++)
	{

		if (!(pSection->Characteristics & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)) ||
			pSection->SizeOfRawData == 0)
		{
			continue;
		}

		/*
		* ��¼.text�ڵ�ƫ�ƺʹ�С
		*/
		if (!_strnicmp((PCHAR)pSection->Name, ".text", strlen(".text")))
		{
			TextSectionVA = pSection->VirtualAddress;
			TextSectionSize = LONGLONG2ULONG(pSection->Misc.VirtualSize);
		}

		RtlCopyMemory(
			ProcessImage + pSection->VirtualAddress,
			ProcessBuffer + pSection->PointerToRawData,
			pSection->SizeOfRawData
		);
	}


	if (0 == TextSectionVA || 0 == TextSectionSize)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->TextSectionVA || TextSectionSize is null.\n", __FUNCTION__));
		Status = STATUS_UNSUCCESSFUL;
		goto EXIT;
	}



	/*
	* ���ӵ�Ŀ����̣���У��Ľ��̣��У���PEB�л�ȡImageBaseAddress
	* ˳��ͨ��PEB�ж�һ���Ƿ񱻵���
	*/
	KeStackAttachProcess(EProcess, &Apc);

	if (IMAGE32(pHeaders))
	{
		Peb32 = (PPEB32)PsGetProcessWow64Process(EProcess);

		if (NULL == Peb32)
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("%s->Peb32 is null.\n", __FUNCTION__));

			KeUnstackDetachProcess(&Apc);

			Status = STATUS_UNSUCCESSFUL;
			goto EXIT;
		}

		OriginProcessImageBase = (PCHAR)Peb32->ImageBaseAddress;

		if (TRUE == Peb32->BeingDebugged)
		{

			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("%s->BeingDebugged process = %ws.\n", __FUNCTION__, uProcessName->Buffer));

			/*
			* ����ѡ������ʲô������ֱ���������������̵�
			*/

			KeUnstackDetachProcess(&Apc);

			Status = STATUS_UNSUCCESSFUL;
			goto EXIT;
		}
	}
	else
	{
		Peb = PsGetProcessPeb(EProcess);

		if (NULL == Peb)
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("%s->Peb is null.\n", __FUNCTION__));

			KeUnstackDetachProcess(&Apc);

			Status = STATUS_UNSUCCESSFUL;
			goto EXIT;
		}

		OriginProcessImageBase = Peb->ImageBaseAddress;

		if (TRUE == Peb->BeingDebugged)
		{
		
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("%s->BeingDebugged process = %ws.\n", __FUNCTION__, uProcessName->Buffer));

			/*
			* ����ѡ������ʲô������ֱ���������������̵�
			*/

			KeUnstackDetachProcess(&Apc);

			Status = STATUS_UNSUCCESSFUL;
			goto EXIT;
		}
	}

	

	if (NULL == OriginProcessImageBase)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->OriginProcessImageBase is null.\n", __FUNCTION__));

		KeUnstackDetachProcess(&Apc);

		Status = STATUS_UNSUCCESSFUL;
		goto EXIT;
	}



	/*
	* �޸�Ŀ�����.text�ı������ĳɿɶ���ִ��
	*/
	Status = ObOpenObjectByPointer(
		EProcess,
		OBJ_KERNEL_HANDLE,
		NULL,
		0,
		*PsProcessType,
		KernelMode,
		&hProcess);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->ObOpenObjectByPointer failed. Status = 0x%x.\n", __FUNCTION__, Status));

		KeUnstackDetachProcess(&Apc);

		goto EXIT;
	}


	TextSectionSize = ROUND_TO_PAGES(TextSectionSize);
	PVOID TextAddr = OriginProcessImageBase + TextSectionVA;

	Status = ZwProtectVirtualMemory(
		hProcess, 
		&TextAddr,
		&TextSectionSize,
		PAGE_EXECUTE_READ,
		&OldProt);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->ZwProtectVirtualMemory1 failed. Status = 0x%x.\n", __FUNCTION__, Status));

		KeUnstackDetachProcess(&Apc);

		goto EXIT;
	}

	/*
	* ����Ŀ�����.text�Ĺ�ϣ
	*/
	Status = PocComputeHash(
		(PUCHAR)OriginProcessImageBase + TextSectionVA, 
		(ULONG)TextSectionSize, 
		&Hash1, 
		&LengthReturned);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->PocComputeHash1 failed. Status = 0x%x.\n", __FUNCTION__, Status));

		KeUnstackDetachProcess(&Apc);

		goto EXIT;
	}


	Status = ZwProtectVirtualMemory(
		hProcess,
		&TextAddr,
		&TextSectionSize,
		OldProt,
		&OldProt);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->ZwProtectVirtualMemory2 failed. Status = 0x%x.\n", __FUNCTION__, Status));

		KeUnstackDetachProcess(&Apc);

		goto EXIT;
	}

	
	KeUnstackDetachProcess(&Apc);
	

	/*
	* �Դ���ӳ��Ľ����ļ�ProcessImage�����ض�λ
	*/
	Status = LdrRelocateImage(
		ProcessImage,
		OriginProcessImageBase,
		STATUS_SUCCESS,
		STATUS_CONFLICTING_ADDRESSES,
		STATUS_INVALID_IMAGE_FORMAT);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->LdrRelocateImage failed. Status = 0x%x.\n", __FUNCTION__, Status));
		goto EXIT;
	}


	Status = PocComputeHash(
		(PUCHAR)ProcessImage + TextSectionVA,
		(ULONG)TextSectionSize,
		&Hash2,
		&LengthReturned);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->PocComputeHash2 failed. Status = 0x%x.\n", __FUNCTION__, Status));
		goto EXIT;
	}

	if (0 != strncmp((PCHAR)Hash1, (PCHAR)Hash2, LengthReturned))
	{
		Status = POC_PROCESS_INTEGRITY_DAMAGE;
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->Integrity check failed. Process %ws .text inconsistent.\n", __FUNCTION__, uProcessName->Buffer));

		/*
		* ����ѡ������ʲô������ֱ���������������̵�
		*/

		goto EXIT;
	}
	else
	{
		Status = STATUS_SUCCESS;
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->Integrity check success. Process %ws .text consistent.\n", __FUNCTION__, uProcessName->Buffer));
		goto EXIT;
	}



EXIT:

	if (NULL != uProcessName)
	{
		ExFreePool(uProcessName);
		uProcessName = NULL;
	}

	if (NULL != FileHandle) 
	{
		ZwClose(FileHandle);
		FileHandle = NULL;
	}

	if (NULL != ProcessBuffer)
	{
		ExFreePoolWithTag(ProcessBuffer, READ_BUFFER_TAG);
		ProcessBuffer = NULL;
	}

	if (NULL != ProcessImage)
	{
		ExFreePoolWithTag(ProcessImage, READ_BUFFER_TAG);
		ProcessImage = NULL;
	}

	if (NULL != hProcess)
	{
		ZwClose(hProcess);
		hProcess = NULL;
	}

	if (NULL != Hash1)
	{
		ExFreePool(Hash1);
		Hash1 = NULL;
	}

	if (NULL != Hash2)
	{
		ExFreePool(Hash2);
		Hash2 = NULL;
	}

	return Status;
}


VOID PocProcessIntegrityCheckThread(
	IN PVOID StartContext)
{

	UNREFERENCED_PARAMETER(StartContext);

	NTSTATUS Status = STATUS_SUCCESS;

	LARGE_INTEGER Interval = { 0 };
	Interval.QuadPart = -100 * 1000 * 1000;

	/*
	* �̻߳���PocProcessCleanup()�ͷŵ�gObjectHandle���˳�ѭ��
	*/
	
	while (NULL != gObjectHandle)
	{

		Status = KeDelayExecutionThread(KernelMode, FALSE, &Interval);

		if (NULL == gObjectHandle)
		{
			break;
		}

		PocFindProcessInfoNodeByPidEx(NULL,
			NULL,
			FALSE,
			TRUE);
	}


	PsTerminateSystemThread(Status);
}


OB_PREOP_CALLBACK_STATUS PocPreObjectOperation(
	_In_ PVOID RegistrationContext,
	_Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(OperationInformation);

	PAGED_CODE();

	OB_PREOP_CALLBACK_STATUS Status = { 0 };

	HANDLE ProcessId = NULL;
	PPOC_CREATED_PROCESS_INFO OutProcessInfo = NULL;

	HANDLE RequestProcessId = NULL;
	PEPROCESS RequestEProcess = NULL;
	PUNICODE_STRING uProcessName = NULL;

	WCHAR CsrssDosPath[POC_MAX_NAME_LENGTH] = { 0 };
	WCHAR SvchostDosPath[POC_MAX_NAME_LENGTH] = { 0 };
	WCHAR ExplorerDosPath[POC_MAX_NAME_LENGTH] = { 0 };
	WCHAR WmiPrvSEDosPath[POC_MAX_NAME_LENGTH] = { 0 };
	WCHAR TaskmgrDosPath[POC_MAX_NAME_LENGTH] = { 0 };
	WCHAR LsassDosPath[POC_MAX_NAME_LENGTH] = { 0 };


	if (*PsProcessType == OperationInformation->ObjectType)
	{
		ProcessId = PsGetProcessId(OperationInformation->Object);

		if (NULL == ProcessId)
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("%s->PsGetProcessId EProcess = %p failed. Status = 0x%x.\n",
					__FUNCTION__,
					OperationInformation->Object,
					Status));

			goto EXIT;
		}
	}
	else if (*PsThreadType == OperationInformation->ObjectType)
	{
		ProcessId = PsGetThreadProcessId(OperationInformation->Object);

		if (NULL == ProcessId)
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("%s->PsGetThreadProcessId EThread = %p failed. Status = 0x%x.\n",
					__FUNCTION__,
					OperationInformation->Object,
					Status));

			goto EXIT;
		}
	}
	

	Status = PocFindProcessInfoNodeByPidEx(ProcessId, &OutProcessInfo, FALSE, FALSE);

	if (STATUS_SUCCESS != Status)
	{
		goto EXIT;
	}

	/*
	* �ȵ����̵ĵ�һ���̴߳����ٹ���Object��������̴�����ʧ��
	*/
	if (FALSE == OutProcessInfo->ThreadStartUp)
	{
		goto EXIT;
	}

	/*
	* ����ǽ����Լ����̶߳�дObject���Ź�
	*/
	RequestProcessId = PsGetThreadProcessId((PETHREAD)PsGetCurrentThread());

	if (RequestProcessId == ProcessId)
	{
		goto EXIT;
	}

	if (TRUE == OperationInformation->KernelHandle)
	{
		goto EXIT;
	}


	/*
	* �������Ľ����Ѿ��ڽ��������У�����Ĭ�����ǰ�ȫ�ģ��Ź�
	*/
	Status = PocFindProcessInfoNodeByPidEx(RequestProcessId, NULL, FALSE, FALSE);

	if (STATUS_SUCCESS == Status)
	{
		goto EXIT;
	}

	/*
	* ��һЩϵͳ���̷Ź�����ֹ�����޷�������
	* ����Ӧ�ö�csrss.exe lsass.exe�ľ�����н�Ȩ����룬����ֱ��ע��dll
	*/
	Status = PsLookupProcessByProcessId(RequestProcessId, &RequestEProcess);

	if (!NT_SUCCESS(Status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PsLookupProcessByProcessId RequestProcessId = %I64d failed. Status = 0x%x.\n",
			__FUNCTION__,
			(LONGLONG)RequestProcessId,
			Status));

		goto EXIT;
	}


	Status = SeLocateProcessImageName(RequestEProcess, &uProcessName);

	if (!NT_SUCCESS(Status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->SeLocateProcessImageName EProcess = %p failed. Status = 0x%x.\n",
				__FUNCTION__, RequestEProcess, Status));

		goto EXIT;
	}





	Status = PocSymbolLinkPathToDosPath(POC_CSRSS_PATH, CsrssDosPath);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, 
			("%s->PocSymbolLinkPathToDosPath EProcess = %p failed. Status = 0x%x.\n", 
				__FUNCTION__, RequestEProcess, Status));

		goto EXIT;
	}

	Status = PocSymbolLinkPathToDosPath(POC_SVCHOST_PATH, SvchostDosPath);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->PocSymbolLinkPathToDosPath EProcess = %p failed. Status = 0x%x.\n",
				__FUNCTION__, RequestEProcess, Status));

		goto EXIT;
	}

	Status = PocSymbolLinkPathToDosPath(POC_EXPLORER_PATH, ExplorerDosPath);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->PocSymbolLinkPathToDosPath EProcess = %p failed. Status = 0x%x.\n",
				__FUNCTION__, RequestEProcess, Status));

		goto EXIT;
	}

	Status = PocSymbolLinkPathToDosPath(POC_WMIPRVSE_PATH, WmiPrvSEDosPath);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->PocSymbolLinkPathToDosPath EProcess = %p failed. Status = 0x%x.\n",
				__FUNCTION__, RequestEProcess, Status));

		goto EXIT;
	}

	Status = PocSymbolLinkPathToDosPath(POC_TASKMGR_PATH, TaskmgrDosPath);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->PocSymbolLinkPathToDosPath EProcess = %p failed. Status = 0x%x.\n",
				__FUNCTION__, RequestEProcess, Status));

		goto EXIT;
	}

	Status = PocSymbolLinkPathToDosPath(POC_LSASS_PATH, LsassDosPath);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->PocSymbolLinkPathToDosPath EProcess = %p failed. Status = 0x%x.\n",
				__FUNCTION__, RequestEProcess, Status));

		goto EXIT;
	}


	if (!_wcsnicmp(CsrssDosPath, uProcessName->Buffer, uProcessName->Length / sizeof(WCHAR)) ||
		!_wcsnicmp(SvchostDosPath, uProcessName->Buffer, uProcessName->Length / sizeof(WCHAR)) ||
		!_wcsnicmp(ExplorerDosPath, uProcessName->Buffer, uProcessName->Length / sizeof(WCHAR)) ||
		!_wcsnicmp(WmiPrvSEDosPath, uProcessName->Buffer, uProcessName->Length / sizeof(WCHAR)) ||
		!_wcsnicmp(TaskmgrDosPath, uProcessName->Buffer, uProcessName->Length / sizeof(WCHAR)) ||
		!_wcsnicmp(LsassDosPath, uProcessName->Buffer, uProcessName->Length / sizeof(WCHAR)))
	{
		goto EXIT;
	}



	if (OB_OPERATION_HANDLE_CREATE == OperationInformation->Operation)
	{

		if (FlagOn(OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess,
			PROCESS_VM_OPERATION))
				ClearFlag(OperationInformation->Parameters->CreateHandleInformation.DesiredAccess,
					PROCESS_VM_OPERATION);

		if (FlagOn(OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess,
			PROCESS_VM_READ))
			ClearFlag(OperationInformation->Parameters->CreateHandleInformation.DesiredAccess,
				PROCESS_VM_READ);

		if (FlagOn(OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess,
			PROCESS_VM_WRITE))
			ClearFlag(OperationInformation->Parameters->CreateHandleInformation.DesiredAccess,
				PROCESS_VM_WRITE);

		if (FlagOn(OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess,
			PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE))
		{
		}

	}
	else if (OB_OPERATION_HANDLE_DUPLICATE == OperationInformation->Operation)
	{

		if (FlagOn(OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess,
			PROCESS_VM_OPERATION))
			ClearFlag(OperationInformation->Parameters->CreateHandleInformation.DesiredAccess,
				PROCESS_VM_OPERATION);

		if (FlagOn(OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess,
			PROCESS_VM_READ))
			ClearFlag(OperationInformation->Parameters->CreateHandleInformation.DesiredAccess,
				PROCESS_VM_READ);

		if (FlagOn(OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess,
			PROCESS_VM_WRITE))
			ClearFlag(OperationInformation->Parameters->CreateHandleInformation.DesiredAccess,
				PROCESS_VM_WRITE);

		if (FlagOn(OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess,
			PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE))
		{
		}
			
	}

EXIT:

	if (NULL != RequestEProcess)
	{
		ObDereferenceObject(RequestEProcess);
		RequestEProcess = NULL;
	}

	if (NULL != uProcessName)
	{
		ExFreePool(uProcessName);
		uProcessName = NULL;
	}

	Status = OB_PREOP_SUCCESS;

	return Status;
}


VOID PocProcessNotifyRoutineEx(
	IN PEPROCESS Process,
	IN HANDLE ProcessId,
	IN PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	UNREFERENCED_PARAMETER(Process);
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(CreateInfo);

	NTSTATUS Status = 0;
	PUNICODE_STRING uProcessName = NULL;

	PPOC_PROCESS_RULES OutProcessRules = NULL;
	PPOC_CREATED_PROCESS_INFO OutProcessInfo = NULL;


	Status = SeLocateProcessImageName(Process, &uProcessName);

	if (!NT_SUCCESS(Status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->SeLocateProcessImageName EProcess = %p failed. Status = 0x%x.\n",
				__FUNCTION__, Process, Status));

		goto EXIT;
	}


	Status = PocFindProcessRulesNodeByName(
		uProcessName->Buffer,
		&OutProcessRules,
		FALSE);

	if (STATUS_SUCCESS != Status)
	{
		goto EXIT;
	}


	if (NULL == CreateInfo)
	{

		PocFindProcessInfoNodeByPid(
			ProcessId,
			OutProcessRules,
			NULL,
			TRUE);

		if (STATUS_SUCCESS != Status)
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("%s->PocFindProcessInfoNodeByPid ProcessName = %ws ProcessId = %I64d failed. Status = 0x%x.\n",
					__FUNCTION__,
					uProcessName->Buffer,
					(LONGLONG)ProcessId,
					Status));

			goto EXIT;
		}

	}
	else
	{


		Status = PocCreateProcessInfoNode(
			OutProcessRules,
			&OutProcessInfo);

		if (STATUS_SUCCESS != Status)
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("%s->PocCreateProcessInfoNode ProcessName = %ws failed. Status = 0x%x.\n",
					__FUNCTION__,
					uProcessName->Buffer,
					Status));

			goto EXIT;
		}

		OutProcessInfo->ProcessId = ProcessId;

	}

EXIT:

	if (NULL != uProcessName)
	{
		ExFreePool(uProcessName);
		uProcessName = NULL;
	}

	return;
}


VOID PocLoadImageNotifyRoutine(
	IN PUNICODE_STRING FullImageName,
	IN HANDLE ProcessId,
	IN PIMAGE_INFO ImageInfo)
{
	UNREFERENCED_PARAMETER(FullImageName);
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(ImageInfo);

	if (0 == ProcessId)
	{
		return;
	}

	NTSTATUS Status = 0;
	PPOC_CREATED_PROCESS_INFO OutProcessInfo = NULL;

	Status = PocFindProcessInfoNodeByPidEx(ProcessId, &OutProcessInfo, FALSE, FALSE);

	if (STATUS_SUCCESS != Status)
	{
		goto EXIT;
	}

	if (FALSE == OutProcessInfo->ThreadStartUp)
	{
		OutProcessInfo->ThreadStartUp = TRUE;
	}

EXIT:

	return;
}


NTSTATUS PocProcessObjectCallbackInit()
{
	NTSTATUS Status = 0;

	OB_CALLBACK_REGISTRATION ObCallbackRegistration = { 0 };
	OB_OPERATION_REGISTRATION ObOperationRegistration[2] = { 0 };


	ObOperationRegistration[0].ObjectType = PsProcessType;
	ObOperationRegistration[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	ObOperationRegistration[0].PreOperation = (POB_PRE_OPERATION_CALLBACK)(&PocPreObjectOperation);

	ObOperationRegistration[1].ObjectType = PsThreadType;
	ObOperationRegistration[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	ObOperationRegistration[1].PreOperation = (POB_PRE_OPERATION_CALLBACK)(&PocPreObjectOperation);


	ObCallbackRegistration.Version = ObGetFilterVersion();
	ObCallbackRegistration.OperationRegistrationCount = 2;
	ObCallbackRegistration.RegistrationContext = NULL;
	RtlInitUnicodeString(&ObCallbackRegistration.Altitude, L"141001");
	ObCallbackRegistration.OperationRegistration = ObOperationRegistration;

	Status = ObRegisterCallbacks(&ObCallbackRegistration, &gObjectHandle);

	if (!NT_SUCCESS(Status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ObRegisterCallbacks failed. Status = 0x%x.\n",
			__FUNCTION__,
			Status));

		goto EXIT;
	}

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("%s->ObRegisterCallbacks register process and thread object success.\n", __FUNCTION__));

EXIT:

	return Status;
}


NTSTATUS PocProcessInit()
{
	NTSTATUS Status = 0;

	PCHAR SystemInfomation = NULL;
	LONGLONG SystemInformationLength = 0;
	ULONG ReturnedLength = 0;

	PSYSTEM_PROCESS_INFORMATION ProcessInfo = NULL;
	LONGLONG TotalOffset = 0;

	PEPROCESS EProcess = NULL;
	PUNICODE_STRING uProcessName = NULL;

	PPOC_PROCESS_RULES OutProcessRules = NULL;
	PPOC_CREATED_PROCESS_INFO OutProcessInfo = NULL;

	HANDLE ThreadHandle = NULL;


	Status = PocProcessRulesListInit();

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, 
			("%s->PocProcessRulesListInit failed. Status = 0x%x.", __FUNCTION__, Status));
		goto EXIT;
	}


	Status = PocProcessObjectCallbackInit();

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->PocProcessObjectCallbackInit failed. Status = 0x%x.", __FUNCTION__, Status));
		goto EXIT;
	}
	

	Status = PsSetCreateProcessNotifyRoutineEx(
		PocProcessNotifyRoutineEx,
		FALSE);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, 
			("%s->PsSetCreateProcessNotifyRoutineEx failed. Status = 0x%x.\n", __FUNCTION__, Status));
		goto EXIT;
	}

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, 
		("%s->PsSetCreateProcessNotifyRoutineEx success.\n", __FUNCTION__));


	/*
	* ����һ��PsSetCreateProcessNotifyRoutineEx���֮ǰ�ʹ����Ľ��̣�
	* ������ProcessRules�Ľ��̼��뵽������
	*/

	Status = NtQuerySystemInformation(
		SystemProcessInformation, 
		SystemInfomation, 
		LONGLONG2ULONG(SystemInformationLength), 
		&ReturnedLength);

	if (STATUS_SUCCESS != Status && STATUS_INFO_LENGTH_MISMATCH != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->NtQuerySystemInformation1 failed. Status = 0x%x.\n", __FUNCTION__, Status));
		goto EXIT;
	}

	SystemInformationLength = (LONGLONG)(ReturnedLength) * 2;

	SystemInfomation = ExAllocatePoolWithTag(
		NonPagedPool,
		SystemInformationLength,
		POC_PR_LIST_TAG);

	if (NULL == SystemInfomation)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ExAllocatePoolWithTag SystemInfomation failed.\n", __FUNCTION__));
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto EXIT;
	}

	RtlZeroMemory(SystemInfomation, SystemInformationLength);

	Status = NtQuerySystemInformation(
		SystemProcessInformation,
		SystemInfomation,
		LONGLONG2ULONG(SystemInformationLength),
		&ReturnedLength);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->NtQuerySystemInformation2 failed. Status = 0x%x.\n", __FUNCTION__, Status));
		goto EXIT;
	}

	ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)SystemInfomation;

	while (TRUE)
	{

		Status = PsLookupProcessByProcessId(ProcessInfo->UniqueProcessId, &EProcess);

		if (!NT_SUCCESS(Status))
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PsLookupProcessByProcessId UniqueProcessId = %I64d failed. Status = 0x%x.\n",
				__FUNCTION__,
				(LONGLONG)ProcessInfo->UniqueProcessId,
				Status));

			goto ERROR;
		}

		Status = SeLocateProcessImageName(EProcess, &uProcessName);

		if (!NT_SUCCESS(Status))
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("%s->SeLocateProcessImageName EProcess = %p failed. Status = 0x%x.\n",
					__FUNCTION__, EProcess, Status));

			goto ERROR;
		}


		Status = PocFindProcessRulesNodeByName(
			uProcessName->Buffer,
			&OutProcessRules,
			FALSE);

		if (STATUS_SUCCESS != Status)
		{
			goto ERROR;
		}

		Status = PocCreateProcessInfoNode(
			OutProcessRules,
			&OutProcessInfo);

		if (STATUS_SUCCESS != Status)
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("%s->PocCreateProcessInfoNode ProcessName = %ws failed. Status = 0x%x.\n",
					__FUNCTION__,
					uProcessName->Buffer,
					Status));

			goto ERROR;
		}

		OutProcessInfo->ProcessId = ProcessInfo->UniqueProcessId;

		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->Add ProcessName = %ws ProcessId = %lld Access = %lld success.\n",
				__FUNCTION__,
				uProcessName->Buffer,
				(LONGLONG)ProcessInfo->UniqueProcessId,
				OutProcessRules->Access));


ERROR:
		if (NULL != EProcess)
		{
			ObDereferenceObject(EProcess);
			EProcess = NULL;
		}

		if (NULL != uProcessName)
		{
			ExFreePool(uProcessName);
			uProcessName = NULL;
		}

		OutProcessRules = NULL;
		OutProcessInfo = NULL;

		if (ProcessInfo->NextEntryOffset == 0) 
		{
			break;
		}
		else 
		{
			TotalOffset += ProcessInfo->NextEntryOffset;
			ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)&SystemInfomation[TotalOffset];
		}

	}



	Status = PsSetLoadImageNotifyRoutine(
		PocLoadImageNotifyRoutine);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, 
			("%s->PsSetLoadImageNotifyRoutine failed. Status = 0x%x.\n", __FUNCTION__, Status));
		goto EXIT;
	}

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("%s->PsSetLoadImageNotifyRoutine success.\n", __FUNCTION__));


	/*
	* ����.text�����Լ��
	*/

	Status = PsCreateSystemThread(
		&ThreadHandle,
		THREAD_ALL_ACCESS,
		NULL,
		NULL,
		NULL,
		PocProcessIntegrityCheckThread,
		NULL);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->PsCreateSystemThread PocProcessIntegrityCheckThread failed. Status = 0x%x.\n",
				__FUNCTION__,
				Status));

		goto EXIT;
	}

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("%s->PsCreateSystemThread PocProcessIntegrityCheckThread init success.\n", __FUNCTION__));

	if (NULL != ThreadHandle)
	{
		ZwClose(ThreadHandle);
		ThreadHandle = NULL;
	}


	if (NULL != SystemInfomation)
	{
		ExFreePoolWithTag(SystemInfomation, POC_PR_LIST_TAG);
		SystemInfomation = NULL;
	}

	return Status;

EXIT:


	PocProcessCleanup();

	return Status;
}


VOID PocProcessCleanup()
{
	NTSTATUS Status = 0;
	LARGE_INTEGER Interval = { 0 };


	Status = PsSetCreateProcessNotifyRoutineEx(
		PocProcessNotifyRoutineEx,
		TRUE);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, 
			("%s->PsSetCreateProcessNotifyRoutineEx Remove failed. Status = 0x%x.\n", __FUNCTION__, Status));
	}

	Status = PsRemoveLoadImageNotifyRoutine(
		PocLoadImageNotifyRoutine);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->PsRemoveLoadImageNotifyRoutine failed. Status = 0x%x.\n", __FUNCTION__, Status));
	}


	if (NULL != gObjectHandle)
	{
		ObUnRegisterCallbacks(gObjectHandle);
		gObjectHandle = NULL;
	}

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("%s->Wait 12 seconds for PocProcessIntegrityCheckThread to exit. \n", __FUNCTION__));

	Interval.QuadPart = -120 * 1000 * 1000;

	Status = KeDelayExecutionThread(KernelMode, FALSE, &Interval);


	PocProcessRulesListCleanup();

}
