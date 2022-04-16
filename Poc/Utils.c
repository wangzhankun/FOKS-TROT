
#include "utils.h"
#include "global.h"
#include "context.h"
#include "import.h"
#include <wdm.h>


NTSTATUS PocGetFileNameOrExtension(
	IN PFLT_CALLBACK_DATA Data, 
	IN OUT PWCHAR FileExtension, 
	IN OUT PWCHAR FileName)
{

	NTSTATUS Status;
	PFLT_FILE_NAME_INFORMATION FileNameInfo = NULL;


	Status = FltGetFileNameInformation(
		Data, 
		FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, 
		&FileNameInfo);

	if (!NT_SUCCESS(Status)) 
	{
		if (STATUS_FLT_NAME_CACHE_MISS == Status)
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocGetFileExtension->FltGetFileNameInformation failed. Status = STATUS_FLT_NAME_CACHE_MISS\n"));
		}
		else
		{
			//PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocGetFileExtension->FltGetFileNameInformation failed. Status = 0x%x\n", Status));
		}
		return Status;
	}

	Status = FltParseFileNameInformation(FileNameInfo);

	if (STATUS_SUCCESS != Status)
	{
		goto EXIT;
	}

	if (NULL != FileExtension && 
		NULL != FileNameInfo->Extension.Buffer &&
		wcslen(FileNameInfo->Extension.Buffer) < POC_MAX_NAME_LENGTH)
	{
		RtlMoveMemory(FileExtension, FileNameInfo->Extension.Buffer, wcslen(FileNameInfo->Extension.Buffer) * sizeof(WCHAR));
	}
		
	if (NULL != FileName && 
		NULL != FileNameInfo->Name.Buffer &&
		wcslen(FileNameInfo->Name.Buffer) < POC_MAX_NAME_LENGTH)
	{
		RtlMoveMemory(FileName, FileNameInfo->Name.Buffer, wcslen(FileNameInfo->Name.Buffer) * sizeof(WCHAR));
	}
	
	//PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocGetFileExtension->FileName is %ws.\n", FileNameInfo->Name.Buffer);

EXIT:
	if (NULL != FileNameInfo)
	{
		FltReleaseFileNameInformation(FileNameInfo);
		FileNameInfo = NULL;
	}

	return Status;
}


ULONG PocQueryEndOfFileInfo(
	IN PFLT_INSTANCE Instance, 
	IN PFILE_OBJECT FileObject)
{

	FILE_STANDARD_INFORMATION StandardInfo = { 0 };
	ULONG LengthReturned = 0;
	NTSTATUS Status;

	Status = FltQueryInformationFile(Instance, FileObject, &StandardInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation, &LengthReturned);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocQueryEndOfFileInfo->FltQueryInformationFile failed. Status = 0x%x.\n", Status));
		return 0;
	}

	return StandardInfo.EndOfFile.LowPart;//FileInfo�����ܳ���4GB
}


NTSTATUS PocSetEndOfFileInfo(
	IN PFLT_INSTANCE Instance, 
	IN PFILE_OBJECT FileObject, 
	IN LONGLONG FileSize)
{
	FILE_END_OF_FILE_INFORMATION EndOfFileInfo = { 0 };
	NTSTATUS Status;

	EndOfFileInfo.EndOfFile.QuadPart = FileSize;

	Status = FltSetInformationFile(Instance, FileObject, &EndOfFileInfo, sizeof(FILE_END_OF_FILE_INFORMATION), FileEndOfFileInformation);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocQueryEndOfFileInfo->FltSetInformationFile failed. Status = 0x%x.\n", Status));
	}

	return Status;
}


USHORT PocQueryVolumeSectorSize(IN PFLT_VOLUME Volume)
{
	//Therefore, a minifilter driver commonly calls this routine from a post-mount callback function 
	//or an InstanceSetupCallback (PFLT_INSTANCE_SETUP_CALLBACK) routine to determine whether to attach to a given volume.

	UCHAR VolPropBuffer[sizeof(FLT_VOLUME_PROPERTIES) + 512] = { 0 };
	PFLT_VOLUME_PROPERTIES VolProp = (PFLT_VOLUME_PROPERTIES)VolPropBuffer;
	ULONG LengthReturned = 0;
	NTSTATUS Status;

	Status = FltGetVolumeProperties(Volume, VolProp, sizeof(VolPropBuffer), &LengthReturned);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocQueryVolumeSectorSize->FltGetVolumeProperties failed. Status = 0x%x.\n", Status));
		return 0;
	}

	return max(VolProp->SectorSize, MIN_SECTOR_SIZE);
}


NTSTATUS PocBypassBsodProcess(IN PFLT_CALLBACK_DATA Data)
/*
* ���������̻ᵼ����������û�н��������ֻ���Ⱥ��Ե�
* ��Ҫ��StreamContext��FltAllocateContext�������Լ�һЩExAllocatePoolWithTag��ExFreePool
* ������IRQL_NOT_LESS_OR_EQUAL���ڽϸߵ�IRQL���ʷ�ҳ�ڴ浼�µ�
*/
{

	NTSTATUS Status = 0;

	PEPROCESS eProcess = NULL;


	eProcess = FltGetRequestorProcess(Data);

	if (!eProcess) {

		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, 
			("%s->FltGetRequestorProcess failed.\n.", __FUNCTION__));
		return STATUS_UNSUCCESSFUL;
	}

	

	if (strncmp((PCHAR)PsGetProcessImageFileName(eProcess), "SearchUI.exe", strlen("SearchUI.exe")) == 0 ||
		strncmp((PCHAR)PsGetProcessImageFileName(eProcess), "RuntimeBroker.exe", strlen("RuntimeBroker.exe")) == 0)
	{
		Status = POC_IS_BSOD_PROCESS;
	}

	return Status;
}


NTSTATUS PocBypassIrrelevantPath(IN PWCHAR FileName)
/*
* ����������Ǳ�Ҫ�ģ���ΪһЩ�ؼ�·������Windows System32��·�����ǲ�Ӧ�ü��ܵ�
*/
{
	
	if (NULL == FileName)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocBypassWordBackupFile->FileName is NULL.\n"));
		return STATUS_INVALID_PARAMETER;
	}

	NTSTATUS Status = STATUS_SUCCESS;

	PWCHAR lpFileName = NULL;

	lpFileName = FileName;

	while (lpFileName < FileName + wcslen(FileName))
	{

		if (wcsncmp(lpFileName, L"Windows\\System32", wcslen(L"Windows\\System32")) == 0)
		{
			return POC_IS_IRRELEVENT_PATH;
		}

		lpFileName++;
	}

	return Status;
}


NTSTATUS PocParseFileNameExtension(
	IN PWCHAR FileName, 
	IN OUT PWCHAR FileExtension)
{
	if (NULL == FileName)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocParseFileNameExtension->FileName is NULL.\n"));
		return STATUS_INVALID_PARAMETER;
	}

	if (NULL == FileExtension)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocParseFileNameExtension->FileExtension is NULL.\n"));
		return STATUS_INVALID_PARAMETER;
	}

	PWCHAR lpExtension = NULL;

	lpExtension = FileName + wcslen(FileName);

	while (lpExtension > FileName)
	{
		if (*lpExtension == L'.' && wcslen(lpExtension) < POC_MAX_NAME_LENGTH)
		{
			lpExtension++;
			RtlMoveMemory(FileExtension, lpExtension, wcslen(lpExtension) * sizeof(WCHAR));
			return STATUS_SUCCESS;
		}

		lpExtension--;
	}

	return STATUS_UNSUCCESSFUL;
}


NTSTATUS PocBypassIrrelevantFileExtension(IN PWCHAR FileExtension)
/*
* ���˵���Ŀ����չ���ļ�
*/
{

	const static PWCHAR allowed_extension[] = { L"txt",
											   L"docx",
											   L"doc",
											   L"xlsx",
											   L"xls",
											   L"pptx",
											   L"ppt",
											   L"txt",
											   L"PNG",
											   L"JPG",
											   NULL };

	if (NULL == FileExtension)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocBypassIrrelevantFileExtension->FileExtension is NULL.\n"));
		return STATUS_INVALID_PARAMETER;
	}

	const PWCHAR* p = allowed_extension;
	while (*p)
	{
		if (0 == _wcsicmp(FileExtension, *p))
		{
			break;
		}
		p++;
	}
	if (*p)
	{
		return POC_IS_TARGET_FILE_EXTENSION;
	}
	else
	{
		return POC_IRRELEVENT_FILE_EXTENSION;
	}

	/*if (NULL == FileExtension)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocBypassIrrelevantFileExtension->FileExtension is NULL.\n"));
		return STATUS_INVALID_PARAMETER;
	}

	if (wcsncmp(FileExtension, L"txt", wcslen(L"txt")) != 0 &&
		wcsncmp(FileExtension, L"docx", wcslen(L"docx")) != 0 &&
		wcsncmp(FileExtension, L"doc", wcslen(L"doc")) != 0 &&
		wcsncmp(FileExtension, L"pptx", wcslen(L"pptx")) != 0 &&
		wcsncmp(FileExtension, L"ppt", wcslen(L"ppt")) != 0 &&
		wcsncmp(FileExtension, L"xlsx", wcslen(L"xlsx")) != 0 &&
		wcsncmp(FileExtension, L"xls", wcslen(L"xls")) != 0 &&
		wcsncmp(FileExtension, L"PNG", wcslen(L"PNG")) != 0 &&
		wcsncmp(FileExtension, L"JPG", wcslen(L"JPG")) != 0)
	{
		return POC_IRRELEVENT_FILE_EXTENSION;
	}
	else
	{
		return POC_IS_TARGET_FILE_EXTENSION;
	}*/

}


NTSTATUS PocQuerySymbolicLink(
	IN PUNICODE_STRING SymbolicLinkName, 
	OUT PUNICODE_STRING LinkTarget)
/*
* �ļ�·������תΪDOS��
* \\??\\c:-->\\device\\\harddiskvolume1
* LinkTarget.Bufferע��Ҫ�ͷ�
*/
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	HANDLE LinkHandle = NULL;

	InitializeObjectAttributes(
		&ObjectAttributes,
		SymbolicLinkName,
		OBJ_CASE_INSENSITIVE,
		0,
		0);

	Status = ZwOpenSymbolicLinkObject(&LinkHandle, GENERIC_READ, &ObjectAttributes);

	if (!NT_SUCCESS(Status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocQuerySymbolicLink->ZwOpenSymbolicLinkObject1 failed. Status = 0x%x.\n", Status));
		goto EXIT;
	}

	LinkTarget->MaximumLength = 260 * sizeof(WCHAR);
	LinkTarget->Length = 0;
	LinkTarget->Buffer = ExAllocatePoolWithTag(NonPagedPool, LinkTarget->MaximumLength, DOS_NAME_BUFFER_TAG);

	if (NULL == LinkTarget->Buffer)
	{
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto EXIT;
	}

	RtlZeroMemory(LinkTarget->Buffer, LinkTarget->MaximumLength);


	Status = ZwQuerySymbolicLinkObject(LinkHandle, LinkTarget, NULL);

	if (!NT_SUCCESS(Status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocQuerySymbolicLink->ZwOpenSymbolicLinkObject2 failed. Status = 0x%x.\n", Status));
		ExFreePoolWithTag(LinkTarget->Buffer, DOS_NAME_BUFFER_TAG);
	}

	Status = STATUS_SUCCESS;

EXIT:

	if (NULL != LinkHandle)
	{
		ZwClose(LinkHandle);
		LinkHandle = NULL;
	}

	return Status;
}


NTSTATUS PocGetVolumeInstance(
	IN PFLT_FILTER pFilter, 
	IN PUNICODE_STRING pVolumeName, 
	OUT PFLT_INSTANCE* Instance)
/*
* �õ���Ӧ���ʵ��
* pVolumeName->BufferӦ����ΪDos����ʾ�� L"\\Device\\HarddiskVolume2"
*/
{
	NTSTATUS		Status;
	PFLT_INSTANCE	pInstance = NULL;
	PFLT_VOLUME		pVolumeList[100];
	ULONG			uRet;
	UNICODE_STRING	uniName = { 0 };
	LONGLONG 			index = 0;
	WCHAR			wszNameBuffer[POC_MAX_NAME_LENGTH] = { 0 };

	Status = FltEnumerateVolumes(pFilter,
		NULL,
		0,
		&uRet);
	if (Status != STATUS_BUFFER_TOO_SMALL)
	{
		return Status;
	}

	Status = FltEnumerateVolumes(pFilter,
		pVolumeList,
		uRet,
		&uRet);

	if (!NT_SUCCESS(Status))
	{
		return Status;
	}
	uniName.Buffer = wszNameBuffer;

	if (uniName.Buffer == NULL)
	{
		for (index = 0; index < uRet; index++)
			FltObjectDereference(pVolumeList[index]);

		return STATUS_UNSUCCESSFUL;
	}

	uniName.MaximumLength = sizeof(wszNameBuffer);

	for (index = 0; index < uRet; index++)
	{
		uniName.Length = 0;

		Status = FltGetVolumeName(pVolumeList[index],
			&uniName,
			NULL);

		if (!NT_SUCCESS(Status))
			continue;

		if (RtlCompareUnicodeString(&uniName,
			pVolumeName,
			TRUE) != 0)
			continue;

		Status = FltGetVolumeInstanceFromName(pFilter,
			pVolumeList[index],
			NULL,
			&pInstance);

		if (NT_SUCCESS(Status))
		{
			FltObjectDereference(pInstance);
			break;
		}
	}

	for (index = 0; index < uRet; index++)
	{
		FltObjectDereference(pVolumeList[index]);
	}

	*Instance = pInstance;

	return Status;
}


NTSTATUS PocSymbolLinkPathToDosPath(
	IN PWCHAR Path, 
	IN OUT PWCHAR DosPath)
/*
* ���ļ��ķ���������ת��ΪDos��
*/
{
	if (NULL == Path)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Path is NULL.\n", __FUNCTION__));
		return STATUS_INVALID_PARAMETER;
	}

	if (NULL == DosPath)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->DosPath is NULL.\n", __FUNCTION__));
		return STATUS_INVALID_PARAMETER;
	}

	NTSTATUS Status = 0;

	UNICODE_STRING uSymbolLinkName = { 0 };
	WCHAR wSymbolLinkName[POC_MAX_NAME_LENGTH] = { 0 };

	PWCHAR lpPath = wSymbolLinkName;

	UNICODE_STRING uDosName = { 0 };

	RtlMoveMemory(wSymbolLinkName, L"\\??\\", wcslen(L"\\??\\") * sizeof(WCHAR));
	RtlMoveMemory(wSymbolLinkName + wcslen(wSymbolLinkName), Path, wcslen(Path) * sizeof(WCHAR));

	while (*lpPath != L':' &&
		lpPath < wSymbolLinkName + wcslen(wSymbolLinkName))
	{
		lpPath++;
	}

	RtlZeroMemory(lpPath + 1, wcslen(lpPath + 1) * sizeof(WCHAR));


	RtlInitUnicodeString(&uSymbolLinkName, wSymbolLinkName);

	Status = PocQuerySymbolicLink(
		&uSymbolLinkName,
		&uDosName);

	if (STATUS_SUCCESS != Status 
		|| NULL == uDosName.Buffer)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocQuerySymbolicLink failed ststus = 0x%x.\n", __FUNCTION__, Status));
		goto EXIT;
	}

	RtlMoveMemory(DosPath, uDosName.Buffer, wcslen(uDosName.Buffer) * sizeof(WCHAR));

	RtlMoveMemory(DosPath + wcslen(DosPath), Path + wcslen(L"C:"), wcslen(Path + wcslen(L"C:")) * sizeof(WCHAR));

	Status = STATUS_SUCCESS;

EXIT:
	if (NULL != uDosName.Buffer)
	{
		ExFreePool(uDosName.Buffer);
		uDosName.Buffer = NULL;
	}

	return Status;
}


VOID PocApcKernelRoutine(
	PKAPC Apc,
	PKNORMAL_ROUTINE* NormalRoutine,
	PVOID* NormalContext,
	PVOID* SystemArgument1,
	PVOID* SystemArgument2
)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	ExFreePoolWithTag(Apc, POC_KAPC_BUFFER_TAG);
}


NTSTATUS PocInjectApc(
	IN PKTHREAD Thread,
	IN KPROCESSOR_MODE ApcMode,
	IN PKNORMAL_ROUTINE NormalRoutine,
	IN PVOID NormalContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2)
{
	if (NULL == Thread)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Thread is null.\n", __FUNCTION__));
		return STATUS_INVALID_PARAMETER;
	}

	NTSTATUS Status = 0;
	PKAPC Apc = NULL;

	Apc = ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), POC_KAPC_BUFFER_TAG);

	if (NULL == Apc)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ExAllocatePoolWithTag Apc failed.\n", __FUNCTION__));
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto EXIT;
	}

	RtlZeroMemory(Apc, sizeof(KAPC));

	KeInitializeApc(
		Apc,
		Thread,
		OriginalApcEnvironment,
		PocApcKernelRoutine,
		NULL,
		NormalRoutine,
		ApcMode,
		NormalContext);

	if (!KeInsertQueueApc(Apc, SystemArgument1, SystemArgument2, 0))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->KeInsertQueueApc failed.\n", __FUNCTION__));
		Status = STATUS_UNSUCCESSFUL;
		goto EXIT;
	}

	Status = STATUS_SUCCESS;
	return Status;

EXIT:

	if (NULL != Apc)
	{
		ExFreePoolWithTag(Apc, POC_KAPC_BUFFER_TAG);
		Apc = NULL;
	}

	return Status;
}
