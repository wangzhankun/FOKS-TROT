#pragma once

#include "global.h"


typedef struct _POC_PAGE_TEMP_BUFFER
{
    // LONGLONG StartingVbo;
    LONGLONG StartingVbo;

    // LONGLONG ByteCount;
    LONGLONG ByteCount;

    PCHAR Buffer;

}POC_PAGE_TEMP_BUFFER, * PPOC_PAGE_TEMP_BUFFER;


//
//  Stream context data structure
//

typedef struct _POC_STREAM_CONTEXT 
{

    LONGLONG Flag;
    PWCHAR FileName;
    /*
    * FileSize�д�������==���Ĵ�С����Ϊд��ȥ��β��NonCachedIo���������������룬���ǽ���������д��
    * FileSize��Ҫ����������β������PostQueryInformation��PreRead��PostRead��ʹ��
    * FileSize����PostWrite�и��£�����PostClose��д��β�����Ա������������һ�δ��ļ�ʱ����β����ȡ��
    */
    //LONGLONG FileSize;
    LARGE_INTEGER FileSize;


    PSECTION_OBJECT_POINTERS OriginSectionObjectPointers;
    PSECTION_OBJECT_POINTERS ShadowSectionObjectPointers;

    BOOLEAN IsCipherText;

    //�������ڶ���������С�Ŀ����StreamContext->PageNextToLastForWrite��
    POC_PAGE_TEMP_BUFFER PageNextToLastForWrite;

    PERESOURCE Resource;

} POC_STREAM_CONTEXT, * PPOC_STREAM_CONTEXT;

#define POC_STREAM_CONTEXT_SIZE         sizeof(POC_STREAM_CONTEXT)
#define POC_RESOURCE_TAG                      'cRxC'
#define POC_STREAM_CONTEXT_TAG                'cSxC'

typedef struct _POC_STREAMHANDLE_CONTEXT
{
    BOOLEAN BeingWrite;

}POC_STREAMHANDLE_CONTEXT, * PPOC_STREAMHANDLE_CONTEXT;

#define POC_STREAMHANDLE_CONTEXT_SIZE   sizeof(POC_STREAMHANDLE_CONTEXT)
#define POC_STREAMHANDLE_CONTEXT_TAG            'SHxC'

typedef struct _POC_VOLUME_CONTEXT 
{

    //
    //  Holds the sector size for this volume.
    //

    ULONG SectorSize;//ÿ��sector�Ĵ�С���������

} POC_VOLUME_CONTEXT, * PPOC_VOLUME_CONTEXT;

#define MIN_SECTOR_SIZE 0x200
#define POC_VOLUME_CONTEXT_SIZE                 sizeof(POC_VOLUME_CONTEXT)
#define POC_VOLUME_CONTEXT_TAG                  'cVxC'


NTSTATUS PocCreateStreamContext(
    _In_ PFLT_FILTER FilterHandle, 
    _Outptr_ PPOC_STREAM_CONTEXT* StreamContext);

NTSTATUS
PocFindOrCreateStreamContext(
    IN PFLT_INSTANCE Instance,
    IN PFILE_OBJECT FileObject,
    _In_ BOOLEAN CreateIfNotFound,
    _Outptr_ PPOC_STREAM_CONTEXT* StreamContext,
    _Out_opt_ PBOOLEAN ContextCreated);

NTSTATUS PocCreateStreamHandleContext(
    _Outptr_ PPOC_STREAMHANDLE_CONTEXT* StreamHandleContext);

NTSTATUS
PocCreateOrReplaceStreamHandleContext(
    _In_ PFLT_CALLBACK_DATA Cbd,
    _In_ BOOLEAN ReplaceIfExists,
    _Outptr_ PPOC_STREAMHANDLE_CONTEXT* StreamHandleContext,
    _Out_opt_ PBOOLEAN ContextReplaced);

VOID PocContextCleanup(
    _In_ PFLT_CONTEXT Context, 
    _In_ FLT_CONTEXT_TYPE ContextType);

NTSTATUS PocUpdateNameInStreamContext(
    IN PPOC_STREAM_CONTEXT StreamContext,
    IN PWCHAR NewFileName);

VOID PocUpdateFlagInStreamContext(
    IN PPOC_STREAM_CONTEXT StreamContext,
    IN LONGLONG Flag);

