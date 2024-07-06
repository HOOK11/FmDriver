#include<ntifs.h>
#include "SsdtIndex.h"
#include "Search.h"
NTSTATUS GetNtModuleBaseAndSize(ULONG64* pModule, ULONG64* pSize)
{
	if (pModule == NULL || pSize == NULL) return STATUS_UNSUCCESSFUL;
	ULONG BufferSize = PAGE_SIZE * 64;
	PVOID Buffer = ExAllocatePool(PagedPool, BufferSize);
	ULONG ReturnLength;
	NTSTATUS Status = ZwQuerySystemInformation(SystemModuleInformation,
		Buffer,
		BufferSize,
		&ReturnLength
	);

	if (Status == STATUS_INFO_LENGTH_MISMATCH) {
		ExFreePool(Buffer);
		return STATUS_INFO_LENGTH_MISMATCH;
	}

	PRTL_PROCESS_MODULES            Modules;
	PRTL_PROCESS_MODULE_INFORMATION ModuleInfo;
	Modules = (PRTL_PROCESS_MODULES)Buffer;
	ModuleInfo = &(Modules->Modules[0]);
	*pModule = (ULONG64)ModuleInfo->ImageBase;
	*pSize = ModuleInfo->ImageSize;

	ExFreePool(Buffer);

	return Status;
}




SSDTStruct* SSSDTFind()
{
	static SSDTStruct* SSSDT = 0;
	if (!SSSDT)
	{
#ifndef _WIN64
		//x86 code
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"KeServiceDescriptorTable");
		SSSDT = (SSDTStruct*)MmGetSystemRoutineAddress(&routineName);
#else
		//x64 code
		ULONG64 kernelSize;
		ULONG_PTR kernelBase = 0;
		GetNtModuleBaseAndSize(&kernelBase, &kernelSize);
		if (!kernelBase)
		{
			return NULL;
		}

		// Find KiSystemServiceStart
		const unsigned char KiSystemServiceStartPattern[] = { 0x8B, 0xF8, 0xC1, 0xEF, 0x07, 0x83, 0xE7, 0x20, 0x25, 0xFF, 0x0F, 0x00, 0x00 };
		const ULONG signatureSize = sizeof(KiSystemServiceStartPattern);
		BOOLEAN found = FALSE;
		ULONG KiSSSOffset;
		for (KiSSSOffset = 0; KiSSSOffset < kernelSize - signatureSize; KiSSSOffset++)
		{
			if (RtlCompareMemory(((unsigned char*)kernelBase + KiSSSOffset), KiSystemServiceStartPattern, signatureSize) == signatureSize)
			{
				found = TRUE;
				break;
			}
		}
		if (!found)
			return NULL;

		// lea r10, KeServiceDescriptorTable
		ULONG_PTR address = kernelBase + KiSSSOffset + signatureSize;
		LONG relativeOffset = 0;
		if ((*(unsigned char*)address == 0x4c) &&
			(*(unsigned char*)(address + 1) == 0x8d) &&
			(*(unsigned char*)(address + 2) == 0x15))
		{
			address += 14;
			relativeOffset = *(LONG*)(address - 4);
		}
		if (relativeOffset == 0)
			return NULL;

		SSSDT = (SSDTStruct*)(address + relativeOffset);
		SSSDT += 1;
#endif
	}
	return SSSDT;
}


