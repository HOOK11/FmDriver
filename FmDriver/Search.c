#include "Search.h"
#include <ntimage.h>

/*取驱动模块基址与大小*/
ULONG_PTR GetKernelModuleBase(PUCHAR moduleName, PULONG pModuleSize) {
	RTL_PROCESS_MODULES SysModules = { 0 };
	PRTL_PROCESS_MODULES pModules = &SysModules;
	ULONG64 SystemInformationLength = 0;


	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, pModules, sizeof(RTL_PROCESS_MODULES), &SystemInformationLength);
	if (status == STATUS_INFO_LENGTH_MISMATCH) {
		pModules = ExAllocatePool(NonPagedPool, SystemInformationLength + sizeof(RTL_PROCESS_MODULES));
		RtlZeroMemory(pModules, SystemInformationLength + sizeof(RTL_PROCESS_MODULES));
		status = ZwQuerySystemInformation(SystemModuleInformation, pModules, SystemInformationLength + sizeof(RTL_PROCESS_MODULES), &SystemInformationLength);
		if (!NT_SUCCESS(status)) {
			ExFreePool(pModules);
			return 0;
		}
	}

	if (!strcmp("ntoskrnl.exe", moduleName) || !strcmp("ntkrnlpa.exe.exe", moduleName)) {
		*pModuleSize = pModules->Modules[0].ImageSize;
		ULONG_PTR ret = pModules->Modules[0].ImageBase;
		if (SystemInformationLength) {
			ExFreePool(pModules);
		}
		return ret;
	}

	for (ULONG i = 0; i < pModules->NumberOfModules; i++) {
		if (strstr(pModules->Modules[i].FullPathName, moduleName)) {
			*pModuleSize = pModules->Modules[i].ImageSize;
			ULONG_PTR ret = pModules->Modules[i].ImageBase;
			if (SystemInformationLength) {
				ExFreePool(pModules);
			}
			return ret;
		}
	}
	if (SystemInformationLength) {
		ExFreePool(pModules);
	}
	return 0;
}

/*根据指定区段名取区段相对偏移*/
ULONG GetSectionOffsetName(PUCHAR ptr, PUCHAR name, PULONG size) {
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ptr;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dos->e_lfanew + (ULONG64)ptr);
	ULONG SectionNum = nt->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER SectionBase = IMAGE_FIRST_SECTION(nt);
	for (ULONG i = 0; i < SectionNum; i++) {
		if (!strcmp(SectionBase->Name, name))
		{
			*size = SectionBase->SizeOfRawData;
			return SectionBase->VirtualAddress;
		}
		SectionBase++;
	}

	return NULL;
}

/*特征码搜寻  AC??AC 格式*/
PUCHAR GetSearchApiCode(PUCHAR startAddr, PUCHAR sign, ULONG len)
{
	ULONG signArr[0x100] = { 0 };
	ULONG index = 0;
	ULONG signBytes = strlen(sign) / 2;
	for (index = 0; index < signBytes; index++)
	{
		ULONG signIndex = index * 2;
		char temp1 = sign[signIndex];
		char temp2 = sign[signIndex + 1];
		ULONG high = 0;
		ULONG low = 0;
		if (temp1 == '?' && temp2 == '?')
		{
			signArr[index] = 999;
			continue;
		}
		if (temp1 < '0' || temp1>'F' || temp2 < '0' || temp2>'F')
		{
			return NULL;
		}
		if (temp1 >= '0' && temp1 <= '9')
		{
			high = temp1 - 48;
		}
		if (temp1 >= 'A' && temp1 <= 'F')
		{
			high = temp1 - 65 + 10;
		}
		if (temp2 >= '0' && temp2 <= '9')
		{
			low = temp2 - 48;
		}
		if (temp2 >= 'A' && temp2 <= 'F')
		{
			low = temp2 - 65 + 10;
		}
		signArr[index] = high * 16 + low;
	}
	PUCHAR currentPtr = startAddr;
	ULONG rightBytes = 0;
	while ((currentPtr - startAddr) <= (len - signBytes)) {
		for (ULONG i = 0; i < signBytes; i++)
		{
			if (signArr[i] == 999) {
				rightBytes++;
				continue;
			}
			if (!MmIsAddressValid(currentPtr + i))
			{
				currentPtr = (PUCHAR)((UCHAR)currentPtr & 0xFFFFF000 + 0x1000);
				rightBytes = 0;
				break;
			}
			if (signArr[i] != (UCHAR) * (currentPtr + i))
			{
				currentPtr = currentPtr + i + 1;
				rightBytes = 0;
				break;
			}
			rightBytes++;
		}
		if (rightBytes == signBytes)
		{
			return currentPtr;
		}
	}
	return NULL;
}



