#include "tools.h"



ULONG_PTR QueryModule(PUCHAR moduleName, ULONG_PTR * moduleSize)
{
	if (moduleName == NULL) return 0;

	RTL_PROCESS_MODULES rtlMoudles = { 0 };
	PRTL_PROCESS_MODULES SystemMoudles = &rtlMoudles;
	BOOLEAN isAllocate = FALSE;
	//测量长度
	ULONG * retLen = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, SystemMoudles, sizeof(RTL_PROCESS_MODULES), &retLen);

	//分配实际长度内存
	if (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		SystemMoudles = ExAllocatePool(PagedPool, retLen + sizeof(RTL_PROCESS_MODULES));
		if (!SystemMoudles) return 0;

		memset(SystemMoudles, 0, retLen + sizeof(RTL_PROCESS_MODULES));

		status = ZwQuerySystemInformation(SystemModuleInformation, SystemMoudles, retLen + sizeof(RTL_PROCESS_MODULES), &retLen);
	
		if (!NT_SUCCESS(status))
		{
			ExFreePool(SystemMoudles);
			return 0;
		}

		isAllocate = TRUE;
	}

	PUCHAR kernelModuleName = NULL;
	ULONG_PTR moudleBase = 0;

	do 
	{
	
		
		if (_stricmp(moduleName, "ntoskrnl.exe") == 0 || _stricmp(moduleName, "ntkrnlpa.exe") == 0)
		{
			PRTL_PROCESS_MODULE_INFORMATION moudleInfo = &SystemMoudles->Modules[0];
			moudleBase = moudleInfo->ImageBase;
			if (moduleSize) *moduleSize = moudleInfo->ImageSize;
			
			break;
		}


		kernelModuleName = ExAllocatePool(PagedPool, strlen(moduleName) + 1);
		memset(kernelModuleName, 0, strlen(moduleName) + 1);
		memcpy(kernelModuleName, moduleName, strlen(moduleName));
		_strupr(kernelModuleName);


		for (int i = 0; i < SystemMoudles->NumberOfModules; i++)
		{
			PRTL_PROCESS_MODULE_INFORMATION moudleInfo = &SystemMoudles->Modules[i];
		
			PUCHAR pathName = _strupr(moudleInfo->FullPathName);
			DbgPrintEx(77, 0, "baseName = %s,fullPath = %s\r\n", 
				moudleInfo->FullPathName + moudleInfo->OffsetToFileName, moudleInfo->FullPathName);

			
			if (strstr(pathName, kernelModuleName))
			{
				moudleBase = moudleInfo->ImageBase;
				if (moduleSize) *moduleSize = moudleInfo->ImageSize;
				break;
			}

		}

	} while (0);
	

	if (kernelModuleName)
	{
		ExFreePool(kernelModuleName);
	}

	if (isAllocate)
	{
		ExFreePool(SystemMoudles);
	}

	return moudleBase;
}

NTSTATUS DeleteRegisterPath(PUNICODE_STRING pReg) //驱动的相关  注册表   删除
{
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, pReg->Buffer, L"DisplayName");
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, pReg->Buffer, L"ErrorControl");
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, pReg->Buffer, L"ImagePath");
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, pReg->Buffer, L"Start");
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, pReg->Buffer, L"Type");
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, pReg->Buffer, L"WOW64");

	//拼装字符串
	PWCH enumPath = (PWCH)ExAllocatePool(PagedPool, pReg->MaximumLength + 0X100);
	memset(enumPath, 0, pReg->MaximumLength + 0X100);
	memcpy(enumPath, pReg->Buffer, pReg->Length);
	wcscat(enumPath, L"\\Enum");

	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, enumPath, L"enumPath");
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, enumPath, L"INITSTARTFAILED");
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, enumPath, L"NextInstance");

	HANDLE hKeyEnum = NULL;
	OBJECT_ATTRIBUTES enumObj = { 0 };
	UNICODE_STRING unEnumName;
	RtlInitUnicodeString(&unEnumName, enumPath);
	InitializeObjectAttributes(&enumObj, &unEnumName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	NTSTATUS status = ZwOpenKey(&hKeyEnum, KEY_ALL_ACCESS, &enumObj);

	if (NT_SUCCESS(status))
	{
		ZwDeleteKey(hKeyEnum);
		ZwClose(hKeyEnum);
	}

	ExFreePool(enumPath);

	//删除根部

	HANDLE hKeyRoot = NULL;
	OBJECT_ATTRIBUTES rootObj = { 0 };

	InitializeObjectAttributes(&rootObj, pReg, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwOpenKey(&hKeyRoot, KEY_ALL_ACCESS, &rootObj);

	if (NT_SUCCESS(status))
	{
		ZwDeleteKey(hKeyRoot);
		ZwClose(hKeyRoot);
		return STATUS_SUCCESS;
	}

	return STATUS_UNSUCCESSFUL;
}


NTSTATUS SelfDeleteFile(PWCH path) //删除自身  
{
	
	OBJECT_ATTRIBUTES objFile = {0};
	HANDLE hFile = NULL;
	IO_STATUS_BLOCK ioBlock = {0};
	UNICODE_STRING unFileName = {0};
	
	RtlInitUnicodeString(&unFileName, path);
	InitializeObjectAttributes(&objFile, &unFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	NTSTATUS status = ZwCreateFile(
		&hFile, 
		GENERIC_READ, //这里并不能用全部权限
		&objFile, 
		&ioBlock, 
		NULL, 
		FILE_ATTRIBUTE_NORMAL, 
		FILE_SHARE_READ,
		FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE, NULL, NULL);
	
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	
	PFILE_OBJECT pFile = NULL;

	status = ObReferenceObjectByHandle(hFile,
		FILE_ALL_ACCESS,
		*IoFileObjectType, KernelMode, &pFile, NULL);

	if (!NT_SUCCESS(status))
	{
		ZwClose(hFile);
		return status;
	}

	pFile->DeleteAccess = TRUE;
	pFile->DeletePending = FALSE;

	pFile->SectionObjectPointer->DataSectionObject = NULL;
	pFile->SectionObjectPointer->ImageSectionObject = NULL;
	//pFile->SectionObjectPointer->SharedCacheMap = NULL;

	ObDereferenceObject(pFile);
	ZwClose(hFile);

	status = ZwDeleteFile(&objFile);

	
	

	return status;
}