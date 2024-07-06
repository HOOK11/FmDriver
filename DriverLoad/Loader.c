#include "Loader.h"
#include <ntimage.h>
#include "tools.h"



typedef NTSTATUS(NTAPI* DriverEntryProc)(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg);

typedef struct _IMAGE_RELOC
{
	UINT16	Offset : 12;		// 低12位---偏移
	UINT16	Type : 4;			// 高4位---类型
} IMAGE_RELOC, * PIMAGE_RELOC;

PUCHAR FileToImage(char* fileBuffer)
{
	if (!fileBuffer) return NULL;

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)fileBuffer;
	PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)(fileBuffer + pDos->e_lfanew);

	//创建imageBuffer
	ULONG sizeofImage = pNts->OptionalHeader.SizeOfImage;
	PUCHAR imageBuffer = ExAllocatePool(NonPagedPool, sizeofImage);
	memset(imageBuffer, 0, sizeofImage);

	//复制PE头
	memcpy(imageBuffer, fileBuffer, pNts->OptionalHeader.SizeOfHeaders);

	ULONG NumberOfSections = pNts->FileHeader.NumberOfSections;

	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNts);

	//拉伸PE 结构
	for (ULONG i = 0; i < NumberOfSections; i++)
	{
		memcpy(imageBuffer + pSection->VirtualAddress, fileBuffer + pSection->PointerToRawData, pSection->SizeOfRawData);
		pSection++;
	}

	return imageBuffer;
}

//获取到 LoadLibraryExW
ULONG64 ExportTableFuncByName(char* pData, char* funcName)
{
	PIMAGE_DOS_HEADER pHead = (PIMAGE_DOS_HEADER)pData;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pData + pHead->e_lfanew);
	int numberRvaAndSize = pNt->OptionalHeader.NumberOfRvaAndSizes;
	PIMAGE_DATA_DIRECTORY pDir = (PIMAGE_DATA_DIRECTORY)&pNt->OptionalHeader.DataDirectory[0];

	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(pData + pDir->VirtualAddress);

	ULONG64 funcAddr = 0;
	for (int i = 0; i < pExport->NumberOfNames; i++)
	{
		int* funcAddress = pData + pExport->AddressOfFunctions;
		int* names = pData + pExport->AddressOfNames;
		short* fh = pData + pExport->AddressOfNameOrdinals;
		int index = -1;
		char* name = pData + names[i];
		if (strcmp(name, funcName) == 0)
		{
			index = fh[i];
		}



		if (index != -1)
		{
			funcAddr = pData + funcAddress[index];
			break;
		}


	}

	if (!funcAddr)
	{
		KdPrint(("没有找到函数%s\r\n", funcName));

	}
	else
	{
		KdPrint(("找到函数%s addr %p\r\n", funcName, funcAddr));
	}


	return funcAddr;
}

BOOLEAN UpdataRelocation(char* imageBuffer)
{
	PIMAGE_NT_HEADERS pNts = RtlImageNtHeader(imageBuffer);
	if (!pNts) return FALSE;

	PIMAGE_DATA_DIRECTORY iRelocation = &pNts->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	PIMAGE_BASE_RELOCATION pBase = (PIMAGE_BASE_RELOCATION)(imageBuffer + iRelocation->VirtualAddress);

	while (pBase->SizeOfBlock && pBase->VirtualAddress)
	{

		PIMAGE_RELOC RelocationBlock = (PIMAGE_RELOC)((PUCHAR)pBase + sizeof(IMAGE_BASE_RELOCATION));

		UINT32	NumberOfRelocations = (pBase->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

		for (int i = 0; i < NumberOfRelocations; i++)
		{
			if (RelocationBlock[i].Type == IMAGE_REL_BASED_DIR64)
			{

				// 64 位
				PUINT64	Address = (PUINT64)((PUINT8)imageBuffer + pBase->VirtualAddress + RelocationBlock[i].Offset);
				UINT64	Delta = *Address - pNts->OptionalHeader.ImageBase + (PUINT8)imageBuffer;
				*Address = Delta;
			}
			else if (RelocationBlock[i].Type == IMAGE_REL_BASED_HIGHLOW)
			{

				PUINT32	Address = (PUINT32)((PUINT8)imageBuffer + pBase->VirtualAddress + (RelocationBlock[i].Offset));
				UINT32	Delta = *Address - pNts->OptionalHeader.ImageBase + (PUINT8)imageBuffer;
				*Address = Delta;
			}
		}

		pBase = (PIMAGE_BASE_RELOCATION)((PUCHAR)pBase + pBase->SizeOfBlock);
	}

	return TRUE;

}

BOOLEAN UpdataIAT(char* imageBuffer)
{
	if (!imageBuffer) return FALSE;

	PIMAGE_NT_HEADERS pNts = RtlImageNtHeader(imageBuffer);
	if (!pNts) return FALSE;

	PIMAGE_DATA_DIRECTORY pimportDir = &pNts->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_IMPORT_DESCRIPTOR import = (PIMAGE_IMPORT_DESCRIPTOR)(imageBuffer + pimportDir->VirtualAddress);

	BOOLEAN isSuccess = TRUE;

	for (; import->Name; import++)
	{
		PUCHAR libName = (imageBuffer + import->Name);
		ULONG_PTR base = QueryModule(libName, NULL);
		if (!base)
		{
			isSuccess = FALSE;
			break;
		}

		PIMAGE_THUNK_DATA pThuckName = (PIMAGE_THUNK_DATA)(imageBuffer + import->OriginalFirstThunk);
		PIMAGE_THUNK_DATA pThuckFunc = (PIMAGE_THUNK_DATA)(imageBuffer + import->FirstThunk);

		for (; pThuckName->u1.ForwarderString; ++pThuckName, ++pThuckFunc)
		{
			PIMAGE_IMPORT_BY_NAME FuncName = (PIMAGE_IMPORT_BY_NAME)(imageBuffer + pThuckName->u1.AddressOfData);

			ULONG_PTR func = ExportTableFuncByName((char*)base, FuncName->Name);
			if (func)
			{
				pThuckFunc->u1.Function = (ULONG_PTR)func;
			}
			else
			{
				isSuccess = FALSE;
				break;
			}
		}

		if (!isSuccess) break;

	}

	return isSuccess;
}

VOID UpdateCookie(char* imageBuffer)
{

	if (!imageBuffer) return FALSE;

	PIMAGE_NT_HEADERS pNts = RtlImageNtHeader(imageBuffer);
	if (!pNts) return FALSE;

	PIMAGE_DATA_DIRECTORY pConfigDir = &pNts->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];

	PIMAGE_LOAD_CONFIG_DIRECTORY config = (PIMAGE_LOAD_CONFIG_DIRECTORY)(pConfigDir->VirtualAddress + imageBuffer);

	*(PULONG_PTR)(config->SecurityCookie) += 10;

}

BOOLEAN LoadDriver(PUCHAR fileBuffer)
{
	PUCHAR imageBase = FileToImage(fileBuffer);
	if (!imageBase) return FALSE;

	BOOLEAN isSuccess = FALSE;

	do
	{
		isSuccess = UpdataRelocation(imageBase);
		if (!isSuccess) break;

		isSuccess = UpdataIAT(imageBase);
		if (!isSuccess) break;

		//修复cookie
		UpdateCookie(imageBase);

		//call 入口点
		PIMAGE_NT_HEADERS pNts = RtlImageNtHeader(imageBase);

		ULONG_PTR entry = pNts->OptionalHeader.AddressOfEntryPoint;
		DriverEntryProc EntryPointFunc = (DriverEntryProc)(imageBase + entry);
		NTSTATUS status = EntryPointFunc(NULL, NULL);
		if (!NT_SUCCESS(status))
		{
			isSuccess = FALSE;
			break;
		}


		//清空PE头
		memset(imageBase, 0, PAGE_SIZE);

	} while (0);



	if (!isSuccess)
	{
		ExFreePool(imageBase);

	}

	return isSuccess;
}