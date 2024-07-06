#include "Function.h"
#include "Tools.h"
#include "Memory.h"
#include <minwindef.h>
RTL_OSVERSIONINFOEXW OsVeSionNinfo = { 0 };


PPEB32 PsGetWow64Peb32(PEPROCESS Process) {
	PPEB32 peb32 = NULL;
	if (OsVeSionNinfo.dwBuildNumber == 7601 || OsVeSionNinfo.dwBuildNumber == 7600)
	{
		peb32 = (PPEB32) * ((PULONG64)((PUCHAR)Process + 0x320));
	}
	else if (OsVeSionNinfo.dwBuildNumber == 22000) {
		ULONG64 tmp = *((((PULONG64)((PUCHAR)Process + 0x580))));
		if (tmp)
		{
			peb32 = (PPEB32) * (PULONG64)(tmp);
		}
	}
	else
	{
		ULONG64 tmp = *((((PULONG64)((PUCHAR)Process + 0x428))));
		if (tmp)
		{
			peb32 = (PPEB32) * (PULONG64)(tmp);
		}
	}
	return peb32;
}

/*从PEB链表中获取指定Wow64进程基址*/
ULONG_PTR Getx86ModuleBase(PPEB32 peb, char* moduleName) {
	if (!peb)
	{
		return NULL;
	}
	PPEB_LDR_DATA32 ldrData = (PPEB_LDR_DATA32)peb->Ldr;
	PLDR_DATA_TABLE_ENTRY32 begin = (PLDR_DATA_TABLE_ENTRY32)ldrData->InLoadOrderModuleList.Flink;
	PLDR_DATA_TABLE_ENTRY32 next = (PLDR_DATA_TABLE_ENTRY32)begin;
	do
	{
		ANSI_STRING name = { 0 };
		UNICODE_STRING nameUni = { 0 };
		RtlInitAnsiString(&name, moduleName);
		RtlAnsiStringToUnicodeString(&nameUni, &name, TRUE);

		if (next->DllBase && wcscmp(nameUni.Buffer, next->BaseDllName.Buffer) == 0)
		{
			RtlFreeAnsiString(&nameUni);
			return next->DllBase;
		}
		next = (PLDR_DATA_TABLE_ENTRY32)next->InLoadOrderLinks.Flink;
		RtlFreeAnsiString(&nameUni);
	} while (begin != next && next);

}

/*从PEB链表中获取指定X64进程基址*/
ULONG_PTR Getx64ModuleBase(PPEB peb64, char* moduleName) {
	if (!peb64)
	{
		return NULL;
	}
	PPEB_LDR_DATA64 ldrData = (PPEB_LDR_DATA64)(*(PULONG64)((ULONG64)peb64 + 0x18));
	PLDR_DATA_TABLE_ENTRY64 begin = (PLDR_DATA_TABLE_ENTRY64)ldrData->InLoadOrderModuleList.Flink;
	PLDR_DATA_TABLE_ENTRY64 next = (PLDR_DATA_TABLE_ENTRY64)begin;
	do
	{
		ANSI_STRING name = { 0 };
		UNICODE_STRING nameUni = { 0 };

		RtlInitAnsiString(&name, moduleName);
		RtlAnsiStringToUnicodeString(&nameUni, &name, TRUE);
		if (next->DllBase && RtlCompareUnicodeString(&nameUni, &(next->BaseDllName), TRUE) == 0)
		{
			RtlFreeAnsiString(&nameUni);
			return next->DllBase;
		}
		next = (PLDR_DATA_TABLE_ENTRY64)next->InLoadOrderLinks.Flink;
		RtlFreeAnsiString(&nameUni);
	} while (begin != next && next);
	return NULL;
}

//查询内存

NTSTATUS Fm_QueryMemory(ULONG64 Pid, ULONG64 VirtualAddress, PFMMEMORY_BASIC_INFORMATION InfoMode)
{
	PEPROCESS Process = NULL;

	FMMEMORY_BASIC_INFORMATION InfoTemp = { 0 };

	NTSTATUS Status = PsLookupProcessByProcessId(Pid, &Process);

	if (!NT_SUCCESS(Status))
	{
		return Status;
	}
	if (PsGetProcessExitStatus(Process) != STATUS_PENDING)
	{
		ObDereferenceObject(Process);

		return STATUS_UNSUCCESSFUL;
	}
	KAPC_STATE KApc = { 0 };

	KeStackAttachProcess(Process, &KApc);

	MODE Mode = SetPreviousMode(KeGetCurrentThread(), KernelMode);


	do 
	{
		MEMORY_BASIC_INFORMATION m_Info = { 0 };

		SIZE_T retSize = 0;

	
		NtQueryVirtualMemoryProc pNtQueryVirtualMemory = (NtQueryVirtualMemoryProc)NtQueryVirtualMemoryAddr();

		//DbgPrintEx(0, 77, "pNtQueryVirtualMemory->%p \r\n", pNtQueryVirtualMemory);

	
		Status = pNtQueryVirtualMemory(NtCurrentProcess(), VirtualAddress, MemoryBasicInformation, &m_Info, sizeof(m_Info),&retSize);

		if (!NT_SUCCESS(Status))
		{
			break;
		}

		InfoTemp.AllocationBase = m_Info.AllocationBase;
		InfoTemp.AllocationProtect = m_Info.AllocationProtect;
		InfoTemp.BaseAddress = m_Info.BaseAddress;
		InfoTemp.PartitionId = m_Info.PartitionId;
		InfoTemp.Protect = m_Info.Protect;
		InfoTemp.RegionSize = m_Info.RegionSize;
		InfoTemp.State = m_Info.State;
		InfoTemp.Type = m_Info.Type;



	} while (0);

	SetPreviousMode(KeGetCurrentThread(), Mode);

	KeUnstackDetachProcess(&KApc);

	DbgBreakPoint();
	if (MmIsAddressValid(InfoMode))
	{
		memcpy(InfoMode, &InfoTemp, sizeof(FMMEMORY_BASIC_INFORMATION));
	}
	
	return InfoTemp.RegionSize != 0 ? STATUS_SUCCESS: STATUS_UNSUCCESSFUL;

}

//获取Exe
ULONG64 Fm_GetExeModule(ULONG64 Pid)
{
	PEPROCESS Process = NULL;

	NTSTATUS Status = PsLookupProcessByProcessId(Pid, &Process);

	if (!NT_SUCCESS(Status))
	{
		return Status;
	}
	ObDereferenceObject(Process);

	return PsGetProcessSectionBaseAddress(Process);
}


//获取模块
ULONG64 Fm_GetModeBase(ULONG64 Pid, char* ModeName)
{
	if (ModeName == NULL)
	{
		return NULL;
	}
	PEPROCESS Process = NULL;

	NTSTATUS Status = PsLookupProcessByProcessId(Pid, &Process);

	KAPC_STATE apc = { 0 };
	
	char* name = (char*)ExAllocatePool(NonPagedPool, 0x200);
	
	strcpy(name, ModeName);

	KeStackAttachProcess(Process, &apc);

	ULONG_PTR base = NULL;
	
	PPEB32 peb32 = PsGetWow64Peb32(Process);

	if (peb32)
	{
		//x86
		base = Getx86ModuleBase(peb32, name);
	}
	else {
		//X64
		PPEB peb64 = (PPEB)PsGetProcessPeb(Process);

		base = Getx64ModuleBase(peb64, name);
	}
	KeUnstackDetachProcess(&apc);
	
	ObDereferenceObject(Process);
	
	return base;
}
PEPROCESS FindProcess(char* processName)
{
	PEPROCESS eprocess = NULL;
	KAPC_STATE kapc = { 0 };
	for (int i = 8; i < 0x10000; i += 4)
	{
		PEPROCESS tempProcess = NULL;
		NTSTATUS status = PsLookupProcessByProcessId((HANDLE)i, &tempProcess);
		if (NT_SUCCESS(status))
		{
			char* name = PsGetProcessImageFileName(tempProcess);
			if (name && _stricmp(name, processName) == 0)
			{
				eprocess = tempProcess;
				break;
			}
			ObDereferenceObject(tempProcess);

		}
	}

	return eprocess;
}



//伪装读内存
NTSTATUS Fm_ReadMemory(ULONG64 Pid, ULONG64 Address, ULONG64 Buffer, ULONG64 Size)
{
	static PVOID Object = NULL;

	if (Address == 0)return STATUS_UNSUCCESSFUL;

	if (Address >= MM_HIGHEST_USER_ADDRESS)return STATUS_UNSUCCESSFUL;

	if(Address+Size >= MM_HIGHEST_USER_ADDRESS)return STATUS_UNSUCCESSFUL;

	static PEPROCESS WinlogonProcess = NULL;

	PEPROCESS Process = NULL;

	NTSTATUS Status = PsLookupProcessByProcessId(Pid, &Process);

	if (!NT_SUCCESS(Status))
	{
		return Status;
	}
	if (PsGetProcessExitStatus(Process) != STATUS_PENDING)
	{
		ObDereferenceObject(Process);

		return STATUS_UNSUCCESSFUL;
	}

	if (!WinlogonProcess)
	{
		WinlogonProcess = FindProcess("winlogon.exe");
	}

	if (!WinlogonProcess)
	{
		ObDereferenceObject(Process);

		return STATUS_UNSUCCESSFUL;
	}
	if (PsGetProcessExitStatus(WinlogonProcess) != STATUS_PENDING)
	{
		ObDereferenceObject(Process);

		return STATUS_UNSUCCESSFUL;
	}
	
	if (!Object)
	{
		Object = ExAllocatePool(NonPagedPool, PAGE_SIZE);

		memcpy(Object, (PUCHAR)WinlogonProcess - 0x30, PAGE_SIZE);
	}

	PEPROCESS FakeProcess = (PEPROCESS)((PUCHAR)Object + 0x30);

	ULONG64 GameCr3 = *(PLONG64)((ULONG64)Process + 0x28);

	*(PLONG64)((ULONG64)FakeProcess + 0x28) = GameCr3;
	
	SIZE_T RetSize = 0;

	Status = MmCopyVirtualMemory(FakeProcess, Address, IoGetCurrentProcess(), Buffer, Size, UserMode, &RetSize);

	ObDereferenceObject(Process);

	//ExFreePool(Object);

	return Status;
}

NTSTATUS Fm_WriteMemory(ULONG64 Pid, ULONG64 Address, ULONG64 Buffer, ULONG64 Size)
{
	if (Address == 0)return STATUS_UNSUCCESSFUL;

	if (Address >= MM_HIGHEST_USER_ADDRESS)return STATUS_UNSUCCESSFUL;

	if (Address + Size >= MM_HIGHEST_USER_ADDRESS)return STATUS_UNSUCCESSFUL;

	static PEPROCESS WinlogonProcess = NULL;

	PEPROCESS Process = NULL;

	NTSTATUS ntPstatus;

	NTSTATUS Status = PsLookupProcessByProcessId(Pid, &Process);

	if (!NT_SUCCESS(Status))
	{
		return Status;
	}
	if (PsGetProcessExitStatus(Process) != STATUS_PENDING)
	{
		ObDereferenceObject(Process);

		return STATUS_UNSUCCESSFUL;
	}

	if (!WinlogonProcess)
	{
		WinlogonProcess = FindProcess("winlogon.exe");
	}

	if (!WinlogonProcess)
	{
		ObDereferenceObject(Process);

		return STATUS_UNSUCCESSFUL;
	}
	if (PsGetProcessExitStatus(WinlogonProcess) != STATUS_PENDING)
	{
		ObDereferenceObject(Process);

		return STATUS_UNSUCCESSFUL;
	}

	PVOID Object = ExAllocatePool(NonPagedPool, PAGE_SIZE);

	memcpy(Object, (PUCHAR)WinlogonProcess - 0x30, PAGE_SIZE);

	PEPROCESS FakeProcess = (PEPROCESS)((PUCHAR)Object + 0x30);

	ULONG64 GameCr3 = *(PLONG64)((ULONG64)Process + 0x28);

	*(PLONG64)((ULONG64)FakeProcess + 0x28) = GameCr3;

	SIZE_T RetSize = 0;

	Status = MmCopyVirtualMemory(IoGetCurrentProcess(), Buffer, FakeProcess, Address, Size, UserMode, &RetSize);

	if (!NT_SUCCESS(Status))
	{
		KAPC_STATE Kapc = { 0 };

		KeStackAttachProcess(FakeProcess, &Kapc);
		//修改内存属性
		NtProtectVirtualMemoryProc pNtProtectVirtualMemory = (NtProtectVirtualMemoryProc)NtProtectVirtualMemoryAddr();

	//	DbgPrintEx(0, 77, "pNtProtectVirtualMemory -> %p \r\n", pNtProtectVirtualMemory);

		MODE Mode = SetPreviousMode(KeGetCurrentThread(), KernelMode);

		PVOID TempBase = Address;

		SIZE_T TempSize = Size;
		
		ULONG OldProtect = 0;


		Status =  pNtProtectVirtualMemory(NtCurrentProcess(), &TempBase, &Size,PAGE_EXECUTE_READWRITE, &OldProtect);

		ntPstatus = Status;

		SetPreviousMode(KeGetCurrentThread(), Mode);

		KeUnstackDetachProcess(&Kapc);

		if (NT_SUCCESS(Status))
		{
			 MmCopyVirtualMemory(IoGetCurrentProcess(), Buffer, FakeProcess, Address, Size, UserMode, &RetSize);
		}
		if (ntPstatus)
		{
			KeStackAttachProcess(FakeProcess, &Kapc);

			pNtProtectVirtualMemory(NtCurrentProcess(), &TempBase, &Size, OldProtect, &OldProtect);

			KeUnstackDetachProcess(&Kapc);
		}

	}

	if (!NT_SUCCESS(Status))
	{
		KAPC_STATE Kapc = { 0 };

		PUCHAR kBuffer = ExAllocatePool(NonPagedPool, Size);

		memcpy(kBuffer, Buffer, Size);

		KeStackAttachProcess(FakeProcess,&Kapc);

		do 
		{
			PMDL Mdl = IoAllocateMdl(Address, Size, NULL, NULL, NULL);

			if (!Mdl)
			{
				break;
			}
			MmBuildMdlForNonPagedPool(Mdl);

			PVOID pBaseAddress = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmCached, NULL, NULL, NormalPagePriority);

			if (!pBaseAddress)
			{

				IoFreeMdl(Mdl);
				break;
			}

			memcpy(pBaseAddress, kBuffer, Size);

			MmUnmapLockedPages(pBaseAddress, Mdl);
			IoFreeMdl(Mdl);

			Status = STATUS_SUCCESS;

		} while (0);

		KeUnstackDetachProcess(&Process);

	}

	ObDereferenceObject(Process);

	ExFreePool(Object);

	return Status;
}

PVOID AllocMdlMemory(ULONG64 Size, ULONG Protect)
{
	PMDL Mdl;

	PVOID UserVAToReturn;

	PHYSICAL_ADDRESS LowAddress;

	PHYSICAL_ADDRESS HighAddress;

	SIZE_T TotalBytes;

	// 初始化MmAllocatePagesForMdl需要的Physical Address

	LowAddress.QuadPart = 0;  

	HighAddress.QuadPart = 0xFFFF'FFFF'FFFF'FFFFULL;

	TotalBytes = Size;

	// 分配4K的共享缓冲区
	Mdl = MmAllocatePagesForMdlEx(LowAddress, HighAddress, LowAddress, TotalBytes, MmCached, MM_ALLOCATE_NO_WAIT);

	if (!Mdl)return 0;

	PVOID Address = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);

	if (Address != 0)
	{
		NTSTATUS Status = MmProtectMdlSystemAddress(Mdl, Protect);

		if (!NT_SUCCESS(Status))
		{
			Address = NULL;
		}
	}

	return Address;
}

PVOID MdlMapRing0ToRing3(PVOID Address, ULONG Size)
{
	PVOID R3Address = 0;

	if (Address == NULL) {
		return 0;
	}
	memset(Address, 0, Size);

	PMDL MD = IoAllocateMdl(Address, Size, FALSE, FALSE, NULL);
	if (MD == NULL) {
		return 0;
	}


	MmBuildMdlForNonPagedPool(MD);
	//映射到R3
	R3Address = MmMapLockedPagesSpecifyCache(MD, UserMode, MmCached, NULL, FALSE, NormalPagePriority);


	return R3Address;
}

//AllocRing3MdlMemory

PVOID AllocRing3MdlMemory(ULONG Size)
{
	PVOID  ADD = AllocMdlMemory(Size, PAGE_EXECUTE_READWRITE);

	if (ADD != 0)
	{
		ADD = MdlMapRing0ToRing3(ADD, Size);

		return ADD;
	}

	return NULL;
}

PVOID Fm_AllocMemory(ULONG64 PID, SIZE_T size)
{
	PEPROCESS Process = NULL;
	KAPC_STATE kApcState = { 0 };
	PVOID BaseAddress = 0;
	NTSTATUS status = PsLookupProcessByProcessId(PID, &Process);

	if (!NT_SUCCESS(status))
	{
		return NULL;
	}

	if (PsGetProcessExitStatus(Process) != STATUS_PENDING)
	{
		ObDereferenceObject(Process);
		return NULL;
	}
	KeStackAttachProcess(Process, &kApcState);
	
	BaseAddress = AllocRing3MdlMemory(size);  //ExAllocatePool() 申请内存
	
	if (BaseAddress)
	{
		memset(BaseAddress, 0, size);

		SetExecutePage((ULONG64)BaseAddress, size);
	}


	KeUnstackDetachProcess(&kApcState);
	ObDereferenceObject(Process);

	return BaseAddress;

}


ULONG64 Read(ULONG64 pid, ULONG64 Address)
{
	ULONG64 TmpVariate = NULL;
	
	NTSTATUS status = InitMemory();

	PEPROCESS pProcess;

	status = PsLookupProcessByProcessId((HANDLE)pid, &pProcess);

	ReadProcessMemory(pProcess, Address, &TmpVariate, sizeof(TmpVariate));
	
	ObDereferenceObject(pProcess);

	return TmpVariate;
}
VOID ReadVritualMemory(ULONG64 pid, __int64 Address, void* buff, size_t size)//读
{

	NTSTATUS status = InitMemory();

	PEPROCESS pProcess;

	status = PsLookupProcessByProcessId((HANDLE)pid, &pProcess);

	ReadProcessMemory(pProcess, Address, (PBYTE)buff, sizeof(size));

	ObDereferenceObject(pProcess);


	return;
}


//ULONG_PTR DecryptCall = NULL;
//
//ULONG64 Fm_InitDecrypt(ULONG64 PID,ULONG64 Encrypted,PUCHAR CodeBuffer)
//{
//	ULONG_PTR GameDecryptVariate = NULL;
//
//	ULONG_PTR GameDecryptFunctoinBaseAddress = NULL;
//
//	//UCHAR CodeBuffer[0x100];
//
//	RtlZeroMemory(CodeBuffer, 0x50);
//
//
//	PUCHAR base = NULL;
//	
//	SIZE_T size = PAGE_SIZE;
//
//	NTSTATUS status = ZwAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size, MEM_COMMIT, PAGE_READWRITE);
//
//	DecryptCall = base;
//
//	if (DecryptCall == NULL)
//		return FALSE;
//
//	memset(DecryptCall, 0xC3, 0x100);
//
//	GameDecryptFunctoinBaseAddress = (ULONG_PTR)Encrypted;
//
//	if (GameDecryptFunctoinBaseAddress == NULL)
//	{
//		return FALSE;
//	}
//
//	GameDecryptVariate = GameDecryptFunctoinBaseAddress + (ULONG32)Read(PID, GameDecryptFunctoinBaseAddress + 3) + 7; 
//
//	if (GameDecryptVariate == NULL)
//	{
//		return FALSE;
//	}
//
//
//	ReadVritualMemory(PID,GameDecryptFunctoinBaseAddress,CodeBuffer, 0x50);
//
//	((PUCHAR)DecryptCall)[0] = 0x48;
//
//	((PUCHAR)DecryptCall)[1] = 0xB8;
//
//	RtlCopyMemory(&((PUCHAR)DecryptCall)[0x02], &GameDecryptVariate, 0x08);
//
//	RtlCopyMemory(&((PUCHAR)DecryptCall)[0x0A], &CodeBuffer[0x0A], 0x50);
//
//
//	return DecryptCall;
//}


#include <ntimage.h>

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(unsigned __int64 *)(name)
#define DEREF_32( name )*(unsigned long *)(name)
#define DEREF_16( name )*(unsigned short *)(name)
#define DEREF_8( name )*(UCHAR *)(name)


ULONG_PTR GetProcAddressR(ULONG_PTR hModule, const char* lpProcName, BOOLEAN x64Module)
{
	UINT_PTR uiLibraryAddress = 0;
	ULONG_PTR fpResult = NULL;

	if (hModule == NULL)
		return NULL;

	// a module handle is really its base address
	uiLibraryAddress = (UINT_PTR)hModule;

	__try
	{
		UINT_PTR uiAddressArray = 0;
		UINT_PTR uiNameArray = 0;
		UINT_PTR uiNameOrdinals = 0;
		PIMAGE_NT_HEADERS32 pNtHeaders32 = NULL;
		PIMAGE_NT_HEADERS64 pNtHeaders64 = NULL;
		PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
		PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;

		// get the VA of the modules NT Header
		pNtHeaders32 = (PIMAGE_NT_HEADERS32)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);
		pNtHeaders64 = (PIMAGE_NT_HEADERS64)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);
		if (x64Module)
		{
			pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		}
		else
		{
			pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		}


		// get the VA of the export directory
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiLibraryAddress + pDataDirectory->VirtualAddress);

		// get the VA for the array of addresses
		uiAddressArray = (uiLibraryAddress + pExportDirectory->AddressOfFunctions);

		// get the VA for the array of name pointers
		uiNameArray = (uiLibraryAddress + pExportDirectory->AddressOfNames);

		// get the VA for the array of name ordinals
		uiNameOrdinals = (uiLibraryAddress + pExportDirectory->AddressOfNameOrdinals);

		// test if we are importing by name or by ordinal...
		if ((PtrToUlong(lpProcName) & 0xFFFF0000) == 0x00000000)
		{
			// import by ordinal...

			// use the import ordinal (- export ordinal base) as an index into the array of addresses
			uiAddressArray += ((IMAGE_ORDINAL(PtrToUlong(lpProcName)) - pExportDirectory->Base) * sizeof(unsigned long));

			// resolve the address for this imported function
			fpResult = (ULONG_PTR)(uiLibraryAddress + DEREF_32(uiAddressArray));
		}
		else
		{
			// import by name...
			unsigned long dwCounter = pExportDirectory->NumberOfNames;
			while (dwCounter--)
			{
				char* cpExportedFunctionName = (char*)(uiLibraryAddress + DEREF_32(uiNameArray));

				// test if we have a match...
				if (strcmp(cpExportedFunctionName, lpProcName) == 0)
				{
					// use the functions name ordinal as an index into the array of name pointers
					uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(unsigned long));

					// calculate the virtual address for the function
					fpResult = (ULONG_PTR)(uiLibraryAddress + DEREF_32(uiAddressArray));

					// finish...
					break;
				}

				// get the next exported function name
				uiNameArray += sizeof(unsigned long);

				// get the next exported function name ordinal
				uiNameOrdinals += sizeof(unsigned short);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		fpResult = NULL;
	}

	return fpResult;
}

//获取版本号

ULONG GetWindowsVersionNumber()
{
	static ULONG gNumber = 0;
	if (gNumber != 0) return gNumber;

	RTL_OSVERSIONINFOW version = { 0 };
	RtlGetVersion(&version);

	if (version.dwMajorVersion <= 6) return 7;

	if (version.dwBuildNumber == 9600)
	{
		gNumber = 8;
	}
	else if (version.dwBuildNumber == 10240)
	{
		gNumber = 1507;
	}
	else if (version.dwBuildNumber == 10586)
	{
		gNumber = 1511;
	}
	else if (version.dwBuildNumber == 14393)
	{
		gNumber = 1607;
	}
	else if (version.dwBuildNumber == 15063)
	{
		gNumber = 1703;
	}
	else if (version.dwBuildNumber == 16299)
	{
		gNumber = 1709;
	}
	else if (version.dwBuildNumber == 17134)
	{
		gNumber = 1803;
	}
	else if (version.dwBuildNumber == 17763)
	{
		gNumber = 1809;
	}
	else if (version.dwBuildNumber == 18362)
	{
		gNumber = 1903;
	}
	else if (version.dwBuildNumber == 18363)
	{
		gNumber = 1909;
	}
	else if (version.dwBuildNumber == 19041)
	{
		gNumber = 2004;
	}
	else if (version.dwBuildNumber == 19042)
	{
		gNumber = 2009;
	}
	else if (version.dwBuildNumber == 19043)
	{
		gNumber = 2011;
	}
	else if (version.dwBuildNumber == 22200)
	{
		gNumber = 2012;
	}


	return gNumber;
}
#define PageCount 64
_PAGE PageList[PageCount];
DirectoryTableOffset = 0x0388;
PVOID PhysicalToVirtual(ULONG64 address)
{
	PHYSICAL_ADDRESS physical;
	physical.QuadPart = address;
	return MmGetVirtualForPhysical(physical);
}

ULONG64 TransformationCR3(const pageindex, ULONG64 cr3, ULONG64 VirtualAddress)
{
	cr3 &= ~0xf;
	ULONG64 PAGE_OFFSET = VirtualAddress & ~(~0ul << 12);
	ULONG64 a = 0, b = 0, c = 0;
	ReadPhysicalAddress(pageindex, (PVOID)(cr3 + 8 * ((VirtualAddress >> 39) & (0x1ffll))), &a, sizeof(a));
	if (~a & 1) return 0;
	ReadPhysicalAddress(pageindex, (PVOID)((a & ((~0xfull << 8) & 0xfffffffffull)) + 8 * ((VirtualAddress >> 30) & (0x1ffll))), &b, sizeof(b));
	if (~b & 1) return 0;
	if (b & 0x80) return (b & (~0ull << 42 >> 12)) + (VirtualAddress & ~(~0ull << 30));
	ReadPhysicalAddress(pageindex, (PVOID)((b & ((~0xfull << 8) & 0xfffffffffull)) + 8 * ((VirtualAddress >> 21) & (0x1ffll))), &c, sizeof(c));
	if (~c & 1) return 0;
	if (c & 0x80) return (c & ((~0xfull << 8) & 0xfffffffffull)) + (VirtualAddress & ~(~0ull << 21));
	ULONG64 address = 0;
	ReadPhysicalAddress(pageindex, (PVOID)((c & ((~0xfull << 8) & 0xfffffffffull)) + 8 * ((VirtualAddress >> 12) & (0x1ffll))), &address, sizeof(address));
	address &= ((~0xfull << 8) & 0xfffffffffull);
	if (!address) return 0;
	return address + PAGE_OFFSET;
}
ULONG GetDirectoryTableOffset(void)
{
	RTL_OSVERSIONINFOW Version;
	RtlGetVersion(&Version);
	switch (Version.dwBuildNumber)
	{
	case 17763:		//1809
		return 0x0278;
		break;
	case 18363:		//1909
		return 0x0280;
		break;
	case 19041:		//2004
		return 0x0388;
		break;
	case 19569:		//20H2
		return 0x0388;
		break;
	case 20180:		//21H1
		return 0x0388;
		break;
	}
	return 0x0388;
}


PTE* MemoryGetPte(const ULONG64 address)
{
	VIRTUAL_ADDRESS virtualAddress;
	virtualAddress.Value = address;

	PTE_CR3 cr3;
	cr3.Value = __readcr3();

	PML4E* pml4 = (PML4E*)(PhysicalToVirtual(PFN_TO_PAGE(cr3.Pml4)));
	const PML4E* pml4e = (pml4 + virtualAddress.Pml4Index);
	if (!pml4e->Present)
		return 0;

	PDPTE* pdpt = (PDPTE*)(PhysicalToVirtual(PFN_TO_PAGE(pml4e->Pdpt)));
	const PDPTE* pdpte = pdpte = (pdpt + virtualAddress.PdptIndex);
	if (!pdpte->Present)
		return 0;

	// sanity check 1GB page
	if (pdpte->PageSize)
		return 0;

	PDE* pd = (PDE*)(PhysicalToVirtual(PFN_TO_PAGE(pdpte->Pd)));
	const PDE* pde = pde = (pd + virtualAddress.PdIndex);
	if (!pde->Present)
		return 0;

	// sanity check 2MB page
	if (pde->PageSize)
		return 0;

	PTE* pt = (PTE*)(PhysicalToVirtual(PFN_TO_PAGE(pde->Pt)));
	PTE* pte = (pt + virtualAddress.PtIndex);
	if (!pte->Present)
		return 0;

	return pte;
}



NTSTATUS InitMemory()
{

	for (UINT32 i = 0; i < 64; i++)
	{
		PHYSICAL_ADDRESS maxAddress;
		maxAddress.QuadPart = MAXULONG64;

		PageList[i].VirtualAddress = MmAllocateContiguousMemory(PAGE_SIZE, maxAddress);
		if (!PageList[i].VirtualAddress)
			return 0;

		PageList[i].PTE = MemoryGetPte((ULONG64)(PageList[i].VirtualAddress));
		if (!PageList[i].PTE)
			return 0;
	}

	return STATUS_SUCCESS;
}

void ReadPhysicalAddress(const UINT32 pageIndex, const ULONG64 targetAddress, const PVOID buffer, const SIZE_T size)
{
	const ULONG pageOffset = targetAddress % PAGE_SIZE;
	const ULONG64 pageStartPhysical = targetAddress - pageOffset;

	_PAGE* pageInfo = &PageList[pageIndex];
	const ULONG64 OldPFN = pageInfo->PTE->PFN;



	pageInfo->PTE->PFN = PAGE_TO_PFN(pageStartPhysical);


	__invlpg(pageInfo->VirtualAddress);


	const PVOID virtualAddress = (PVOID)(((ULONG64)(pageInfo->VirtualAddress) + pageOffset));

	memcpy(buffer, virtualAddress, size);

	pageInfo->PTE->PFN = OldPFN;
	__invlpg(pageInfo->VirtualAddress);
}

void ReadProcessMemory(PEPROCESS GameEProcess, IN  PVOID BaseAddress, OUT PVOID Buffer, IN ULONG Length)
{
	const UINT32 pageIndex = KeGetCurrentProcessorIndex();

	NTSTATUS Status = STATUS_SUCCESS;

	if (BaseAddress <= 0 || (UINT_PTR)BaseAddress > 0x7FFFFFFFFFFF || Length <= 0 || Buffer <= 0) return STATUS_UNSUCCESSFUL;

	if (GameEProcess != NULL)	
	{
		ULONG64 TargetAddress = (ULONG64)BaseAddress;
		SIZE_T TargetSize = Length;
		SIZE_T read = 0;

		DirectoryTableOffset = GetDirectoryTableOffset();

		PUCHAR Var = (PUCHAR)GameEProcess;
		ULONG64 CR3 = *(ULONG64*)(Var + 0x28);//maybe some game ac changed this 

		if (!CR3) CR3 = *(ULONG64*)(Var + DirectoryTableOffset);


		while (TargetSize)
		{
			ULONG64 PhysicalAddress = TransformationCR3(pageIndex, CR3, TargetAddress + read);
			if (!PhysicalAddress) break;
			ULONG64 ReadSize = min(PAGE_SIZE - (PhysicalAddress & 0xfff), TargetSize);

			ReadPhysicalAddress(pageIndex, (PVOID)(PhysicalAddress), (PVOID)((UINT_PTR)Buffer + read), ReadSize);


			TargetSize -= ReadSize;

			read += ReadSize;

		}
	}
}
