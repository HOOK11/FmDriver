#include "Memory.h"

#define PTE_BASE 0xFFFFF68000000000ull


typedef struct HardwarePteX64 {
	ULONG64 valid : 1;               //!< [0]
	ULONG64 write : 1;               //!< [1]
	ULONG64 owner : 1;               //!< [2]
	ULONG64 write_through : 1;       //!< [3]
	ULONG64 cache_disable : 1;       //!< [4]
	ULONG64 accessed : 1;            //!< [5]
	ULONG64 dirty : 1;               //!< [6]
	ULONG64 large_page : 1;          //!< [7]
	ULONG64 global : 1;              //!< [8]
	ULONG64 copy_on_write : 1;       //!< [9]
	ULONG64 prototype : 1;           //!< [10]
	ULONG64 reserved0 : 1;           //!< [11]
	ULONG64 page_frame_number : 36;  //!< [12:47]
	ULONG64 reserved1 : 4;           //!< [48:51]
	ULONG64 software_ws_index : 11;  //!< [52:62]
	ULONG64 no_execute : 1;          //!< [63]
}HardwarePte, *PHardwarePte;

ULONG64 GetPTEBase()
{
	static ULONG64 pteBase = 0;
	if (pteBase) return pteBase;

	RTL_OSVERSIONINFOEXW version = {0};
	RtlGetVersion(&version);
	/*
		 Windows 10£¨20H2£©	19042
		 Windows 10£¨2004)  19041
		 Windows 10£¨1909£©	18363
		 Windows 10£¨1903£©	18362
		 Windows 10£¨1809£©	17763
		 Windows 10£¨1803£©	17134
		 Windows 10£¨1709£©	16299
		 Windows 10£¨1703£©	15063
		 Windows 10£¨1607£©	14393
		 Windows 10£¨1511£©	10586
		 Windows 10	(1507)	10240
		 
		 Windows 8.1£¨¸üÐÂ1£©	MajorVersion = 6 MinorVersion = 3 BuildNumber = 9600
		 Windows 8.1			MajorVersion = 6 MinorVersion = 3 BuildNumber = 9200
		 Windows 8				MajorVersion = 6 MinorVersion = 2 BuildNumber = 9200
	*/
	if (version.dwBuildNumber == 7600 || version.dwBuildNumber == 7601)
	{
		pteBase = PTE_BASE;
	}
	else if (version.dwBuildNumber > 14393)
	{
		//È¡PTE
		UNICODE_STRING unName = {0};
		RtlInitUnicodeString(&unName,L"MmGetVirtualForPhysical");
		PUCHAR func = (PUCHAR)MmGetSystemRoutineAddress(&unName);
		pteBase = *(PULONG64)(func + 0x22);
	}
	else 
	{
		pteBase = PTE_BASE;
	}

	return pteBase;
}

ULONG64 GetPte(ULONG64 VirtualAddress)
{
	ULONG64 pteBase = GetPTEBase();
	return ((VirtualAddress >> 9) & 0x7FFFFFFFF8) + pteBase;
}

ULONG64 GetPde(ULONG64 VirtualAddress)
{
	ULONG64 pteBase = GetPTEBase();
	ULONG64 pte = GetPte(VirtualAddress);
	return ((pte >> 9) & 0x7FFFFFFFF8) + pteBase;
}

ULONG64 GetPdpte(ULONG64 VirtualAddress)
{
	ULONG64 pteBase = GetPTEBase();
	ULONG64 pde = GetPde(VirtualAddress);
	return ((pde >> 9) & 0x7FFFFFFFF8) + pteBase;
}

ULONG64 GetPml4e(ULONG64 VirtualAddress)
{
	ULONG64 pteBase = GetPTEBase();
	ULONG64 ppe = GetPdpte(VirtualAddress);
	return ((ppe >> 9) & 0x7FFFFFFFF8) + pteBase;
}

BOOLEAN SetExecutePage(ULONG64 VirtualAddress, ULONG size)
{
	ULONG64 endAddress = (VirtualAddress + size) & (~0xFFF);
	ULONG64 startAddress = VirtualAddress &  (~0xFFF);
	int count = 0;
	while (endAddress >= startAddress)
	{

		PHardwarePte pde =  GetPde(startAddress);
		
		if (MmIsAddressValid(pde) && pde->valid)
		{
			pde->no_execute = 0;
			pde->write = 1;
		}


		PHardwarePte pte = GetPte(startAddress);

		if (MmIsAddressValid(pte) && pte->valid)
		{
			pte->no_execute = 0;
			pte->write = 1;
		}

		DbgPrintEx(77, 0, "[db]:pde %llx pte %llx %d\r\n", pde, pte,count);

		startAddress += PAGE_SIZE;
	}

	return TRUE;
}


PVOID AllocateMemory(HANDLE pid, SIZE_T size)
{
	PEPROCESS Process = NULL;
	KAPC_STATE kApcState = { 0 };
	PVOID BaseAddress = 0;
	NTSTATUS status = PsLookupProcessByProcessId(pid, &Process);

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


	status = ZwAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &size, MEM_COMMIT, PAGE_READWRITE);

	if (NT_SUCCESS(status))
	{
		
		memset(BaseAddress,0, size);
		SetExecutePage(BaseAddress, size);
	}

	KeUnstackDetachProcess(&kApcState);

	return BaseAddress;

}

NTSTATUS FreeMemory(HANDLE pid, PVOID BaseAddress, SIZE_T size)
{
	PEPROCESS Process = NULL;
	KAPC_STATE kApcState = { 0 };
	NTSTATUS status = PsLookupProcessByProcessId(pid, &Process);

	if (!NT_SUCCESS(status))
	{
		return STATUS_NOT_FOUND;
	}

	if (PsGetProcessExitStatus(Process) != STATUS_PENDING)
	{
		ObDereferenceObject(Process);
		return STATUS_UNSUCCESSFUL;
	}


	KeStackAttachProcess(Process, &kApcState);

	if (BaseAddress)
	{
		status = ZwFreeVirtualMemory(NtCurrentProcess(), &BaseAddress, &size, MEM_RELEASE);
	}

	KeUnstackDetachProcess(&kApcState);

	return status;
}


PVOID AllocateMemoryNotExecute(HANDLE pid, SIZE_T size)
{
	PEPROCESS Process = NULL;
	KAPC_STATE kApcState = { 0 };
	PVOID BaseAddress = 0;
	NTSTATUS status = PsLookupProcessByProcessId(pid, &Process);

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


	status = ZwAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &size, MEM_COMMIT, PAGE_READWRITE);

	if (NT_SUCCESS(status))
	{

		memset(BaseAddress, 0, size);
	}

	KeUnstackDetachProcess(&kApcState);

	return BaseAddress;

}