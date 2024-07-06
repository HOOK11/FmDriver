#include <ntifs.h>
#include"Search.h"
MODE SetPreviousMode(PETHREAD Thread, MODE Mode);


typedef NTSTATUS(*NtQueryVirtualMemoryProc)
(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
);

typedef NTSTATUS(*NtProtectVirtualMemoryProc)(
	 HANDLE ProcessHandle,
	 PVOID* BaseAddress,
	 PSIZE_T RegionSize,
	 ULONG NewProtect,
	 PULONG OldProtect
);

PUCHAR NtQueryVirtualMemoryAddr();

PUCHAR NtProtectVirtualMemoryAddr();
