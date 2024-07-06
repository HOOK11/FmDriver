#pragma once
#include <ntifs.h>

typedef struct _SSDTStruct
{
	LONG* pServiceTable;
	PVOID pCounterTable;
#ifdef _WIN64
	ULONGLONG NumberOfServices;
#else
	ULONG NumberOfServices;
#endif
	PCHAR pArgumentTable;
}SSDTStruct, * PSSDTStruct;

NTSTATUS NTAPI ZwProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect
);

EXTERN_C SSDTStruct* SSSDTFind();

SSDTStruct* SSDTfind();





