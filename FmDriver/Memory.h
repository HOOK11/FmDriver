#pragma once
#include <ntifs.h>

ULONG64 GetPTEBase();

ULONG64 GetPte(ULONG64 VirtualAddress);

ULONG64 GetPde(ULONG64 VirtualAddress);

ULONG64 GetPdpte(ULONG64 VirtualAddress);

ULONG64 GetPml4e(ULONG64 VirtualAddress);

BOOLEAN SetExecutePage(ULONG64 VirtualAddress, ULONG size);

PVOID AllocateMemory(HANDLE pid, SIZE_T size);

PVOID AllocateMemoryNotExecute(HANDLE pid, SIZE_T size);

NTSTATUS FreeMemory(HANDLE pid, PVOID BaseAddress ,SIZE_T size);