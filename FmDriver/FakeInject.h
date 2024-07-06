#pragma once
#include <ntifs.h>

NTSTATUS InjectX64(HANDLE pid, char *shellcode, SIZE_T shellcodeSize);

NTSTATUS Fm_Inject(ULONG64 pid, unsigned char* sysData, SIZE_T dwImageSize);