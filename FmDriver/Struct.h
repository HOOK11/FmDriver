#pragma once

typedef struct _CommInfo
{
	ULONG64 CommID;

	ULONG64 Cmd;

	ULONG64 InData;

	ULONG64 Size;

	ULONG64 RetStatus;

}CommInfo, * PCommInfo;

typedef enum _HOTCOMD
{
	CMD_INIT,

	CMD_QUERYMEMORY,

	CMD_READMEMORY,

	CMD_WIRTEMEMORY,

	CMD_GETMODULE,

	CMD_INJECT,

	CMD_FAKEPROCESS,

	CMD_GETEXEMODULE,

	CMD_WINDOWPROTECT,

	CMD_INITDECRYPT,

	CMD_ALLOCMEMORY,

}HOTCOMD;


typedef struct _FMMEMORY_BASIC_INFORMATION {
	ULONG64  BaseAddress;
	ULONG64  AllocationBase;
	ULONG64  AllocationProtect;
	ULONG64 PartitionId;
	ULONG64 RegionSize;
	ULONG64  State;
	ULONG64  Protect;
	ULONG64  Type;
} FMMEMORY_BASIC_INFORMATION, * PFMMEMORY_BASIC_INFORMATION;


typedef struct _QueryMemoryInfo
{

	ULONG64 PID;

	ULONG64 BaseAddress;

	ULONG64 RetBase;

}QueryMemoryInfo,*PQueryMemoryInfo;

typedef struct _GetModuleInfo
{

	ULONG64 PID;

	ULONG64 ModuleName;

	ULONG64 RetBase;

}GetModuleInfo, * PGetModuleInfo;

typedef struct _GetExeModule
{

	ULONG64 PID;

	ULONG64 RetBase;

}GetExeModule,*PGetExeModule;

typedef struct _ReadWriteMemoryInfo
{

	ULONG64 PID;

	ULONG64 Base;

	ULONG64 Buffer;

	ULONG64 Size;

}ReadWriteMemoryInfo,*PReadWriteMemoryInfo;



typedef struct _InjectInfo
{

	ULONG64 PID;
	
	unsigned char* DllBuffer;
	
	SIZE_T size;

}InjectInfo,*PInjectInfo;


typedef struct _FakeProcessInfo
{
	ULONG64 MyPID;

	ULONG64 FakePID;

}FakeProcessInfo,*PFakeProcessInfo;

typedef struct _WindowProtect
{
	ULONG64 Hwnd;

}WindowProtect,*PWindowProtect;

typedef struct _InitDecrypt
{
	ULONG64 PID;

	ULONG64 Address;

	ULONG64 DecryptCall;

	PUCHAR CodeBuffer;

}InitDecrypt,* PInitDecrypt;

typedef struct _AllocMemory
{
	//ULONG64 PID;

	SIZE_T size;

	ULONG64 Buffer;
}AllocMemory,*PAllocMemory;




