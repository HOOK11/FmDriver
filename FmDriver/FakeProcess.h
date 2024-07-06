
#include<ntifs.h>

typedef struct _CURDIR
{
	UNICODE_STRING DosPath;                                         //0x0
	VOID* Handle;                                                           //0x10
}CURDIR, *PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	USHORT Flags;                                                           //0x0
	USHORT Length;                                                          //0x2
	ULONG TimeStamp;                                                        //0x4
	STRING DosPath;                                                 //0x8
}RTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS64
{
	ULONG MaximumLength;                                                    //0x0
	ULONG Length;                                                           //0x4
	ULONG Flags;                                                            //0x8
	ULONG DebugFlags;                                                       //0xc
	VOID* ConsoleHandle;                                                    //0x10
	ULONG ConsoleFlags;                                                     //0x18
	VOID* StandardInput;                                                    //0x20
	VOID* StandardOutput;                                                   //0x28
	VOID* StandardError;                                                    //0x30
	CURDIR CurrentDirectory;                                        //0x38
	UNICODE_STRING DllPath;                                         //0x50
	UNICODE_STRING ImagePathName;                                   //0x60
	UNICODE_STRING CommandLine;                                     //0x70
	VOID* Environment;                                                      //0x80
	ULONG StartingX;                                                        //0x88
	ULONG StartingY;                                                        //0x8c
	ULONG CountX;                                                           //0x90
	ULONG CountY;                                                           //0x94
	ULONG CountCharsX;                                                      //0x98
	ULONG CountCharsY;                                                      //0x9c
	ULONG FillAttribute;                                                    //0xa0
	ULONG WindowFlags;                                                      //0xa4
	ULONG ShowWindowFlags;                                                  //0xa8
	UNICODE_STRING WindowTitle;                                     //0xb0
	UNICODE_STRING DesktopInfo;                                     //0xc0
	UNICODE_STRING ShellInfo;                                       //0xd0
	UNICODE_STRING RuntimeData;                                     //0xe0
	RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];                  //0xf0
	ULONGLONG EnvironmentSize;                                              //0x3f0
	ULONGLONG EnvironmentVersion;                                           //0x3f8
	VOID* PackageDependencyData;                                            //0x400
	ULONG ProcessGroupId;                                                   //0x408
	ULONG LoaderThreads;                                                    //0x40c
	UNICODE_STRING RedirectionDllName;                              //0x410
	UNICODE_STRING HeapPartitionName;                               //0x420
	ULONGLONG* DefaultThreadpoolCpuSetMasks;                                //0x430
	ULONG DefaultThreadpoolCpuSetMaskCount;                                 //0x438
	ULONG DefaultThreadpoolThreadMaximum;                                   //0x43c
}RTL_USER_PROCESS_PARAMETERS64, *PRTL_USER_PROCESS_PARAMETERS64;

typedef struct _MLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;                                    //0x0
	LIST_ENTRY InMemoryOrderLinks;                                  //0x10
	LIST_ENTRY InInitializationOrderLinks;                          //0x20
	VOID* DllBase;                                                  //0x30
	VOID* EntryPoint;                                               //0x38
	ULONG SizeOfImage;                                              //0x40
	UNICODE_STRING FullDllName;                                     //0x48
	UNICODE_STRING BaseDllName;                                     //0x58
}MLDR_DATA_TABLE_ENTRY, *PMLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;                                                           //0x0
	UCHAR Initialized;                                                      //0x4
	VOID* SsHandle;                                                         //0x8
	LIST_ENTRY InLoadOrderModuleList;                               //0x10
	LIST_ENTRY InMemoryOrderModuleList;                             //0x20
	LIST_ENTRY InInitializationOrderModuleList;                     //0x30
	VOID* EntryInProgress;                                                  //0x40
	UCHAR ShutdownInProgress;                                               //0x48
	VOID* ShutdownThreadId;                                                 //0x50
}PEB_LDR_DATA,*PPEB_LDR_DATA;




typedef struct _MPEB64
{
	UCHAR InheritedAddressSpace;                                            //0x0
	UCHAR ReadImageFileExecOptions;                                         //0x1
	UCHAR BeingDebugged;                                                    //0x2
	UCHAR BitField;
	UCHAR Padding0[4];                                                      //0x4
	ULONGLONG Mutant;                                                       //0x8
	ULONGLONG ImageBaseAddress;                                             //0x10
	PPEB_LDR_DATA Ldr;                                                          //0x18
	PRTL_USER_PROCESS_PARAMETERS64 ProcessParameters;                                            //0x20
}MPEB64,*PMPEB64;

#pragma pack(4)
//typedef struct _PEB_LDR_DATA32
//{
//	ULONG Length;                                                           //0x0
//	UCHAR Initialized;                                                      //0x4
//	ULONG SsHandle;                                                         //0x8
//	LIST_ENTRY32 InLoadOrderModuleList;										//0xc
//	LIST_ENTRY32 InMemoryOrderModuleList;								   //0x14
//	LIST_ENTRY32 InInitializationOrderModuleList;                          //0x1c
//	ULONG EntryInProgress;                                                  //0x24
//	UCHAR ShutdownInProgress;                                               //0x28
//	ULONG ShutdownThreadId;                                                 //0x2c
//}PEB_LDR_DATA32, *PPEB_LDR_DATA32;

//typedef struct _LDR_DATA_TABLE_ENTRY32
//{
//	LIST_ENTRY32 InLoadOrderLinks;                                    //0x0
//	LIST_ENTRY32 InMemoryOrderLinks;                                  //0x8
//	LIST_ENTRY32 InInitializationOrderLinks;                          //0x10
//	ULONG DllBase;                                                          //0x18
//	ULONG EntryPoint;                                                       //0x1c
//	ULONG SizeOfImage;                                                      //0x20
//	UNICODE_STRING32 FullDllName;                                     //0x24
//	UNICODE_STRING32 BaseDllName;                                     //0x2c
//}LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

typedef struct _CURDIR32
{
	UNICODE_STRING32 DosPath;                                         //0x0
	ULONG Handle;                                                           //0x8
}CURDIR32,*PCURDIR32;

typedef struct _RTL_DRIVE_LETTER_CURDIR32
{
	USHORT Flags;                                                           //0x0
	USHORT Length;                                                          //0x2
	ULONG TimeStamp;                                                        //0x4
	STRING32 DosPath;                                                 //0x8
}RTL_DRIVE_LETTER_CURDIR32,*PRTL_DRIVE_LETTER_CURDIR32;

typedef struct _RTL_USER_PROCESS_PARAMETERS32
{
	ULONG MaximumLength;                                                    //0x0
	ULONG Length;                                                           //0x4
	ULONG Flags;                                                            //0x8
	ULONG DebugFlags;                                                       //0xc
	ULONG ConsoleHandle;                                                    //0x10
	ULONG ConsoleFlags;                                                     //0x14
	ULONG StandardInput;                                                    //0x18
	ULONG StandardOutput;                                                   //0x1c
	ULONG StandardError;                                                    //0x20
	CURDIR32 CurrentDirectory;                                        //0x24
	UNICODE_STRING32 DllPath;                                         //0x30
	UNICODE_STRING32 ImagePathName;                                   //0x38
	UNICODE_STRING32 CommandLine;                                     //0x40
	ULONG Environment;                                                      //0x48
	ULONG StartingX;                                                        //0x4c
	ULONG StartingY;                                                        //0x50
	ULONG CountX;                                                           //0x54
	ULONG CountY;                                                           //0x58
	ULONG CountCharsX;                                                      //0x5c
	ULONG CountCharsY;                                                      //0x60
	ULONG FillAttribute;                                                    //0x64
	ULONG WindowFlags;                                                      //0x68
	ULONG ShowWindowFlags;                                                  //0x6c
	UNICODE_STRING32 WindowTitle;                                     //0x70
	UNICODE_STRING32 DesktopInfo;                                     //0x78
	UNICODE_STRING32 ShellInfo;                                       //0x80
	UNICODE_STRING32 RuntimeData;                                     //0x88
	RTL_DRIVE_LETTER_CURDIR32 CurrentDirectores[32];                  //0x90
	ULONG EnvironmentSize;                                                  //0x290
	ULONG EnvironmentVersion;                                               //0x294
	ULONG PackageDependencyData;                                            //0x298
	ULONG ProcessGroupId;                                                   //0x29c
	ULONG LoaderThreads;                                                    //0x2a0
	UNICODE_STRING32 RedirectionDllName;                              //0x2a4
	UNICODE_STRING32 HeapPartitionName;                               //0x2ac
	ULONG DefaultThreadpoolCpuSetMasks;                                //0x2b4
	ULONG DefaultThreadpoolCpuSetMaskCount;                                 //0x2b8
	ULONG DefaultThreadpoolThreadMaximum;                                   //0x2bc
}RTL_USER_PROCESS_PARAMETERS32,*PRTL_USER_PROCESS_PARAMETERS32;

typedef struct _MPEB32
{
	UCHAR InheritedAddressSpace;                                            //0x0
	UCHAR ReadImageFileExecOptions;                                         //0x1
	UCHAR BeingDebugged;                                                    //0x2
	UCHAR BitField;
	ULONG Mutant;                                                           //0x4
	ULONG ImageBaseAddress;                                                 //0x8
	ULONG Ldr;                                                              //0xc
	ULONG ProcessParameters;                                                //0x10
}MPEB32, *PMPEB32;
#pragma pack(8)

BOOLEAN FakeProcessByPid(PEPROCESS fakeProcess, HANDLE SrcPid);

EXTERN_C BOOLEAN Fm_FakeProcess(ULONG64 MyPid, ULONG64 fakepid);

