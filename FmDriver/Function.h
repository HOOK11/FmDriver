#include <ntifs.h>
#include"Struct.h"

typedef struct _PEB32
{
	UCHAR InheritedAddressSpace;                                            //0x0
	UCHAR ReadImageFileExecOptions;                                         //0x1
	UCHAR BeingDebugged;                                                    //0x2
	union
	{
		UCHAR BitField;                                                     //0x3
		struct
		{
			UCHAR ImageUsesLargePages : 1;                                    //0x3
			UCHAR IsProtectedProcess : 1;                                     //0x3
			UCHAR IsLegacyProcess : 1;                                        //0x3
			UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
			UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
			UCHAR SpareBits : 3;                                              //0x3
		};
	};
	ULONG Mutant;                                                           //0x4
	ULONG ImageBaseAddress;                                                 //0x8
	ULONG Ldr;                                                              //0xc

}PEB32, * PPEB32;

typedef struct _PEB_LDR_DATA32
{
	ULONG Length;                                                           //0x0
	UCHAR Initialized;                                                      //0x4
	ULONG SsHandle;                                                         //0x8
	LIST_ENTRY32 InLoadOrderModuleList;                               //0xc
	LIST_ENTRY32 InMemoryOrderModuleList;                             //0x14
	LIST_ENTRY32 InInitializationOrderModuleList;                     //0x1c
	ULONG Entr32yInProgress;                                                  //0x24
	UCHAR ShutdownInProgress;                                               //0x28
	ULONG ShutdownThreadId;                                                 //0x2c
}PEB_LDR_DATA32, * PPEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32 InLoadOrderLinks;                                    //0x0
	LIST_ENTRY32 InMemoryOrderLinks;                                  //0x8
	LIST_ENTRY32 InInitializationOrderLinks;                          //0x10
	ULONG DllBase;                                                          //0x18
	ULONG EntryPoint;                                                       //0x1c
	ULONG SizeOfImage;                                                      //0x20
	UNICODE_STRING32 FullDllName;                                     //0x24
	UNICODE_STRING32 BaseDllName;                                     //0x2c
}LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

typedef struct _PEB_LDR_DATA64
{
	ULONG Length;                                                           //0x0
	UCHAR Initialized;                                                      //0x4
	VOID* SsHandle;                                                         //0x8
	struct _LIST_ENTRY InLoadOrderModuleList;                               //0x10
	struct _LIST_ENTRY InMemoryOrderModuleList;                             //0x20
	struct _LIST_ENTRY InInitializationOrderModuleList;                     //0x30
	VOID* EntryInProgress;                                                  //0x40
	UCHAR ShutdownInProgress;                                               //0x48
	VOID* ShutdownThreadId;                                                 //0x50
}PEB_LDR_DATA64, * PPEB_LDR_DATA64;

typedef struct _LDR_DATA_TABLE_ENTRY64
{
	struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
	struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
	struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
	VOID* DllBase;                                                          //0x30
	VOID* EntryPoint;                                                       //0x38
	ULONG SizeOfImage;                                                      //0x40
	struct _UNICODE_STRING FullDllName;                                     //0x48
	struct _UNICODE_STRING BaseDllName;                                     //0x58
	ULONG Flags;                                                            //0x68
	USHORT LoadCount;                                                       //0x6c
	USHORT TlsIndex;                                                        //0x6e
	union
	{
		struct _LIST_ENTRY HashLinks;                                       //0x70
		struct
		{
			VOID* SectionPointer;                                           //0x70
			ULONG CheckSum;                                                 //0x78
		};
	};
	union
	{
		ULONG TimeDateStamp;                                                //0x80
		VOID* LoadedImports;                                                //0x80
	};
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
	VOID* PatchInformation;                                                 //0x90
	struct _LIST_ENTRY ForwarderLinks;                                      //0x98
	struct _LIST_ENTRY ServiceTagLinks;                                     //0xa8
	struct _LIST_ENTRY StaticLinks;                                         //0xb8
	VOID* ContextInformation;                                               //0xc8
	ULONGLONG OriginalBase;                                                 //0xd0
	union _LARGE_INTEGER LoadTime;                                          //0xd8
}LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;



#define PFN_TO_PAGE(pfn) (pfn << PAGE_SHIFT)
#define PAGE_TO_PFN(pfn) (pfn >> PAGE_SHIFT)

#pragma warning(push)
#pragma warning(disable : 4201) // nonstandard extension used: nameless struct/union

#pragma pack(push, 1)
typedef union CR3_
{
	ULONG64 Value;
	struct
	{
		ULONG64 Ignored1 : 3;
		ULONG64 WriteThrough : 1;
		ULONG64 CacheDisable : 1;
		ULONG64 Ignored2 : 7;
		ULONG64 Pml4 : 40;
		ULONG64 Reserved : 12;
	};
} PTE_CR3;

typedef union VIRT_ADDR_
{
	ULONG64 Value;
	void* Pointer;
	struct
	{
		ULONG64 Offset : 12;
		ULONG64 PtIndex : 9;
		ULONG64 PdIndex : 9;
		ULONG64 PdptIndex : 9;
		ULONG64 Pml4Index : 9;
		ULONG64 Reserved : 16;
	};
} VIRTUAL_ADDRESS;

typedef union PML4E_
{
	ULONG64 Value;
	struct
	{
		ULONG64 Present : 1;
		ULONG64 Rw : 1;
		ULONG64 User : 1;
		ULONG64 WriteThrough : 1;
		ULONG64 CacheDisable : 1;
		ULONG64 Accessed : 1;
		ULONG64 Ignored1 : 1;
		ULONG64 Reserved1 : 1;
		ULONG64 Ignored2 : 4;
		ULONG64 Pdpt : 40;
		ULONG64 Ignored3 : 11;
		ULONG64 Xd : 1;
	};
} PML4E;

typedef union PDPTE_
{
	ULONG64 Value;
	struct
	{
		ULONG64 Present : 1;
		ULONG64 Rw : 1;
		ULONG64 User : 1;
		ULONG64 WriteThrough : 1;
		ULONG64 CacheDisable : 1;
		ULONG64 Accessed : 1;
		ULONG64 Dirty : 1;
		ULONG64 PageSize : 1;
		ULONG64 Ignored2 : 4;
		ULONG64 Pd : 40;
		ULONG64 Ignored3 : 11;
		ULONG64 Xd : 1;
	};
} PDPTE;

typedef union PDE_
{
	ULONG64 Value;
	struct
	{
		ULONG64 Present : 1;
		ULONG64 Rw : 1;
		ULONG64 User : 1;
		ULONG64 WriteThrough : 1;
		ULONG64 CacheDisable : 1;
		ULONG64 Accessed : 1;
		ULONG64 Dirty : 1;
		ULONG64 PageSize : 1;
		ULONG64 Ignored2 : 4;
		ULONG64 Pt : 40;
		ULONG64 Ignored3 : 11;
		ULONG64 Xd : 1;
	};
} PDE;
typedef union PTE_
{
	ULONG64 Value;
	VIRTUAL_ADDRESS VirtualAddress;
	struct
	{
		ULONG64 Present : 1;
		ULONG64 Rw : 1;
		ULONG64 User : 1;
		ULONG64 WriteThrough : 1;
		ULONG64 CacheDisable : 1;
		ULONG64 Accessed : 1;
		ULONG64 Dirty : 1;
		ULONG64 Pat : 1;
		ULONG64 Global : 1;
		ULONG64 Ignored1 : 3;
		ULONG64 PFN : 40;
		ULONG64 Ignored3 : 11;
		ULONG64 Xd : 1;
	};
} PTE;
typedef struct _MMPTE_HARDWARE
{
	struct /* bitfield */
	{
		/* 0x0000 */ unsigned __int64 Valid : 1; /* bit position: 0 */
		/* 0x0000 */ unsigned __int64 Dirty1 : 1; /* bit position: 1 */
		/* 0x0000 */ unsigned __int64 Owner : 1; /* bit position: 2 */
		/* 0x0000 */ unsigned __int64 WriteThrough : 1; /* bit position: 3 */
		/* 0x0000 */ unsigned __int64 CacheDisable : 1; /* bit position: 4 */
		/* 0x0000 */ unsigned __int64 Accessed : 1; /* bit position: 5 */
		/* 0x0000 */ unsigned __int64 Dirty : 1; /* bit position: 6 */
		/* 0x0000 */ unsigned __int64 LargePage : 1; /* bit position: 7 */
		/* 0x0000 */ unsigned __int64 Global : 1; /* bit position: 8 */
		/* 0x0000 */ unsigned __int64 CopyOnWrite : 1; /* bit position: 9 */
		/* 0x0000 */ unsigned __int64 Unused : 1; /* bit position: 10 */
		/* 0x0000 */ unsigned __int64 Write : 1; /* bit position: 11 */
		/* 0x0000 */ unsigned __int64 PageFrameNumber : 36; /* bit position: 12 */
		/* 0x0000 */ unsigned __int64 ReservedForHardware : 4; /* bit position: 48 */
		/* 0x0000 */ unsigned __int64 ReservedForSoftware : 4; /* bit position: 52 */
		/* 0x0000 */ unsigned __int64 WsleAge : 4; /* bit position: 56 */
		/* 0x0000 */ unsigned __int64 WsleProtection : 3; /* bit position: 60 */
		/* 0x0000 */ unsigned __int64 NoExecute : 1; /* bit position: 63 */
	}; /* bitfield */
} MMPTE_HARDWARE, * PMMPTE_HARDWARE; /* size: 0x0008 */

typedef struct _MMPTE_PROTOTYPE
{
	struct /* bitfield */
	{
		/* 0x0000 */ unsigned __int64 Valid : 1; /* bit position: 0 */
		/* 0x0000 */ unsigned __int64 DemandFillProto : 1; /* bit position: 1 */
		/* 0x0000 */ unsigned __int64 HiberVerifyConverted : 1; /* bit position: 2 */
		/* 0x0000 */ unsigned __int64 ReadOnly : 1; /* bit position: 3 */
		/* 0x0000 */ unsigned __int64 SwizzleBit : 1; /* bit position: 4 */
		/* 0x0000 */ unsigned __int64 Protection : 5; /* bit position: 5 */
		/* 0x0000 */ unsigned __int64 Prototype : 1; /* bit position: 10 */
		/* 0x0000 */ unsigned __int64 Combined : 1; /* bit position: 11 */
		/* 0x0000 */ unsigned __int64 Unused1 : 4; /* bit position: 12 */
		/* 0x0000 */ __int64 ProtoAddress : 48; /* bit position: 16 */
	}; /* bitfield */
} MMPTE_PROTOTYPE, * PMMPTE_PROTOTYPE; /* size: 0x0008 */

typedef struct _MMPTE_SOFTWARE
{
	struct /* bitfield */
	{
		/* 0x0000 */ unsigned __int64 Valid : 1; /* bit position: 0 */
		/* 0x0000 */ unsigned __int64 PageFileReserved : 1; /* bit position: 1 */
		/* 0x0000 */ unsigned __int64 PageFileAllocated : 1; /* bit position: 2 */
		/* 0x0000 */ unsigned __int64 ColdPage : 1; /* bit position: 3 */
		/* 0x0000 */ unsigned __int64 SwizzleBit : 1; /* bit position: 4 */
		/* 0x0000 */ unsigned __int64 Protection : 5; /* bit position: 5 */
		/* 0x0000 */ unsigned __int64 Prototype : 1; /* bit position: 10 */
		/* 0x0000 */ unsigned __int64 Transition : 1; /* bit position: 11 */
		/* 0x0000 */ unsigned __int64 PageFileLow : 4; /* bit position: 12 */
		/* 0x0000 */ unsigned __int64 UsedPageTableEntries : 10; /* bit position: 16 */
		/* 0x0000 */ unsigned __int64 ShadowStack : 1; /* bit position: 26 */
		/* 0x0000 */ unsigned __int64 Unused : 5; /* bit position: 27 */
		/* 0x0000 */ unsigned __int64 PageFileHigh : 32; /* bit position: 32 */
	}; /* bitfield */
} MMPTE_SOFTWARE, * PMMPTE_SOFTWARE; /* size: 0x0008 */

typedef struct _MMPTE_TIMESTAMP
{
	struct /* bitfield */
	{
		/* 0x0000 */ unsigned __int64 MustBeZero : 1; /* bit position: 0 */
		/* 0x0000 */ unsigned __int64 Unused : 3; /* bit position: 1 */
		/* 0x0000 */ unsigned __int64 SwizzleBit : 1; /* bit position: 4 */
		/* 0x0000 */ unsigned __int64 Protection : 5; /* bit position: 5 */
		/* 0x0000 */ unsigned __int64 Prototype : 1; /* bit position: 10 */
		/* 0x0000 */ unsigned __int64 Transition : 1; /* bit position: 11 */
		/* 0x0000 */ unsigned __int64 PageFileLow : 4; /* bit position: 12 */
		/* 0x0000 */ unsigned __int64 Reserved : 16; /* bit position: 16 */
		/* 0x0000 */ unsigned __int64 GlobalTimeStamp : 32; /* bit position: 32 */
	}; /* bitfield */
} MMPTE_TIMESTAMP, * PMMPTE_TIMESTAMP; /* size: 0x0008 */

typedef struct _MMPTE_TRANSITION
{
	struct /* bitfield */
	{
		/* 0x0000 */ unsigned __int64 Valid : 1; /* bit position: 0 */
		/* 0x0000 */ unsigned __int64 Write : 1; /* bit position: 1 */
		/* 0x0000 */ unsigned __int64 Spare : 1; /* bit position: 2 */
		/* 0x0000 */ unsigned __int64 IoTracker : 1; /* bit position: 3 */
		/* 0x0000 */ unsigned __int64 SwizzleBit : 1; /* bit position: 4 */
		/* 0x0000 */ unsigned __int64 Protection : 5; /* bit position: 5 */
		/* 0x0000 */ unsigned __int64 Prototype : 1; /* bit position: 10 */
		/* 0x0000 */ unsigned __int64 Transition : 1; /* bit position: 11 */
		/* 0x0000 */ unsigned __int64 PageFrameNumber : 36; /* bit position: 12 */
		/* 0x0000 */ unsigned __int64 Unused : 16; /* bit position: 48 */
	}; /* bitfield */
} MMPTE_TRANSITION, * PMMPTE_TRANSITION; /* size: 0x0008 */

typedef struct _MMPTE_SUBSECTION
{
	struct /* bitfield */
	{
		/* 0x0000 */ unsigned __int64 Valid : 1; /* bit position: 0 */
		/* 0x0000 */ unsigned __int64 Unused0 : 3; /* bit position: 1 */
		/* 0x0000 */ unsigned __int64 SwizzleBit : 1; /* bit position: 4 */
		/* 0x0000 */ unsigned __int64 Protection : 5; /* bit position: 5 */
		/* 0x0000 */ unsigned __int64 Prototype : 1; /* bit position: 10 */
		/* 0x0000 */ unsigned __int64 ColdPage : 1; /* bit position: 11 */
		/* 0x0000 */ unsigned __int64 Unused1 : 3; /* bit position: 12 */
		/* 0x0000 */ unsigned __int64 ExecutePrivilege : 1; /* bit position: 15 */
		/* 0x0000 */ __int64 SubsectionAddress : 48; /* bit position: 16 */
	}; /* bitfield */
} MMPTE_SUBSECTION, * PMMPTE_SUBSECTION; /* size: 0x0008 */

typedef struct _MMPTE_LIST
{
	struct /* bitfield */
	{
		/* 0x0000 */ unsigned __int64 Valid : 1; /* bit position: 0 */
		/* 0x0000 */ unsigned __int64 OneEntry : 1; /* bit position: 1 */
		/* 0x0000 */ unsigned __int64 filler0 : 2; /* bit position: 2 */
		/* 0x0000 */ unsigned __int64 SwizzleBit : 1; /* bit position: 4 */
		/* 0x0000 */ unsigned __int64 Protection : 5; /* bit position: 5 */
		/* 0x0000 */ unsigned __int64 Prototype : 1; /* bit position: 10 */
		/* 0x0000 */ unsigned __int64 Transition : 1; /* bit position: 11 */
		/* 0x0000 */ unsigned __int64 filler1 : 16; /* bit position: 12 */
		/* 0x0000 */ unsigned __int64 NextEntry : 36; /* bit position: 28 */
	}; /* bitfield */
} MMPTE_LIST, * PMMPTE_LIST; /* size: 0x0008 */

typedef struct _MMPTE
{
	union
	{
		union
		{
			/* 0x0000 */ unsigned __int64 Long;
			/* 0x0000 */ volatile unsigned __int64 VolatileLong;
			/* 0x0000 */ struct _MMPTE_HARDWARE Hard;
			/* 0x0000 */ struct _MMPTE_PROTOTYPE Proto;
			/* 0x0000 */ struct _MMPTE_SOFTWARE Soft;
			/* 0x0000 */ struct _MMPTE_TIMESTAMP TimeStamp;
			/* 0x0000 */ struct _MMPTE_TRANSITION Trans;
			/* 0x0000 */ struct _MMPTE_SUBSECTION Subsect;
			/* 0x0000 */ struct _MMPTE_LIST List;
		}; /* size: 0x0008 */
	} /* size: 0x0008 */ u;
} MMPTE, * PMMPTE; /* size: 0x0008 */
#pragma pack(pop)

typedef struct _PAGE
{
	PVOID VirtualAddress;
	PTE* PTE;

	ULONG64 PreviousPageFrame;
} _PAGE;

NTSTATUS InitMemory();

void ReadProcessMemory(PEPROCESS GameEProcess, IN  PVOID BaseAddress, OUT PVOID Buffer, IN ULONG Length);

void ReadPhysicalAddress(const UINT32 pageIndex, const ULONG64 targetAddress, const PVOID buffer, const SIZE_T size);

EXTERN_C PVOID PsGetProcessSectionBaseAddress(PEPROCESS Process);

EXTERN_C ULONG_PTR NTAPI PsGetProcessPeb(PEPROCESS proc);

EXTERN_C CHAR* PsGetProcessImageFileName(__in PEPROCESS Process);

EXTERN_C NTSTATUS  MmCopyVirtualMemory(PEPROCESS FromProcess, PVOID FromAddress,
	PEPROCESS ToProcess, PVOID ToAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode,
	PSIZE_T NumberOfBytesCopied);



//ULONG64 Fm_InitDecrypt(ULONG64 PID, ULONG64 Encrypted, PUCHAR CodeBuffer);


PVOID Fm_AllocMemory(ULONG64 PID, SIZE_T size);

PEPROCESS FindProcess(char* processName);

NTSTATUS Fm_QueryMemory(ULONG64 Pid, ULONG64 VirtualAddress, PFMMEMORY_BASIC_INFORMATION InfoMode);

ULONG64 Fm_GetExeModule(ULONG64 Pid);

ULONG64 Fm_GetModeBase(ULONG64 Pid, char* ModeName);

NTSTATUS Fm_ReadMemory(ULONG64 Pid, ULONG64 Address, ULONG64 Buffer, ULONG64 Size);

NTSTATUS Fm_WriteMemory(ULONG64 Pid, ULONG64 Address, ULONG64 Buffer, ULONG64 Size);

ULONG_PTR GetProcAddressR(ULONG_PTR hModule, const char* lpProcName, BOOLEAN x64Module);

ULONG GetWindowsVersionNumber();
