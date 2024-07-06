
#include"FakeProcess.h"
#include "Function.h"

//EXTERN_C NTSTATUS MmCopyVirtualMemory(
//	IN PEPROCESS FromProcess,
//	IN CONST VOID* FromAddress,
//	IN PEPROCESS ToProcess,
//	OUT PVOID ToAddress,
//	IN SIZE_T BufferSize,
//	IN KPROCESSOR_MODE PreviousMode,
//	OUT PSIZE_T NumberOfBytesCopied
//);

EXTERN_C void* PsGetProcessWow64Process(PEPROCESS Process);

//EXTERN_C PCHAR PsGetProcessImageFileName(PEPROCESS Process);

//EXTERN_C PPEB  PsGetProcessPeb(PEPROCESS Process);

EXTERN_C NTSTATUS PsReferenceProcessFilePointer(PEPROCESS Process, PFILE_OBJECT* OutFileObject);

EXTERN_C NTSTATUS ObQueryNameString(PVOID Object, POBJECT_NAME_INFORMATION ObjectNameInfo, ULONG Length, PULONG ReturnLength);




ULONG GetLocateProcessImageNameOffset()
{
	RTL_OSVERSIONINFOEXW version = {0};

	RtlGetVersion(&version);
	
	UNICODE_STRING unName;

	RtlInitUnicodeString(&unName, L"PsGetProcessPeb");

	PUCHAR funcAddr = (PUCHAR)MmGetSystemRoutineAddress(&unName);

	ULONG pebOffset = *(PULONG)(funcAddr + 3);

	ULONG seOffset = 0;

	//7 58
	//win11 70
	//1507 68

	if (version.dwBuildNumber == 7600 || version.dwBuildNumber == 7601)
	{
		seOffset = pebOffset + 0x58;
	}
	else if(version.dwBuildNumber >7601 && version.dwBuildNumber <= 10240)
	{
		seOffset = pebOffset + 0x68;
	}
	else 
	{
		seOffset = pebOffset + 0x70;
	}
	
	return seOffset;
}

ULONG GetProcessFileObjectOffset()
{
	RTL_OSVERSIONINFOEXW version = { 0 };
	RtlGetVersion(&version);
	if (version.dwMajorVersion == 10)
	{
		if (version.dwBuildNumber != 10240)
		{
			UNICODE_STRING uni = { 0 };

			RtlInitUnicodeString(&uni, L"PsGetProcessImageFileName");
			PUCHAR p = (PUCHAR)MmGetSystemRoutineAddress(&uni);
			ULONG offset = *(PULONG)(p + 3);
			if (offset)
			{
				offset -= 8;
			}
			return offset;
		}
	}

	return 0;
}

//修改进程名字
void resetProcessImageName(PEPROCESS fakeProcess, PEPROCESS srcProcess)
{
	PCHAR imageName = PsGetProcessImageFileName(fakeProcess);

	PCHAR targetName = PsGetProcessImageFileName(srcProcess);

	memcpy(imageName, targetName, 15);

}

//修改全路径
void resetProcessFullName(PEPROCESS fakeProcess, PEPROCESS srcProcess)
{
	PUNICODE_STRING pTargetFullName = NULL;
	
	NTSTATUS status = SeLocateProcessImageName(srcProcess,&pTargetFullName);
	
	if (!NT_SUCCESS(status))
	{
		return;
	}
	
	ULONG seOffset = GetLocateProcessImageNameOffset();

	POBJECT_NAME_INFORMATION pSeInfo = (POBJECT_NAME_INFORMATION)*((PULONG64)((PUCHAR)fakeProcess + seOffset));

	if (pSeInfo->Name.Length >= pTargetFullName->Length)
	{
		memset(pSeInfo->Name.Buffer, 0, pSeInfo->Name.MaximumLength);

		memcpy(pSeInfo->Name.Buffer, pTargetFullName->Buffer, pTargetFullName->Length);

	}
	else 
	{
		//申请一块内存
		SIZE_T size = pTargetFullName->MaximumLength + sizeof(UNICODE_STRING);
		
		PUNICODE_STRING uname = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, size, 'fIeS');

		uname->MaximumLength = pTargetFullName->MaximumLength;
		
		uname->Length = pTargetFullName->Length;

		uname->Buffer = (PWCH)((PUCHAR)uname + sizeof(UNICODE_STRING));

		memcpy(uname->Buffer, pTargetFullName->Buffer, pTargetFullName->Length);

		ExFreePool(pSeInfo);

		*((PULONG64)((PUCHAR)fakeProcess + seOffset)) = (ULONG64)uname;
	}

	ExFreePool(pTargetFullName);

}

//修改文件对象路径
void resetProcessFileObjectName(PEPROCESS fakeProcess, PEPROCESS srcProcess)
{
	PFILE_OBJECT fakeFileObj = NULL;

	PFILE_OBJECT srcFileObj = NULL;

	OBJECT_NAME_INFORMATION srcFileName;

	
	NTSTATUS status = PsReferenceProcessFilePointer(srcProcess, &srcFileObj);
	
	if (!NT_SUCCESS(status))
	{
		return;
	}

	status = PsReferenceProcessFilePointer(fakeProcess, &fakeFileObj);

	if (!NT_SUCCESS(status))
	{
		ObDereferenceObject(srcFileObj);
		return;
	}

	PUNICODE_STRING usrcName = &srcFileObj->FileName;
	
	PUNICODE_STRING ufakeName = &fakeFileObj->FileName;

	PWCH fakeName = NULL;

	if(ufakeName->Length >= usrcName->Length)
	{
		memset(ufakeName->Buffer, 0, usrcName->MaximumLength);

		memcpy(ufakeName->Buffer, usrcName->Buffer, usrcName->Length);

		fakeName = ufakeName->Buffer;

		
		
	}
	else
	{
		//申请一块内存
		SIZE_T size = usrcName->MaximumLength;

		fakeName = (PWCH)ExAllocatePool(NonPagedPool, size);
		
		memset(fakeName, 0, size);

		memcpy(fakeName, usrcName->Buffer, usrcName->Length);

		ufakeName->Buffer = fakeName;

	}

	ufakeName->MaximumLength = usrcName->MaximumLength;

	ufakeName->Length = usrcName->Length;

	ULONG64 fsContext2 = *(PULONG64)((PUCHAR)fakeFileObj + 0x20);

	if (MmIsAddressValid((PUCHAR)fsContext2))
	{
		PUNICODE_STRING unfsContextName = (PUNICODE_STRING)(fsContext2 + 0x10);

		if (unfsContextName->Length && unfsContextName->MaximumLength)
		{
			unfsContextName->Buffer = fakeName;
			unfsContextName->Length = ufakeName->Length;
			unfsContextName->MaximumLength = ufakeName->MaximumLength;
		}
	}

	fakeFileObj->DeviceObject = srcFileObj->DeviceObject;
	fakeFileObj->Vpb = srcFileObj->Vpb;

	ObDereferenceObject(srcFileObj);

	ObDereferenceObject(fakeFileObj);
}

//修改WIN10路径
void resetProcessFileObjectNameWin10(PEPROCESS fakeProcess, PEPROCESS srcProcess)
{
	RTL_OSVERSIONINFOEXW version = { 0 };

	RtlGetVersion(&version);

	if (version.dwMajorVersion < 10)
	{
		return;
	}

	ULONG fileOffset = GetProcessFileObjectOffset();

	PFILE_OBJECT fakeFileObj = (PFILE_OBJECT)*(PULONG64)(fileOffset + (PUCHAR)fakeProcess);

	PFILE_OBJECT srcFileObj = (PFILE_OBJECT)*(PULONG64)(fileOffset + (PUCHAR)srcProcess);;

	OBJECT_NAME_INFORMATION srcFileName;


	
	PUNICODE_STRING usrcName = &srcFileObj->FileName;

	PUNICODE_STRING ufakeName = &fakeFileObj->FileName;

	PWCH fakeName = NULL;

	if (ufakeName->Length >= usrcName->Length)
	{
		memset(ufakeName->Buffer, 0, usrcName->MaximumLength);

		memcpy(ufakeName->Buffer, usrcName->Buffer, usrcName->Length);

		fakeName = ufakeName->Buffer;



	}
	else
	{
		//申请一块内存
		SIZE_T size = usrcName->MaximumLength;

		fakeName = (PWCH)ExAllocatePool(NonPagedPool, size);

		memset(fakeName, 0, size);

		memcpy(fakeName, usrcName->Buffer, usrcName->Length);

		ufakeName->Buffer = fakeName;

	}

	ufakeName->MaximumLength = usrcName->MaximumLength;

	ufakeName->Length = usrcName->Length;

	ULONG64 fsContext2 = *(PULONG64)((PUCHAR)fakeFileObj + 0x20);

	if (MmIsAddressValid((PUCHAR)fsContext2))
	{
		PUNICODE_STRING unfsContextName = (PUNICODE_STRING)(fsContext2 + 0x10);

		if (unfsContextName->Length && unfsContextName->MaximumLength)
		{
			unfsContextName->Buffer = fakeName;
			unfsContextName->Length = ufakeName->Length;
			unfsContextName->MaximumLength = ufakeName->MaximumLength;
		}
	}

	fakeFileObj->DeviceObject = srcFileObj->DeviceObject;
	fakeFileObj->Vpb = srcFileObj->Vpb;

	
}

PVOID GetTokenUserSidPointer(PVOID token)
{
	RTL_OSVERSIONINFOEXW version = { 0 };

	RtlGetVersion(&version);

	int offset = 0;

	PVOID result = NULL;

	if (version.dwBuildNumber == 7600 || version.dwBuildNumber == 7601)
	{
		offset = 0x90;
	}
	else
	{
		offset = 0x98;
	}

	if (offset)
	{
		ULONG64 userGs = *(PULONG64)((ULONG64)token + offset);
		if (userGs)
		{
			result = (PVOID)(*(PULONG64)userGs);
		}
	}

	return result;
}

void resetProcessTokenGroup(PEPROCESS fakeProcess, PEPROCESS srcProcess)
{

	ULONG64 pSystemToken = PsReferencePrimaryToken(srcProcess);
	ULONG64 MyToken = PsReferencePrimaryToken(fakeProcess);

	PVOID mvt = GetTokenUserSidPointer((PVOID)MyToken);
	PVOID svt = GetTokenUserSidPointer((PVOID)pSystemToken);
	if (mvt && svt)
	{
		memcpy(mvt, svt, 0x20);
	}

	ObDereferenceObject(pSystemToken);
	ObDereferenceObject(MyToken);
}

void resetProcessPeb64Param(PEPROCESS fakeProcess, PEPROCESS srcProcess)
{

	PMPEB64 fakePeb = (PMPEB64)PsGetProcessPeb(fakeProcess);

	PMPEB64 srcPeb = (PMPEB64)PsGetProcessPeb(srcProcess);

	if (!srcPeb || !fakePeb) return;

	KAPC_STATE fakeApcState = { 0 };

	KAPC_STATE srcApcState = {0};

	UNICODE_STRING ImagePathName = { 0 };
	UNICODE_STRING CommandLine = { 0 };
	UNICODE_STRING WindowTitle = { 0 };

	KeStackAttachProcess(srcProcess, &srcApcState);

	//防止隐藏驱动读R3内存蓝屏
	SIZE_T pro = NULL;
	MmCopyVirtualMemory(srcProcess, srcPeb, srcProcess, srcPeb, 1, UserMode, &pro);

	MmCopyVirtualMemory(srcProcess, srcPeb->ProcessParameters, srcProcess, srcPeb->ProcessParameters, 1, UserMode, &pro);

	if (srcPeb->ProcessParameters->ImagePathName.Length)
	{
		ImagePathName.Buffer = ExAllocatePool(NonPagedPool, srcPeb->ProcessParameters->ImagePathName.MaximumLength);
		memcpy(ImagePathName.Buffer, srcPeb->ProcessParameters->ImagePathName.Buffer, srcPeb->ProcessParameters->ImagePathName.Length);
		ImagePathName.Length = srcPeb->ProcessParameters->ImagePathName.Length;
		ImagePathName.MaximumLength = srcPeb->ProcessParameters->ImagePathName.MaximumLength;
	}
	
	
	if (srcPeb->ProcessParameters->CommandLine.Length)
	{
		CommandLine.Buffer = ExAllocatePool(NonPagedPool, srcPeb->ProcessParameters->CommandLine.MaximumLength);
		memcpy(CommandLine.Buffer, srcPeb->ProcessParameters->CommandLine.Buffer, srcPeb->ProcessParameters->CommandLine.Length);
		CommandLine.Length = srcPeb->ProcessParameters->CommandLine.Length;
		CommandLine.MaximumLength = srcPeb->ProcessParameters->CommandLine.MaximumLength;
	}
	
	
	if (srcPeb->ProcessParameters->WindowTitle.Length)
	{
		WindowTitle.Buffer = ExAllocatePool(NonPagedPool, srcPeb->ProcessParameters->WindowTitle.MaximumLength);
		memcpy(WindowTitle.Buffer, srcPeb->ProcessParameters->WindowTitle.Buffer, srcPeb->ProcessParameters->WindowTitle.Length);
		WindowTitle.Length = srcPeb->ProcessParameters->WindowTitle.Length;
		WindowTitle.MaximumLength = srcPeb->ProcessParameters->WindowTitle.MaximumLength;
	}
	
	KeUnstackDetachProcess(&srcApcState);


	KeStackAttachProcess(fakeProcess, &fakeApcState);

	MmCopyVirtualMemory(fakeProcess, fakePeb, fakeProcess, fakePeb, 1, UserMode, &pro);

	MmCopyVirtualMemory(fakeProcess, fakePeb->ProcessParameters, fakeProcess, fakePeb->ProcessParameters, 1, UserMode, &pro);

	PVOID BaseAddr = NULL;
	SIZE_T size = PAGE_SIZE;
	NTSTATUS status = ZwAllocateVirtualMemory(NtCurrentProcess(), &BaseAddr, 0, &size,MEM_COMMIT,PAGE_READWRITE);
	PUCHAR tempBase = BaseAddr;


	if (fakePeb->ProcessParameters->ImagePathName.Length && ImagePathName.Length)
	{
		if (fakePeb->ProcessParameters->ImagePathName.Length >= ImagePathName.Length)
		{
			memset(fakePeb->ProcessParameters->ImagePathName.Buffer, 0, fakePeb->ProcessParameters->ImagePathName.MaximumLength);
			
			memcpy(fakePeb->ProcessParameters->ImagePathName.Buffer, ImagePathName.Buffer, ImagePathName.Length);
			
			fakePeb->ProcessParameters->ImagePathName.Length = ImagePathName.Length;
		}
		else 
		{
			if (!NT_SUCCESS(status))
			{
				memset(fakePeb->ProcessParameters->ImagePathName.Buffer, 0, fakePeb->ProcessParameters->ImagePathName.MaximumLength);
				fakePeb->ProcessParameters->ImagePathName.Length = 0;
				fakePeb->ProcessParameters->ImagePathName.MaximumLength = 0;
			}
			else 
			{
				memcpy(tempBase, ImagePathName.Buffer, ImagePathName.Length);
				fakePeb->ProcessParameters->ImagePathName.Length = ImagePathName.Length;
				fakePeb->ProcessParameters->ImagePathName.MaximumLength = ImagePathName.MaximumLength;
				fakePeb->ProcessParameters->ImagePathName.Buffer = tempBase;
				tempBase += ImagePathName.MaximumLength;
			}
		}
	}


	if (fakePeb->ProcessParameters->CommandLine.Length && CommandLine.Length)
	{
		if (fakePeb->ProcessParameters->CommandLine.Length >= CommandLine.Length)
		{
			memset(fakePeb->ProcessParameters->CommandLine.Buffer, 0, fakePeb->ProcessParameters->CommandLine.MaximumLength);

			memcpy(fakePeb->ProcessParameters->CommandLine.Buffer, CommandLine.Buffer, CommandLine.Length);

			fakePeb->ProcessParameters->CommandLine.Length = CommandLine.Length;
		}
		else
		{
			if (!NT_SUCCESS(status))
			{
				memset(fakePeb->ProcessParameters->CommandLine.Buffer, 0, fakePeb->ProcessParameters->CommandLine.MaximumLength);
				fakePeb->ProcessParameters->CommandLine.Length = 0;
				fakePeb->ProcessParameters->CommandLine.MaximumLength = 0;
			}
			else
			{
				memcpy(tempBase, CommandLine.Buffer, CommandLine.Length);
				fakePeb->ProcessParameters->CommandLine.Length = CommandLine.Length;
				fakePeb->ProcessParameters->CommandLine.MaximumLength = CommandLine.MaximumLength;
				fakePeb->ProcessParameters->CommandLine.Buffer = tempBase;
				tempBase += CommandLine.MaximumLength;
			}
		}
	}


	if (fakePeb->ProcessParameters->WindowTitle.Length && WindowTitle.Length)
	{
		if (fakePeb->ProcessParameters->WindowTitle.Length >= WindowTitle.Length)
		{
			memset(fakePeb->ProcessParameters->WindowTitle.Buffer, 0, fakePeb->ProcessParameters->WindowTitle.MaximumLength);

			memcpy(fakePeb->ProcessParameters->WindowTitle.Buffer, WindowTitle.Buffer, WindowTitle.Length);

			fakePeb->ProcessParameters->WindowTitle.Length = WindowTitle.Length;
		}
		else
		{
			if (!NT_SUCCESS(status))
			{
				memset(fakePeb->ProcessParameters->WindowTitle.Buffer, 0, fakePeb->ProcessParameters->WindowTitle.MaximumLength);
				fakePeb->ProcessParameters->WindowTitle.Length = 0;
				fakePeb->ProcessParameters->WindowTitle.MaximumLength = 0;
			}
			else
			{
				memcpy(tempBase, WindowTitle.Buffer, WindowTitle.Length);
				fakePeb->ProcessParameters->WindowTitle.Length = WindowTitle.Length;
				fakePeb->ProcessParameters->WindowTitle.MaximumLength = WindowTitle.MaximumLength;
				fakePeb->ProcessParameters->WindowTitle.Buffer = tempBase;
				
			}
		}
	}
	else 
	{
		memset(fakePeb->ProcessParameters->WindowTitle.Buffer, 0, fakePeb->ProcessParameters->WindowTitle.MaximumLength);
		fakePeb->ProcessParameters->WindowTitle.Length = 0;
		fakePeb->ProcessParameters->WindowTitle.MaximumLength = 0;
		
	}


	KeUnstackDetachProcess(&fakeApcState);

	if (ImagePathName.Length) ExFreePool(ImagePathName.Buffer);
	if (CommandLine.Length) ExFreePool(CommandLine.Buffer);
	if (WindowTitle.Length) ExFreePool(WindowTitle.Buffer);

}

void resetProcessPeb64Moudle(PEPROCESS fakeProcess, PEPROCESS srcProcess)
{
	PMPEB64 fakePeb = (PMPEB64)PsGetProcessPeb(fakeProcess);

	PMPEB64 srcPeb = (PMPEB64)PsGetProcessPeb(srcProcess);

	if (!srcPeb || !fakePeb) return;

	KAPC_STATE fakeApcState = { 0 };

	KAPC_STATE srcApcState = { 0 };

	UNICODE_STRING FullDllName = { 0 };
	ULONG baseLen = 0;

	KeStackAttachProcess(srcProcess, &srcApcState);

	//防止隐藏驱动读R3内存蓝屏
	SIZE_T pro = NULL;
	MmCopyVirtualMemory(srcProcess, srcPeb, srcProcess, srcPeb, 1, UserMode, &pro);

	MmCopyVirtualMemory(srcProcess, srcPeb->Ldr, srcProcess, srcPeb->Ldr, 1, UserMode, &pro);

	PMLDR_DATA_TABLE_ENTRY list = (PMLDR_DATA_TABLE_ENTRY)srcPeb->Ldr->InLoadOrderModuleList.Flink;

	if (list->FullDllName.Length)
	{
		FullDllName.Buffer = ExAllocatePool(NonPagedPool, list->FullDllName.MaximumLength);

		memcpy(FullDllName.Buffer, list->FullDllName.Buffer, list->FullDllName.Length);

		FullDllName.Length = list->FullDllName.Length;

		FullDllName.MaximumLength = list->FullDllName.MaximumLength;

		baseLen = (PUCHAR)list->BaseDllName.Buffer -  (PUCHAR)list->FullDllName.Buffer;
	}

	KeUnstackDetachProcess(&srcApcState);

	//附加源进程
	KeStackAttachProcess(fakeProcess, &fakeApcState);

	//防止隐藏驱动读R3内存蓝屏
	MmCopyVirtualMemory(fakeProcess, fakePeb, fakeProcess, fakePeb, 1, UserMode, &pro);

	MmCopyVirtualMemory(fakeProcess, fakePeb->Ldr, fakeProcess, fakePeb->Ldr, 1, UserMode, &pro);

	PMLDR_DATA_TABLE_ENTRY fakeList = (PMLDR_DATA_TABLE_ENTRY)fakePeb->Ldr->InLoadOrderModuleList.Flink;

	if (fakeList->FullDllName.Length >= FullDllName.Length)
	{
		memset(fakeList->FullDllName.Buffer, 0, fakeList->FullDllName.MaximumLength);

		memcpy(fakeList->FullDllName.Buffer, FullDllName.Buffer, FullDllName.Length);

		fakeList->FullDllName.Length = FullDllName.Length;
	}
	else 
	{
		PVOID BaseAddr = NULL;

		SIZE_T size = PAGE_SIZE;
		
		NTSTATUS status = ZwAllocateVirtualMemory(NtCurrentProcess(), &BaseAddr, 0, &size, MEM_COMMIT, PAGE_READWRITE);
		
		memcpy(BaseAddr, FullDllName.Buffer, FullDllName.Length);

		fakeList->FullDllName.Length = FullDllName.Length;

		fakeList->FullDllName.MaximumLength = FullDllName.MaximumLength;

		fakeList->FullDllName.Buffer = BaseAddr;
	}

	fakeList->BaseDllName.Buffer = (PUCHAR)fakeList->FullDllName.Buffer + baseLen;
	fakeList->BaseDllName.Length = fakeList->FullDllName.Length - baseLen;
	fakeList->BaseDllName.MaximumLength = baseLen + 2;

	KeUnstackDetachProcess(&fakeApcState);


	if (FullDllName.Length) ExFreePool(FullDllName.Buffer);
}

void resetProcessPeb32Param(PEPROCESS fakeProcess)
{

	PMPEB32 peb32 = (PMPEB32)PsGetProcessWow64Process(fakeProcess);

	if (!peb32) return;

	PMPEB64 fakePeb = (PMPEB64)PsGetProcessPeb(fakeProcess);


	if (!fakePeb) return;

	KAPC_STATE fakeApcState = { 0 };

	KeStackAttachProcess(fakeProcess, &fakeApcState);

	SIZE_T pro  = NULL;
	MmCopyVirtualMemory(fakeProcess, fakePeb, fakeProcess, fakePeb, 1, UserMode, &pro);

	MmCopyVirtualMemory(fakeProcess, fakePeb->ProcessParameters, fakeProcess, fakePeb->ProcessParameters, 1, UserMode, &pro);

	MmCopyVirtualMemory(fakeProcess, peb32, fakeProcess, peb32, 1, UserMode, &pro);

	PRTL_USER_PROCESS_PARAMETERS32 param32 = (PRTL_USER_PROCESS_PARAMETERS32)ULongToPtr(peb32->ProcessParameters);
	
	MmCopyVirtualMemory(fakeProcess, param32, fakeProcess,
		param32, 1, UserMode, &pro);

	PVOID BaseAddr = NULL;
	SIZE_T size = PAGE_SIZE;
	NTSTATUS status = ZwAllocateVirtualMemory(NtCurrentProcess(), &BaseAddr, 0, &size, MEM_COMMIT, PAGE_READWRITE);
	PUCHAR tempBase = BaseAddr;

	

	if (fakePeb->ProcessParameters->ImagePathName.Length)
	{
		
		if (param32->ImagePathName.Length >= fakePeb->ProcessParameters->ImagePathName.Length)
		{
			memset(param32->ImagePathName.Buffer, 0, param32->ImagePathName.MaximumLength);

			memcpy(param32->ImagePathName.Buffer, fakePeb->ProcessParameters->ImagePathName.Buffer, fakePeb->ProcessParameters->ImagePathName.Length);

			param32->ImagePathName.Length = fakePeb->ProcessParameters->ImagePathName.Length;
		}
		else
		{
			if (!NT_SUCCESS(status))
			{
				memset(param32->ImagePathName.Buffer, 0, param32->ImagePathName.MaximumLength);
				param32->ImagePathName.Length = 0;
				param32->ImagePathName.MaximumLength = 0;
			}
			else
			{
				memcpy(tempBase, fakePeb->ProcessParameters->ImagePathName.Buffer, fakePeb->ProcessParameters->ImagePathName.Length);
				param32->ImagePathName.Length =  fakePeb->ProcessParameters->ImagePathName.Length;
				param32->ImagePathName.MaximumLength = fakePeb->ProcessParameters->ImagePathName.MaximumLength ;
				param32->ImagePathName.Buffer = tempBase;
				tempBase += param32->ImagePathName.MaximumLength;
			}
		}
	}


	if (fakePeb->ProcessParameters->CommandLine.Length)
	{
		if ( param32->CommandLine.Length >= fakePeb->ProcessParameters->CommandLine.Length)
		{
			memset(param32->CommandLine.Buffer, 0, param32->CommandLine.MaximumLength);

			memcpy(param32->CommandLine.Buffer, fakePeb->ProcessParameters->CommandLine.Buffer, fakePeb->ProcessParameters->CommandLine.Length);

			param32->CommandLine.Length = fakePeb->ProcessParameters->CommandLine.Length;
		}
		else
		{
			if (!NT_SUCCESS(status))
			{
				memset(param32->CommandLine.Buffer, 0, param32->CommandLine.MaximumLength);
				param32->CommandLine.Length = 0;
				param32->CommandLine.MaximumLength = 0;

				
			}
			else
			{
				memcpy(tempBase, fakePeb->ProcessParameters->CommandLine.Buffer, fakePeb->ProcessParameters->CommandLine.Length);
				param32->CommandLine.Length = fakePeb->ProcessParameters->CommandLine.Length;
				param32->CommandLine.MaximumLength = fakePeb->ProcessParameters->CommandLine.MaximumLength;
				param32->CommandLine.Buffer = tempBase;
				tempBase += param32->CommandLine.MaximumLength;

			
			}
		}
	}

	if (fakePeb->ProcessParameters->WindowTitle.Length)
	{
		if (param32->WindowTitle.Length >= fakePeb->ProcessParameters->WindowTitle.Length)
		{
			memset(param32->WindowTitle.Buffer, 0, param32->WindowTitle.MaximumLength);

			memcpy(param32->WindowTitle.Buffer, fakePeb->ProcessParameters->WindowTitle.Buffer, fakePeb->ProcessParameters->WindowTitle.Length);

			param32->WindowTitle.Length = fakePeb->ProcessParameters->WindowTitle.Length;
		}
		else
		{
			if (!NT_SUCCESS(status))
			{
				memset(param32->WindowTitle.Buffer, 0, param32->WindowTitle.MaximumLength);
				param32->WindowTitle.Length = 0;
				param32->WindowTitle.MaximumLength = 0;


			}
			else
			{
				memcpy(tempBase, fakePeb->ProcessParameters->WindowTitle.Buffer, fakePeb->ProcessParameters->WindowTitle.Length);
				param32->WindowTitle.Length = fakePeb->ProcessParameters->WindowTitle.Length;
				param32->WindowTitle.MaximumLength = fakePeb->ProcessParameters->WindowTitle.MaximumLength;
				param32->WindowTitle.Buffer = tempBase;
				tempBase += param32->WindowTitle.MaximumLength;


			}
		}
	}
	else 
	{
		memset(param32->WindowTitle.Buffer, 0, param32->WindowTitle.MaximumLength);
		param32->WindowTitle.Length = 0;
		param32->WindowTitle.MaximumLength = 0;
	}

	KeUnstackDetachProcess(&fakeApcState);



}

void resetProcessPeb32Moudle(PEPROCESS fakeProcess)
{

	PMPEB32 peb32 = (PMPEB32)PsGetProcessWow64Process(fakeProcess);

	if (!peb32) return;

	PMPEB64 fakePeb = (PMPEB64)PsGetProcessPeb(fakeProcess);

	if (!fakePeb) return;

	KAPC_STATE fakeApcState = { 0 };


	ULONG baseLen = 0;


	//附加源进程
	KeStackAttachProcess(fakeProcess, &fakeApcState);

	SIZE_T pro = NULL;
	//防止隐藏驱动读R3内存蓝屏
	MmCopyVirtualMemory(fakeProcess, fakePeb, fakeProcess, fakePeb, 1, UserMode, &pro);

	MmCopyVirtualMemory(fakeProcess, fakePeb->Ldr, fakeProcess, fakePeb->Ldr, 1, UserMode, &pro);

	MmCopyVirtualMemory(fakeProcess, peb32, fakeProcess, peb32, 1, UserMode, &pro);

	PPEB_LDR_DATA32 pldr32 = (PPEB_LDR_DATA32)ULongToPtr(peb32->Ldr);

	MmCopyVirtualMemory(fakeProcess, pldr32, fakeProcess, pldr32, 1, UserMode, &pro);


	PMLDR_DATA_TABLE_ENTRY fakeList = (PMLDR_DATA_TABLE_ENTRY)fakePeb->Ldr->InLoadOrderModuleList.Flink;
	PLDR_DATA_TABLE_ENTRY32 fakeList32 = (PLDR_DATA_TABLE_ENTRY32)ULongToPtr(pldr32->InLoadOrderModuleList.Flink);

	if (fakeList32->FullDllName.Length >= fakeList->FullDllName.Length)
	{
		memset(fakeList32->FullDllName.Buffer, 0, fakeList32->FullDllName.MaximumLength);

		memcpy(fakeList32->FullDllName.Buffer, fakeList->FullDllName.Buffer, fakeList->FullDllName.Length);

		fakeList32->FullDllName.Length = fakeList->FullDllName.Length;
	}
	else
	{
		PVOID BaseAddr = NULL;

		SIZE_T size = PAGE_SIZE;

		NTSTATUS status = ZwAllocateVirtualMemory(NtCurrentProcess(), &BaseAddr, 0, &size, MEM_COMMIT, PAGE_READWRITE);

		memcpy(BaseAddr, fakeList->FullDllName.Buffer, fakeList->FullDllName.Length);

		fakeList32->FullDllName.Length = fakeList->FullDllName.Length;

		fakeList32->FullDllName.MaximumLength = fakeList->FullDllName.MaximumLength;

		fakeList32->FullDllName.Buffer = BaseAddr;
	}

	fakeList32->BaseDllName.Buffer = (PUCHAR)fakeList->FullDllName.Buffer + baseLen;
	fakeList32->BaseDllName.Length = fakeList->FullDllName.Length - baseLen;
	fakeList32->BaseDllName.MaximumLength = baseLen + 2;

	KeUnstackDetachProcess(&fakeApcState);

}

BOOLEAN FakeProcessByPid(PEPROCESS fakeProcess, HANDLE SrcPid)
{
	PEPROCESS Process = NULL;
	
	NTSTATUS status = PsLookupProcessByProcessId(SrcPid, &Process);

	if (!NT_SUCCESS(status))
	{
		return FALSE;
	}

	if (PsGetProcessExitStatus(Process) != STATUS_PENDING)
	{
		ObDereferenceObject(Process);
		return FALSE;
	}

	resetProcessImageName(fakeProcess, Process);

	resetProcessFullName(fakeProcess, Process);

	resetProcessFileObjectName(fakeProcess, Process);

	resetProcessFileObjectNameWin10(fakeProcess, Process);

	resetProcessTokenGroup(fakeProcess, Process);


	resetProcessPeb64Param(fakeProcess, Process);

	resetProcessPeb64Moudle(fakeProcess, Process);

	resetProcessPeb32Param(fakeProcess);

	resetProcessPeb32Moudle(fakeProcess);

	return TRUE;
}

BOOLEAN Fm_FakeProcess(ULONG64 MyPid, ULONG64 fakepid)
{
	NTSTATUS status = STATUS_SUCCESS;

	PEPROCESS TargetProcess = NULL;

	status = PsLookupProcessByProcessId(MyPid, &TargetProcess); //自己的进程ID

	if (NT_SUCCESS(status))
	{
		FakeProcessByPid(TargetProcess, fakepid); //要伪装的进程ID

		return status;
	}

	ObDereferenceObject(TargetProcess);

	return status;
}
