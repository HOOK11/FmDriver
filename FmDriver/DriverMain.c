#include<ntifs.h>
#include"Comm.h"
//#include"Function.h"
#include "FakeInject.h"
#include "FakeProcess.h"
#include"WinProtect.h"
//保护窗口 读写 获取模块 伪装进程

NTSTATUS NTAPI  DispatchCallBack(PVOID CommInfo)
{
	PCommInfo Info = (PCommInfo)CommInfo;

	//DbgBreakPoint();
	PVOID Date = Info->InData;

	NTSTATUS status = STATUS_UNSUCCESSFUL;

	switch (Info->Cmd)
	{

	case CMD_INIT: {//测试通讯

		status = STATUS_SUCCESS;
		
	}
				 break;
	case CMD_QUERYMEMORY: {
		PQueryMemoryInfo Info = (PQueryMemoryInfo)Date;

		status=  Fm_QueryMemory(Info->PID, Info->BaseAddress, (PFMMEMORY_BASIC_INFORMATION)Info->RetBase);
	}
		break;

	case CMD_GETMODULE: {
		PGetModuleInfo Info = (PGetModuleInfo)Date;
		
		Info->RetBase = Fm_GetModeBase(Info->PID, Info->ModuleName);
		
		if (Info->RetBase)
		{
			status = STATUS_SUCCESS;
		}

	}
		break;
	case CMD_GETEXEMODULE: {

		PGetExeModule Info = (PGetExeModule)Date;

		Info->RetBase = Fm_GetExeModule(Info->PID);

		if (Info->RetBase)
		{
			//DbgPrintEx(0, 77, "Info->RetBase = %llx \r\n", Info->RetBase);
			status = STATUS_SUCCESS;
		}

	}
		 break;
	case CMD_READMEMORY: {

		PReadWriteMemoryInfo Info = (PReadWriteMemoryInfo)Date;

		status = Fm_ReadMemory(Info->PID, Info->Base, Info->Buffer, Info->Size);

	}
	 break;

	case CMD_WIRTEMEMORY: {

		PReadWriteMemoryInfo Info = (PReadWriteMemoryInfo)Date;

		status = Fm_WriteMemory(Info->PID, Info->Base, Info->Buffer, Info->Size);
	}
	break;
	case CMD_INJECT: {
		PInjectInfo Info = (PInjectInfo)Date;

		status = Fm_Inject(Info->PID, Info->DllBuffer, Info->size);

	}
	 break;

	case CMD_FAKEPROCESS: {
		PFakeProcessInfo Info = (PFakeProcessInfo)Date;

		status = Fm_FakeProcess(Info->MyPID, Info->FakePID);


	}
	 break;

	case CMD_WINDOWPROTECT: {
		PWindowProtect Info = (PWindowProtect)Date;

		ghwnd = Info->Hwnd;

		if (ghwnd)
		{
			status = STATUS_SUCCESS;
		}
	}
	break;

	case CMD_ALLOCMEMORY: {
		PAllocMemory Info = (PAllocMemory)Date;

		Info->Buffer = Fm_AllocMemory(PsGetCurrentProcessId(), Info->size);

		if (Info->Buffer)
		{
			status = STATUS_SUCCESS;
		}

	}
						break;
	//case CMD_INITDECRYPT: {
	//	PInitDecrypt Info = (PInitDecrypt)Date;


	//	Info->DecryptCall =  Fm_InitDecrypt(Info->PID, Info->Address,Info->CodeBuffer);

	//	if (Info->DecryptCall)
	//	{
	//		status = STATUS_SUCCESS;
	//	}

	//}
	//break;
	
	default:
		break;
	}

	return status;
}

//VOID DriverUnload(PDRIVER_OBJECT pDriver)
//{
//	UnRegisterComm;
//
//	IfhRelease2();
//	//DbgPrint("驱动卸载成功！\r\n");
//}

NTSTATUS WindowProtectHook()
{
	InitHook();

	IfhInitialize2(HookCallBack);

	return STATUS_SUCCESS;
}



NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver,PUNICODE_STRING pReg_Path)
{

	RegisterComm(DispatchCallBack);

	WindowProtectHook();

	//pDriver->DriverUnload = DriverUnload;


	return STATUS_SUCCESS;
}



