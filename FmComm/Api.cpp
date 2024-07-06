#include"pch.h"
#include"Api.h"
#include"Comms.h"
#include"../FmDriver/Struct.h"
#include"DriverLoad.h"
#include"HttpDownFile.h"
#pragma warning(disable:4996)
char AZTable[62] =
{
	0,
};

void initTable()
{
	if (AZTable[0] != 0) return;
	int k = 0;
	for (char i = 'A'; i <= 'Z'; i++, k++)
	{
		AZTable[k] = i;
	}

	for (char i = 'a'; i <= 'z'; i++, k++)
	{
		AZTable[k] = i;
	}

	for (char i = '0'; i <= '9'; i++, k++)
	{
		AZTable[k] = i;
	}
}



char* GetRandName()
{
	static char* name = NULL;
	if (name) return name;

	initTable();

	name = (char*)malloc(20);

	memset(name, 0, 20);  //15 .sys 0

	time_t t = time(NULL);
	srand(t);

	int len = (rand() % 10) + 5;
	for (int i = 0; i < len; i++)
	{
		int index = rand() % sizeof(AZTable);
		name[i] = AZTable[index];
	}

	strcat(name, ".sys");

	return name;
}
char* GetRandServiceName()
{
	static char* name = NULL;
	if (name) return name;

	initTable();

	name = (char*)malloc(10);

	memset(name, 0, 10);  //15 .sys 0

	time_t t = time(NULL);
	srand(t);

	int len = (rand() % 4) + 5;
	for (int i = 0; i < len; i++)
	{
		int index = rand() % sizeof(AZTable);
		name[i] = AZTable[index];
	}

	return name;
}



EXTERN_C BOOLEAN Fm_InitComm()
{
	ULONG X = 0;
	return DriverComm(CMD_INIT, (PVOID)&X, sizeof(X));
}

//测试加载
EXTERN_C BOOLEAN WINAPI Fm_DriverLoad()
{

	if (Fm_InitComm())  //通讯成功就不需要再次加载了
	{
		return TRUE;
	}
	LoadDriver Load;

	char bufPath[MAX_PATH] = { 0 };
	GetTempPathA(MAX_PATH, bufPath);

	//char* driverName = GetRandName();
	char* serviceName = GetRandServiceName();

	std::string Path = httpdownload();

	//strcat(bufPath, driverName);

	Load.InstallDriver(Path.c_str(), serviceName);

	BOOLEAN RetComm = Fm_InitComm();

	return RetComm;

	//else {
	//	return LoadDriver("FmDriver", "FmDriver.sys");
	//}

}


EXTERN_C BOOLEAN WINAPI Fm_QueryMemory(ULONG64 Pid, ULONG64 VirtualAddress, PFMMEMORY_BASIC_INFORMATION InfoMode)
{
	QueryMemoryInfo Info;
	Info.PID = Pid;
	Info.BaseAddress = VirtualAddress;
	Info.RetBase = (ULONG64)InfoMode;
	
	return DriverComm(CMD_QUERYMEMORY, (PVOID)&Info, sizeof(QueryMemoryInfo));

}

EXTERN_C ULONG64 WINAPI Fm_GetModule(ULONG64 Pid, char* ModuleName)
{
	GetModuleInfo Info;

	Info.PID = Pid;
	Info.ModuleName = (ULONG64)ModuleName;

	if (DriverComm(CMD_GETMODULE,(PVOID)&Info,sizeof(GetModuleInfo)))
	{
		return Info.RetBase;
	}
	return 0;
}

EXTERN_C ULONG64 WINAPI Fm_GetExeModule(ULONG64 PID)
{
	GetExeModule Info;

	Info.PID = PID;

	if (DriverComm(CMD_GETEXEMODULE, (PVOID)&Info, sizeof(GetExeModule)))
	{
		return Info.RetBase;
	}
	return 0;
}

EXTERN_C BOOLEAN WINAPI Fm_ReadMemory(ULONG64 Pid, ULONG64 Address, PVOID Buffer, ULONG64 Size)
{
	ReadWriteMemoryInfo Info;
	Info.PID = Pid;
	Info.Base = Address;
	Info.Buffer = (ULONG64)Buffer;
	Info.Size = Size;
	return DriverComm(CMD_READMEMORY, (PVOID)&Info, sizeof(ReadWriteMemoryInfo));
}

EXTERN_C BOOLEAN WINAPI Fm_WriteMemory(ULONG64 Pid, ULONG64 Address, PVOID Buffer, ULONG64 Size)
{
	ReadWriteMemoryInfo Info;
	Info.PID = Pid;
	Info.Base = Address;
	Info.Buffer = (ULONG64)Buffer;
	Info.Size = Size;
	return DriverComm(CMD_WIRTEMEMORY, (PVOID)&Info, sizeof(ReadWriteMemoryInfo));
}


EXTERN_C BOOLEAN WINAPI Fm_Inject(ULONG64 pid, unsigned char* DllData, SIZE_T dwImageSize)
{
	InjectInfo Info;
	Info.PID = pid;
	Info.DllBuffer = DllData;
	Info.size = dwImageSize;
	return DriverComm(CMD_INJECT, (PVOID)&Info, sizeof(InjectInfo));
}

EXTERN_C BOOLEAN WINAPI Fm_FakeProcess(ULONG64 MyPid, ULONG64 fakepid)
{
	FakeProcessInfo Info;
	Info.MyPID = MyPid;
	Info.FakePID = fakepid;
	return DriverComm(CMD_FAKEPROCESS, (PVOID)&Info, sizeof(FakeProcessInfo));
}

EXTERN_C BOOLEAN WINAPI Fm_WindowProtect(ULONG64 Hwnd)
{
	WindowProtect Info;

	Info.Hwnd = Hwnd;

	return DriverComm(CMD_WINDOWPROTECT, (PVOID)&Info, sizeof(WindowProtect));
}
EXTERN_C ULONG64 WINAPI Fm_AllocMemory(SIZE_T Size)
{
	AllocMemory Info;

	Info.size = Size;

	if (DriverComm(CMD_ALLOCMEMORY, (PVOID)&Info, sizeof(WindowProtect)))
	{
		return Info.Buffer;
	}
	return 0;
}

//测试
//EXTERN_C ULONG64 Fm_InitDecryptFunc(ULONG64 PID, ULONG64 FuncAddress,PUCHAR CodeBuffer)
//{
//	InitDecrypt Info;
//
//	Info.PID = PID;
//
//	Info.Address = FuncAddress;
//
//	Info.CodeBuffer = CodeBuffer;
//
//	if (DriverComm(CMD_INITDECRYPT, (PVOID)&Info, sizeof(InitDecrypt)))
//	{
//		printf("Info.DecryptCall = %llx \r\n", Info.DecryptCall);
//		return Info.DecryptCall;
//	}
//	return 0;
//}



