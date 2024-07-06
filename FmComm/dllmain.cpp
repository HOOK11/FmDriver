// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <tlhelp32.h>
#include <string>
#include <locale.h>
#include"Api.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
DWORD GetProcessID(LPCTSTR lpProcessName)//根据进程名查找进程PID 
{
    DWORD dwRet = 0;
    HANDLE hSnapShot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapShot == INVALID_HANDLE_VALUE)
    {
        printf("\n获得进程快照失败,返回的GetLastError():%d", ::GetLastError());
        return dwRet;
    }

    PROCESSENTRY32 pe32;//声明进程入口对象 
    pe32.dwSize = sizeof(PROCESSENTRY32);//填充进程入口对象大小 
    ::Process32First(hSnapShot, &pe32);//遍历进程列表 
    do
    {
        if (!lstrcmp(pe32.szExeFile, lpProcessName))//查找指定进程名的PID 
        {
            dwRet = pe32.th32ProcessID;
            break;
        }
    } while (::Process32Next(hSnapShot, &pe32));
    ::CloseHandle(hSnapShot);
    return dwRet;//返回 
}
DWORD GamePID;

ULONG64 TslGameBase;

namespace Driver
{


	VOID GetGameID(HWND Hwnd)
	{

		while (Hwnd == NULL) {

			Hwnd = FindWindowA("UnrealWindow", NULL);

			Sleep(100);
		}

		GetWindowThreadProcessId(Hwnd, &GamePID);

	}


	template <class type>
	type Read(ULONG64 address)
	{
		type Buffer = {};

		Fm_ReadMemory(GamePID, address, &Buffer, sizeof(type));

		return Buffer;
	}

	void ReadMemory(__int64 ptr, void* buff, size_t size)//读
	{

		Fm_ReadMemory(GamePID, ptr, (PBYTE)buff, size);

		return;
	}
	ULONG64 Alloc(SIZE_T Size)
	{
		return Fm_AllocMemory(Size);
	}

}



namespace OffSet
{
	static constexpr uint64_t Shield指针 = 0xFBB2D28;
	static constexpr uint64_t Uworld = 0x11392B68;
}
typedef ULONG_PTR(__fastcall* DecryptFunctoin)(ULONG_PTR key);
DecryptFunctoin DecryptCall = DecryptFunctoin();

BOOL InitDecryptFunctoin()
{
	ULONG_PTR GameDecryptVariate = ULONG_PTR();

	ULONG_PTR GameDecryptFunctoinBaseAddress = ULONG_PTR();

	UCHAR CodeBuffer[0x100];

	RtlZeroMemory(CodeBuffer, 0x50);

    DecryptCall = (DecryptFunctoin)Driver::Alloc(0x100);//VirtualAlloc(NULL, 0x100, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!DecryptCall)
	{
		printf("申请失败\r\n");

	}

	printf("pDecryptFunctoin %p\n", DecryptCall);

	if (DecryptCall == DecryptFunctoin())
		return FALSE;

	memset(DecryptCall, 0xC3, 0x100);

	GameDecryptFunctoinBaseAddress = Driver::Read<ULONG_PTR>(TslGameBase + OffSet::Shield指针);

	printf("GameDecryptFunctoinBaseAddress %p\n", GameDecryptFunctoinBaseAddress);

	if (GameDecryptFunctoinBaseAddress == ULONG_PTR())
		return FALSE;

	GameDecryptVariate = GameDecryptFunctoinBaseAddress + Driver::Read<ULONG32>(GameDecryptFunctoinBaseAddress + 3) + 7;

	ULONG64 BufferAddress = Driver::Read<ULONG32>(GameDecryptFunctoinBaseAddress + 3);

	printf("BufferAddress = %llx \r\n", BufferAddress);

	if (GameDecryptFunctoinBaseAddress == ULONG_PTR())
		return FALSE;

	printf("GameDecryptVariate = %llx \r\n", GameDecryptVariate);

	Driver::ReadMemory(GameDecryptFunctoinBaseAddress, CodeBuffer, 0x50);

	printf("CodeBuffer = %llx \r\n", &CodeBuffer[0x0A]);

	((PUCHAR)DecryptCall)[0] = 0x48;

	((PUCHAR)DecryptCall)[1] = 0xB8;

	RtlCopyMemory(&((PUCHAR)DecryptCall)[0x02], &GameDecryptVariate, 0x08);

	RtlCopyMemory(&((PUCHAR)DecryptCall)[0x0A], &CodeBuffer[0x0A], 0x50);

	printf("pDecryptFunctoin %llx \r\n", DecryptCall);

	return TRUE;
}








int main(int argc,char * argv[]) 
{

    static BOOLEAN DriverComm;

    DriverComm = Fm_InitComm();

	if (DriverComm == TRUE)
	{
		printf("驱动通讯成功 \r\n");
    }
    else
    {
	
		static BOOLEAN  RetDriverLaod = Fm_DriverLoad();

		if (RetDriverLaod == FALSE)
		{
			printf("驱动安装失败\r\n");
			system("pause");
			return 0;
		}
		else {
			printf("驱动安装成功\r\n");
		}

    }

    HWND hwnd = NULL;
    DWORD PID;
   
    do
    {
        hwnd = FindWindowA("UnrealWindow", "PUBG：绝地求生 ");  //Notepad  UnrealWindow

    } while (!hwnd);

    Driver::GetGameID(hwnd);

   // GetWindowThreadProcessId(hwnd, &PID);

     TslGameBase = Fm_GetExeModule(GamePID);

    printf("ExeModule =  %llx \r\n", TslGameBase);


    InitDecryptFunctoin();

    //ULONG_PTR 解密地址 = Driver::Read<ULONG64>(TslGameBase+ gShield指针);

    //UCHAR CodeBuffer[0x100];

    //Driver::ReadMemory(解密地址, CodeBuffer, 0x50);


    //DecryptCall =  (DecryptFunctoin)Fm_InitDecryptFunc(GamePID, 解密地址, CodeBuffer);  //初始化

    //printf("DecryptCall = %llx \r\n", DecryptCall);

    ULONG64 Uworld = DecryptCall(Driver::Read<ULONG_PTR>(TslGameBase + OffSet::Uworld));

   printf("Uworld = %llx \r\n", Uworld);

     system("pause");
}
//  printf("hwnd = %llx \r\n", hwnd);

//   ULONG64 Mudlue =  Fm_GetModule(PID, "notepad.exe");

//   printf("Mudlue -> %llx \r\n", Mudlue);

//   ULONG64 ExeModule = Fm_GetExeModule(PID);

//   printf("ExeModule =  %llx \r\n", ExeModule);



//  ULONG64 buffer = 0;

//   Fm_ReadMemory(PID, Mudlue, &buffer, sizeof(buffer));

//   printf("buffer = %d \r\n", buffer);

//   Fm_WindowProtect((ULONG64)hwnd); // GetWindow

   //char bufw[10] = { 0 };

//   memset(bufw, 0x80, 10);
   //
//   Fm_WriteMemory(PID, Mudlue, bufw, sizeof(bufw));

   //ULONG64 FakePid = GetProcessID(L"winlogon.exe");

   //Fm_FakeProcess(PID, FakePid);