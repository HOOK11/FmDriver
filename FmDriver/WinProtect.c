#include<ntifs.h>
#include"WinProtect.h"

int ReadIndex(ULONG64 addr, int offset)
{
	PUCHAR base = NULL;
	SIZE_T size = PAGE_SIZE;
	NTSTATUS status = ZwAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size, MEM_COMMIT, PAGE_READWRITE);

	if (!NT_SUCCESS(status)) return -1;

	ULONG proc = NULL;

	memset(base, 0, size);

	status = MmCopyVirtualMemory(IoGetCurrentProcess(), addr, IoGetCurrentProcess(), base, 0x300, UserMode, &proc);

	if (!NT_SUCCESS(status))
	{
		ZwFreeVirtualMemory(NtCurrentProcess(), &base, &size, MEM_RELEASE);
		return -1;
	}

	//int index = *(int*)(base + 0x4);
	ULONG number = GetWindowsVersionNumber();
	int index = 0;
	if (!offset)
	{
		index = *(int*)(base + 0x4);
	}
	else
	{
		if (number != 7)
		{
			index = *(int*)(base + 0x4);
		}
		else
		{
			PUCHAR temp = base + offset;
			for (int i = 0; i < 200; i++)
			{
				if (temp[i] == 0x4C && temp[i + 1] == 0x8B && temp[i + 2] == 0xD1)
				{
					index = *(int*)(temp + i + 4);
					break;
				}
			}
		}
	}

	ZwFreeVirtualMemory(NtCurrentProcess(), &base, &size, MEM_RELEASE);

	return index;
}


char* GetSearchModule()
{
	ULONG number = GetWindowsVersionNumber();
	char* moudleName = NULL;

	if (number == 7)
	{
		moudleName = "user32.dll";
	}
	else
	{
		moudleName = "win32u.dll";
	}

	return moudleName;
}


int GetFuncIndexPlus(char* funcName, int subAddr, int offset)
{
	int index = -1;
	PEPROCESS Process = FindProcess("explorer.exe");
	if (Process == NULL) return index;

	ULONG number = GetWindowsVersionNumber();
	char* moudleName = GetSearchModule();

	char* FuncName = funcName;

	ULONG_PTR imageBase = 0;
	ULONG_PTR imageSize = 0;
	KAPC_STATE kApcState = { 0 };

	KeStackAttachProcess(Process, &kApcState);

	do
	{

		imageBase = Fm_GetModeBase(PsGetProcessId(Process), moudleName);

		if (!imageBase) break;

		ULONG_PTR funcAddr = GetProcAddressR(imageBase, FuncName, TRUE);

		if (!funcAddr) break;

		if (subAddr)
		{
			funcAddr -= subAddr;
		}

		index = ReadIndex(funcAddr, offset);

	} while (0);



	KeUnstackDetachProcess(&kApcState);

	ObDereferenceObject(Process);

	return index;
}

int GetFuncIndex(char* funcName, int offset)
{
	return GetFuncIndexPlus(funcName, 0, offset);
}



int GetUserGetForegroundWindowIndex()
{
	static int index = -1;
	if (index != -1) return index;

	ULONG number = GetWindowsVersionNumber();
	char* FuncName = NULL;

	if (number == 7)
	{
		FuncName = "GetForegroundWindow";
	}
	else
	{
		FuncName = "NtUserGetForegroundWindow";
	}

	index = GetFuncIndex(FuncName, 0);
	return index;
}

int GetUserFindWindowExIndex()
{
	static int index = -1;
	if (index != -1) return index;

	ULONG number = GetWindowsVersionNumber();
	char* FuncName = NULL;

	if (number == 7)
	{
		FuncName = "SetThreadDesktop";
	}
	else
	{
		FuncName = "NtUserFindWindowEx";
	}

	index = GetFuncIndex(FuncName, 11);
	return index;
}


int GetUserWindowFromPointIndex()
{
	static int index = -1;
	if (index != -1) return index;

	ULONG number = GetWindowsVersionNumber();
	char* FuncName = NULL;

	if (number == 7)
	{
		FuncName = "WindowFromPoint";
	}
	else
	{
		FuncName = "NtUserWindowFromPoint";
	}

	index = GetFuncIndex(FuncName, 0);
	return index;
}

int GetUserBuildHwndListIndex()
{
	static int index = -1;
	if (index != -1) return index;

	ULONG number = GetWindowsVersionNumber();
	char* FuncName = NULL;

	if (number == 7)
	{
		FuncName = "EnumDisplayMonitors";
	}
	else
	{
		FuncName = "NtUserBuildHwndList";
	}

	index = GetFuncIndex(FuncName, 11);
	return index;
}

int GetUserQueryWindowIndex() //重点怀疑对象
{
	static int index = -1;
	if (index != -1) return index;

	ULONG number = GetWindowsVersionNumber();
	char* FuncName = NULL;

	if (number == 7)
	{
		FuncName = "GetWindowLongW";
	}
	else
	{
		FuncName = "NtUserQueryWindow";
	}

	//index = GetFuncIndexPlus(FuncName, 0x65, 1);
	index = GetFuncIndex(FuncName, 11); //win10 
	return index;
}

ULONG_PTR GetSSSDTFuncByIndex(LONG index)
{

	if (index == -1) return 0;

	PEPROCESS Process = FindProcess("explorer.exe");
	if (Process == NULL) return 0;

	KAPC_STATE kApcState = { 0 };

	KeStackAttachProcess(Process, &kApcState);

	SSDTStruct* sssdt = SSSDTFind();

	if (index >= 0x1000) index -= 0x1000;

	LONG offset = sssdt->pServiceTable[index];

	offset = (offset >> 4); // 使用无符号右移

	ULONG64 func = ((ULONG64)sssdt->pServiceTable + offset);

	KeUnstackDetachProcess(&kApcState);

	ObDereferenceObject(Process);

	return func;


}

ULONG_PTR GetUserFindWindowEx()
{
	static ULONG64 func = 0;
	if (func) return func;

	LONG index = GetUserFindWindowExIndex();
	func = GetSSSDTFuncByIndex(index);

	return func;
}

ULONG_PTR GetUserGetForegroundWindow()
{
	static ULONG64 func = 0;

	if (func) return func;

	LONG index = GetUserGetForegroundWindowIndex();

	func = GetSSSDTFuncByIndex(index);

	return func;
}

ULONG_PTR GetUserBuildHwndList()
{
	static ULONG64 func = 0;
	if (func) return func;

	LONG index = GetUserBuildHwndListIndex();
	func = GetSSSDTFuncByIndex(index);

	return func;
}


ULONG_PTR GetUserQueryWindow() //-------
{
	static ULONG64 func = 0;
	if (func) return func;

	LONG index = GetUserQueryWindowIndex();
	func = GetSSSDTFuncByIndex(index);

	return func;
}

ULONG_PTR GetUserWindowFromPoint()
{
	static ULONG64 func = 0;
	if (func) return func;

	LONG index = GetUserWindowFromPointIndex();
	func = GetSSSDTFuncByIndex(index);

	return func;
}


VOID InitHook()
{
	GetUserGetForegroundWindow();
	GetUserFindWindowEx();
	GetUserBuildHwndList();
	GetUserQueryWindow();
	GetUserWindowFromPoint();
}



PVOID MyNtUserGetForegroundWindow()
{
	typedef PVOID(NTAPI* NtUserGetForegroundWindowProc)(VOID);

	NtUserGetForegroundWindowProc NtUserGetForegroundWindowFunc = (NtUserGetForegroundWindowProc)GetUserGetForegroundWindow();

	PVOID hwnd = NtUserGetForegroundWindowFunc();

	if (ghwnd == hwnd)
	{
		//DbgBreakPoint();
		return NULL;
	}

	return hwnd;
}

PVOID MyNtUserFindWindowEx(PVOID desktop1, PVOID desktop2, PUNICODE_STRING tName, PUNICODE_STRING tclassName, ULONG64 x)
{
	typedef PVOID(NTAPI* MyUserFindWindowExProc)(PVOID desktop1, PVOID desktop2, PUNICODE_STRING tName, PUNICODE_STRING tclassName, ULONG64 x);

	MyUserFindWindowExProc MyUserFindWindowExFunc = (MyUserFindWindowExProc)GetUserFindWindowEx();

	PVOID hwnd = MyUserFindWindowExFunc(desktop1, desktop2, tName, tclassName, x);

	if (ghwnd == hwnd)
	{
		//DbgBreakPoint();
		return NULL;
	}

	return hwnd;
}

ULONG64 MyNtUserQueryWindow(PVOID Hwnd, int flags)
{
	typedef ULONG64(NTAPI* MyNtUserQueryWindowProc)(PVOID Hwnd, int flags);

	MyNtUserQueryWindowProc MyNtUserQueryWindowFunc = (MyNtUserQueryWindowProc)GetUserQueryWindow();

	if (Hwnd == ghwnd) return 0;

	return MyNtUserQueryWindowFunc(Hwnd, flags);
}

PVOID MyNtUserWindowFromPoint(PVOID Point)
{
	typedef PVOID(NTAPI* NtUserWindowFromPointProc)(PVOID Point);

	NtUserWindowFromPointProc NtUserWindowFromPointFunc = (NtUserWindowFromPointProc)GetUserWindowFromPoint();

	PVOID Hwnd = NtUserWindowFromPointFunc(Point);

	if (Hwnd == ghwnd) return 0;

	return Hwnd;
}

NTSTATUS MyNtUserBuildHwndList(PVOID a1, PVOID a2, PVOID Address, unsigned int a4, ULONG count, PVOID Addressa, PULONG pretCount)
{
	typedef NTSTATUS(NTAPI* MyNtUserBuildHwndListProc)(PVOID a1, PVOID a2, PVOID Address, unsigned int a4, ULONG count, PVOID Addressa, PULONG pretCount);

	MyNtUserBuildHwndListProc MyNtUserBuildHwndListFunc = (MyNtUserBuildHwndListProc)GetUserBuildHwndList();

	NTSTATUS status = MyNtUserBuildHwndListFunc(a1, a2, Address, a4, count, Addressa, pretCount);


	if (NT_SUCCESS(status))
	{

		if (MmIsAddressValid(pretCount) && MmIsAddressValid(Addressa))
		{
			int scount = *pretCount;
			PVOID* arrays = (PVOID*)Addressa;
			for (int i = 0; i < scount; i++)
			{
				if (arrays[i] == ghwnd)
				{
					//如果我们的句柄就是第一个
					if (i == 0)
					{

						//只有一个情况
						if (scount == 1)
						{
							arrays[i] = 0;
							*pretCount = 0;
							break;
						}

						arrays[i] = arrays[i + 1];
						break;
					}
					else
					{

						arrays[i] = arrays[i - 1];
						break;
					}

				}
			}
		}

	}

	return status;
}





void HookCallBack(unsigned int SystemCallIndex, void** SystemCallFunction)  //开始Hook Nt 函数
{
	if (*SystemCallFunction == GetUserGetForegroundWindow())
	{
		*SystemCallFunction = MyNtUserGetForegroundWindow;
		//DbgPrintEx(77, 0, "[db]:GetUserGetForegroundWindow\r\n");
	}
	else if (*SystemCallFunction == GetUserFindWindowEx())
	{
		//DbgPrintEx(77, 0, "[db]:GetUserFindWindowEx\r\n");
		*SystemCallFunction = MyNtUserFindWindowEx;
	}
	else if (*SystemCallFunction == GetUserBuildHwndList())
	{
		*SystemCallFunction = MyNtUserBuildHwndList;
		//DbgPrintEx(77, 0, "[db]:GetUserBuildHwndList\r\n");

	}
	else if (*SystemCallFunction == GetUserQueryWindow())
	{
		//DbgPrintEx(77, 0, "[db]:GetUserQueryWindow\r\n");
		*SystemCallFunction = MyNtUserQueryWindow;
	}
	else if (*SystemCallFunction == GetUserWindowFromPoint())
	{

		*SystemCallFunction = MyNtUserWindowFromPoint;
		//DbgPrintEx(77, 0, "[db]:GetUserWindowFromPoint\r\n");

	}
}

