#include<ntifs.h>
#include "./Hooks/hook.h"
#include "SsdtIndex.h"
#include "Function.h"

PVOID ghwnd;

VOID InitHook();

void HookCallBack(unsigned int SystemCallIndex, void** SystemCallFunction);  //��ʼHook Nt ����

NTSTATUS WindowProtectHook();




