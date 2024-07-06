#include <ntifs.h>

typedef NTSTATUS(NTAPI* CommCallBack)(PVOID CommInfo);

BOOLEAN RegisterComm(CommCallBack CallBack);

VOID  UnRegisterComm(CommCallBack CallBack);