#include"pch.h"
#include "Comms.h"
#include"../FmDriver/Struct.h"
BOOLEAN DriverComm(ULONG Cmd, PVOID InData, ULONG size)
{
    static HANDLE hDevice = NULL;

    if (!hDevice || hDevice == INVALID_HANDLE_VALUE)
    {
        hDevice = CreateFileA("\\??\\Nul", FILE_GENERIC_WRITE | FILE_GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    }
    ULONG64 RetStatus = -1;
    CommInfo Info;
    Info.CommID = 0x12345678;
    Info.InData = (ULONG64)InData;
    Info.RetStatus = (ULONG64)&RetStatus;
    Info.Cmd = Cmd;
    DWORD RetLen = 0;

    BOOLEAN User = DeviceIoControl(hDevice, 0, &Info, sizeof(Info), &Info, sizeof(Info), &RetLen, NULL);

    return RetStatus == 0;

}
