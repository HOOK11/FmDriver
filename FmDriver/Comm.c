#include "Comm.h"
#include"Struct.h"

CommCallBack gCommCallBack = NULL;

PDEVICE_OBJECT GetDeviceObjectName(PWCH DriverName)
{
	UNICODE_STRING uName = { 0 };

	RtlInitUnicodeString(&uName, DriverName);
	
	PFILE_OBJECT FileObj = NULL;

	PDEVICE_OBJECT pDevice = NULL;

	NTSTATUS status = IoGetDeviceObjectPointer(&uName, FILE_ALL_ACCESS, &FileObj, &pDevice);

	if (!NT_SUCCESS(status))return NULL;

	if (FileObj)ObDereferenceObject(FileObj);

	return pDevice;

}


BOOLEAN DeviceIoControl(
	_In_ struct _FILE_OBJECT* FileObject,
	_In_ BOOLEAN Wait,
	_In_opt_ PVOID InputBuffer,
	_In_ ULONG InputBufferLength,
	_Out_opt_ PVOID OutputBuffer,
	_In_ ULONG OutputBufferLength,
	_In_ ULONG IoControlCode,
	_Out_ PIO_STATUS_BLOCK IoStatus,
	_In_ struct _DEVICE_OBJECT* DeviceObject
)
{

	if (MmIsAddressValid(InputBuffer) && MmIsAddressValid((PUCHAR)InputBuffer + InputBufferLength - 1))
	{
		PULONG64 mem = (PULONG64)InputBuffer;

		if (mem[0] == 0x12345678)
		{
			NTSTATUS status =  gCommCallBack(mem);

			PCommInfo Info = mem;

			*(PULONG64)Info->RetStatus = status;
			
			IoStatus->Information = 0;

			IoStatus->Status = status;
		}

	}


	return TRUE;
}


BOOLEAN RegisterComm(CommCallBack CallBack)
{

	PDEVICE_OBJECT pDevice = GetDeviceObjectName(L"\\Device\\Null");

	if (!pDevice)return FALSE;

	PDRIVER_OBJECT pDriver = pDevice->DriverObject;

	pDriver->FastIoDispatch->FastIoDeviceControl = DeviceIoControl;

	gCommCallBack = CallBack ;

	return TRUE;
}

VOID UnRegisterComm(CommCallBack CallBack)
{
	if (gCommCallBack)
	{

		PDEVICE_OBJECT pDevice = GetDeviceObjectName(L"\\Device\\Null");

		if (!pDevice)return FALSE;

		PDRIVER_OBJECT pDriver = pDevice->DriverObject;

		pDriver->FastIoDispatch->FastIoDeviceControl = NULL;

	}

	gCommCallBack = NULL;
}
