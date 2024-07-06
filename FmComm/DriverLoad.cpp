#include"pch.h"
#include"DriverLoad.h"
#include"PeData.h"

#pragma comment(lib,"Urlmon.lib")
#pragma comment(lib, "Wininet.lib")
#pragma warning(disable:4996)


LoadDriver::LoadDriver()
{

}


LoadDriver::~LoadDriver()
{
}

BOOLEAN LoadDriver::Load(std::string Path, std::string ServiceName)
{
	bool bRet = false;
	DWORD dwLastError;
	SC_HANDLE hSCManager;
	SC_HANDLE hService = NULL;

	if (hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS))
	{
		hService = CreateServiceA(
			hSCManager, ServiceName.c_str(),
			ServiceName.c_str(), SERVICE_ALL_ACCESS,
			SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
			SERVICE_ERROR_IGNORE, Path.c_str(),
			NULL, NULL, NULL, NULL, NULL
		);

		if (hService == NULL)
		{
			hService = OpenServiceA(hSCManager, ServiceName.c_str(), SERVICE_ALL_ACCESS);

			if (!hService)
			{
				CloseServiceHandle(hSCManager);
				return false;
			}

		}

		bRet = StartServiceA(hService, 0, NULL);
		if (!bRet)
		{
			dwLastError = GetLastError();
			//printf("%d\r\n", dwLastError);
		}

	}

	if (hService)
	{
		CloseServiceHandle(hService);
	}

	if (hSCManager)
	{
		CloseServiceHandle(hSCManager);
	}

	return bRet;
}

BOOLEAN LoadDriver::Unload(std::string ServiceName)
{
	BOOL bRet = FALSE;
	SC_HANDLE hServiceMgr = NULL;
	SC_HANDLE hServiceDDK = NULL;
	SERVICE_STATUS SvrSta;

	do
	{
		//
		// 打开SCM管理器
		//
		hServiceMgr = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);

		if (hServiceMgr == NULL)
		{
			break;
		}

		//
		// 打开驱动所对应的服务
		//
		hServiceDDK = OpenServiceA(hServiceMgr, ServiceName.c_str(), SERVICE_ALL_ACCESS);

		if (hServiceDDK == NULL)
		{
			break;
		}

		ControlService(hServiceDDK, SERVICE_CONTROL_STOP, &SvrSta);


		if (DeleteService(hServiceDDK))
		{
			bRet = TRUE;
		}

	} while (FALSE);

	if (hServiceDDK)
	{
		CloseServiceHandle(hServiceDDK);
	}

	if (hServiceMgr)
	{
		CloseServiceHandle(hServiceMgr);
	}

	return bRet;
}



HMODULE GetSelfModuleHandle()
{
	MEMORY_BASIC_INFORMATION mbi;

	return ((::VirtualQuery(GetSelfModuleHandle, &mbi, sizeof(mbi)) != 0)
		? (HMODULE)mbi.AllocationBase : NULL);
}

HMODULE LoadDriver::GetDllBase()
{
	return GetSelfModuleHandle();
}
//本地内存安装

BOOLEAN LoadDriver::InstallDriver(std::string Path, std::string ServiceName)
{
	HRSRC hResc;
	DWORD dwImageSize;
	HANDLE hFile;
	DWORD dwByteWrite;
	HGLOBAL	hResourecImage;
	CHAR str[512] = { 0 };

	//
	// 或许是上次由于未知错误, 导致驱动卸载
	// 不干净, 这里卸载一次.
	//
//	this->Unload(ServiceName.c_str());

	//dwImageSize = sizeof(sysData);
	//unsigned char* pMemory = (unsigned char*)malloc(dwImageSize);
	//memcpy(pMemory, sysData, dwImageSize);
	//for (ULONG i = 0; i < dwImageSize; i++)
	//{
	//	pMemory[i] ^= 0xd8;
	//	pMemory[i] ^= 0xcd;
	//}

	//hFile = CreateFileA(Path.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
	//	NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	//if (hFile == INVALID_HANDLE_VALUE)
	//{
	//	OutputDebugStringA(Path.c_str());
	//	return false;
	//}

	//if (!WriteFile(hFile, pMemory, dwImageSize, &dwByteWrite, NULL))
	//{
	//	OutputDebugStringA(Path.c_str());
	//	CloseHandle(hFile);
	//	return false;
	//}

	//if (dwByteWrite != dwImageSize)
	//{
	//	OutputDebugStringA(Path.c_str());
	//	CloseHandle(hFile);
	//	return false;
	//}

	//CloseHandle(hFile);

	
// 安装驱动
//
	if (!this->Load(Path, ServiceName))
	{
		DeleteFileA(Path.c_str());
		return false;
	}

	DeleteFileA(Path.c_str());

	return true;


}

