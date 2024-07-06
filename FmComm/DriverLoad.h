#pragma once
#include <string>
#include <Windows.h>
#include <time.h>
using namespace std;

class LoadDriver
{
public:
	LoadDriver();
	~LoadDriver();

	BOOLEAN Load(std::string Path, std::string ServiceName);

	BOOLEAN Unload(std::string ServiceName);

	BOOLEAN InstallDriver(std::string Path, std::string ServiceName);

	static HMODULE GetDllBase();
};




//EXTERN_C BOOLEAN __stdcall DriverLoad();
//EXTERN_C BOOL LoadDriver(const  char* lpszDriverName, const  char* sysFileName);