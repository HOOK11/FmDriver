#include "Tools.h"

MODE SetPreviousMode(PETHREAD Thread, MODE Mode)
{
	static ULONG ModeOffset = 0;

	if (!ModeOffset)
	{
		PUCHAR Temp = (PUCHAR)ExGetPreviousMode;

		for (int i = 0; i < 100; i++)
		{
			if (Temp[i] == 0xc3)
			{
				ModeOffset = *(PUCHAR)(Temp + i - 4);

				break;
			}
		}

	}
	MODE J_Mode = *((PUCHAR)Thread + ModeOffset);

	*((PUCHAR)Thread + ModeOffset) = Mode;

	return J_Mode;
}

//ËÑË÷º¯ÊýµØÖ·

PUCHAR NtQueryVirtualMemoryAddr()
{
	ULONG size = 0;
	PUCHAR base = GetKernelModuleBase("ntoskrnl.exe", &size);
	if (!base)
	{
		return NULL;
	}
	ULONG offset = GetSectionOffsetName(base, "PAGE", &size);
	if (!offset)
	{
		return NULL;
	}
//	__debugbreak(); 
	PUCHAR addr = GetSearchApiCode(base + offset,
			"C744????????????4889??????488B??????4889??????E8????????48??????"  
			, size);
	if (!addr)
	{
		return NULL;
	}
	return addr - 0x9;  //¼õÈ¥0x9
}


PUCHAR NtProtectVirtualMemoryAddr()
{
	ULONG size = 0;
	PUCHAR base = GetKernelModuleBase("ntoskrnl.exe", &size);
	if (!base)
	{
		return NULL;
	}
	ULONG offset = GetSectionOffsetName(base, "PAGE", &size);
	if (!offset)
	{
		return NULL;
	}
	
	PUCHAR addr = GetSearchApiCode(base + offset,
		"415441554156415748????????????48????????????4833C44889????????????458BE14C89??????"
		, size);
	if (!addr)
	{
		return NULL;
	}
	return addr - 0x4;  
}
