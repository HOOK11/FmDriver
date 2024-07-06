#pragma once
#include <ntifs.h>

BOOLEAN UpdataIAT(char* imageBuffer);

BOOLEAN LoadDriver(PUCHAR fileBuffer);