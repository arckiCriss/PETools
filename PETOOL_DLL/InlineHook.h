#pragma once
#include "stdafx.h"

//Inline Hook
void InlineHook_X86(CHAR* destDllName, CHAR* destFuncName, DWORD hookFuncAddr, int byteLen);
void InlineHook_MyMessageBoxA_X86();