#pragma once
#include "pch.h"

//通过进程名打开进程
HANDLE OpenProcessByName(const TCHAR* processName, DWORD ACCESS);

//提升权限(要用管理员权限运行EXE)
bool Up();

//原样转换：十六进制的数和字符串
CHAR* HexToStr(DWORD srcHex);
CHAR* DecToStr(DWORD srcDec);

//打印十六进制数字hex和msg到OutputDebugString (四字节的hex数)
void ShowDbg(const char* msgStr, DWORD hex);
