#define _CRT_SECURE_NO_WARNINGS
#pragma once

#ifndef PCH_H
#define PCH_H

// TODO: 添加要在此处预编译的标头

#endif //PCH_H


#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <psapi.h>
#include <math.h>
#include <tlhelp32.h>	//用于CreateToolhelp32Snapshot枚举进程
#include "d3d11.h"		//D3D11
#include "d3dcompiler.h"//D3D11
#include <iostream>


#include "PEStruct.h"
#include "PETools.h"
#include "WindowsTools.h"
#include "RemoteThreadInject.h"
#include "ReflectInject.h"
#include "InlineHook.h"
#include "Asm.h"
#include "ChreatD3D11.h"
#include "WallHack.h"
#include "HardwareBP.h"
#include "NamedPipe.h"