// stdafx.h : 标准系统包含文件的包含文件，
// 或是经常使用但不常更改的
// 特定于项目的包含文件
//

#pragma once

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>

// TODO:  在此处引用程序需要的其他头文件
#include <windows.h>
#include <psapi.h>
#include <math.h>
#include <tlhelp32.h>  //用于CreateToolhelp32Snapshot枚举进程
#include "d3d11.h"  //D3D11

#include "MyFunc.h"
#include "MyVariable.h"
#include "InlineHook.h"
#include "Inject_RemoteThreadInject.h"
#include "Inject_ReflectInject.h"
