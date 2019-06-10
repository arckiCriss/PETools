#pragma once
#include "stdafx.h"

DWORD WINAPI Malware_Core_x86(LPVOID lpThreadParameter);	//在目标进程中执行的恶意代码(需负责修复IAT表)
VOID Malware_HandleParam(PEBody PEBody, DWORD virtualAddr);	// 为malware全局参数赋值
VOID ReflectInject_X86(CHAR* processName);	//反射式注入(X86)

//>>>>>>>>>>>>>>>>>>MalWare所需的参数>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
struct IAT_MALWARE
{
	DWORD funcAddr[200];	//函数地址(需足够大)
	int numOfItem_pri;		//私有：标识当前IAT表中有几个项
};
struct INT_MALWARE
{
	//若值的最高二进制位=1，则其余位存放"函数名称序号"
	//若值的最高二进制位=0，则存放RVA值，指向一个_IMAGE_IMPORT_BY_NAME结构(系统类库已定义此结构)
	DWORD IMAGE_THUNK_DATA[200]; //需足够大
	int numOfItem_pri;			 //私有：标识当前INT表中有几个项
};
struct MALWARE_PARAM
{
	int numOfImportDirectory;
	DWORD virtualAddr;		//从目标进程中申请到的基址
	ImportDirectory ImportDirectory[100];		//需足够大
	IAT_MALWARE IAT_Malware[100];				//需足够大
	INT_MALWARE INT_Malware[100];				//需足够大
};
//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>