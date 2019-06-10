#pragma once
#include "pch.h"

//=====================================其他定义=======================================================================
#define 硬断_仅执行 0x55		    //局部断点+执行断点 (有效)
#define 硬断_仅写入 0x55550055	//局部断点+写入断点（有效）
#define 硬断_读或写 0xFFFF0055   //局部断点+读或写断点（有效）

//用于分别调用4个DRX的异常处理函数
LONG NTAPI MyVectoredExceptionHandle(struct _EXCEPTION_POINTERS* ExceptionInfo);//用于分别调用4个异常处理函数的函数
//函数指针：定义VEH函数
typedef LONG(NTAPI* PVEH_Func)(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params);

//结构体：硬件断点所需的全局参数
typedef struct HardwareBP_Params
{
	LPVOID BreakPointAddress;
	PVEH_Func pVEHFunc;
	LPVOID pFirstCode;
};

//枚举：4个调试寄存器
enum DRX
{
	Dr0, Dr1, Dr2, Dr3
};

//具体的VEH函数
LONG NTAPI VEH_AddVectoredExceptionHandler(struct _EXCEPTION_POINTERS* ExceptionInfo, HardwareBP_Params HardwareBP_Params);
LONG NTAPI VEH_D3D11Present(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params);
LONG NTAPI VEH_D3D11DrawIndexed(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params);
LONG NTAPI VEH_GetThreadContext(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params);
LONG NTAPI VEH_IsDebuggerPresent(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params);
LONG NTAPI VEH_CreateQuery(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params);
LONG NTAPI VEH_PSSetShaderResources(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params);
LONG NTAPI VEH_DEBUG(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params);

//声明全局变量：4个调试寄存器触发的异常处理函数所需的参数
extern HardwareBP_Params g_HardwareBP_Params_DR0;
extern HardwareBP_Params g_HardwareBP_Params_DR1;
extern HardwareBP_Params g_HardwareBP_Params_DR2;
extern HardwareBP_Params g_HardwareBP_Params_DR3;

//==================================================================================================================

//=========================================类定义====================================================================
class HardwareBP
{
private:
	LPVOID BreakPointAddress;		//下断位置
	DRX Drx;						//硬断所用的调试寄存器
	PVEH_Func pVEHFunc;				//当前调试寄存器所调用的异常处理函数
	int firstCodeLen;				//首句代码的长度		(设置仅执行断点时)
	LPVOID pFirstCode;				//首句代码的副本位置	(设置仅执行断点时)

	/**
		* 对所有线程下硬件断点(当前线程除外)
		* 参数 Drx-对哪个调试寄存器下硬断
		* 参数 Dr7Type-硬件断点的类型
		*	#define 硬断_仅执行 0x55
		*	#define 硬断_仅写入 0x55550055
		*	#define 硬断_读或写 0xFFFF0055
	*/
	BOOL HookAllThread(enum DRX Drx, DWORD64 Dr7Type);

public:
	/**
		* 构造器：硬件断点
		* 参数 BreakPointAddress
		* 参数 pVEHFunc
		* 参数 Drx-指定用于硬件断点的调试寄存器
		* 参数 firstCodeLen	被Hook函数的首句代码所占字节数 
			【MessageBoxA-4字节】【DrawIndexed-4字节】【Present-5字节】【CreateQuery-4】【PSSetShaderResources-3】
			【AddVectoredExceptionHandler-3】【GetThreadContext-3】【IsDebuggerPresent-9】
	*/
	HardwareBP(LPVOID BreakPointAddress, PVEH_Func pVEHFunc, enum DRX Drx, int firstCodeLen);
	/**
		* 设置硬断：利用向量异常处理机制
		* 参数 Dr7Type 硬件断点的类型
	*/
	VOID WINAPI SetVEHHook(DWORD64 Dr7Type);
};
//==================================================================================================================