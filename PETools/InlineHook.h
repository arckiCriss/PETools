#pragma once
#include "pch.h"
//====指定对齐值为1======================
#pragma pack(1) 
//有条件跳转指令
struct HardCode_JCC
{
	BYTE JC;
	BYTE Opcode;	//JC指令的操作数只有1字节
};
struct HardCode_JMP
{
	BYTE JMP;		//0xE9
	DWORD Opcode;	//JMP操作数是4字节
};

//x64下的远跳
// PUSH Low32TargetAddr  5字节
// MOV  High32TargetAddr 8字节
// RET					 1字节
struct HardCode_FarJMP
{
	BYTE PUSH;				//0x68
	DWORD Addr_Low32;
	DWORD MOV_DWORD_PTR_SS;	//0x042444C7
	DWORD Addr_High32;
	BYTE RET;				//0xC3
};
#pragma pack() 
//====取消指定对齐值===============

/**
 * x86下的8个寄存器
 */
struct REGISTER_X86
{
	DWORD eax;
	DWORD ebx;
	DWORD ecx;
	DWORD edx;
	DWORD esp;
	DWORD ebp;
	DWORD esi;
	DWORD edi;
};
/**
 * x64下的16+1+1个寄存器
 */
struct REGISTER_X64
{
	DWORD64 rax;	//结构体首地址
	DWORD64 rbx;	//地址+8
	DWORD64 rcx;	//地址+16
	DWORD64 rdx;
	DWORD64 rsi;
	DWORD64 rdi;
	DWORD64 rsp;
	DWORD64 rbp;
	DWORD64 r8;
	DWORD64 r9;
	DWORD64 r10;
	DWORD64 r11;
	DWORD64 r12;
	DWORD64 r13;
	DWORD64 r14;
	DWORD64 r15;
	DWORD64 efl; //RFlags寄存器只有低32位有用，我暂时只能调用PUSHF指令，操作它的低16位
	DWORD64 rip; 
};

struct HOOKPARAM
{
	REGISTER_X64 reg_x64;
	DWORD64 originFunc;		//原函数的入口地址
	DWORD64 remainFunc;		//原始函数剩余代码的位置
	DWORD64 pCoverdCode;	//被覆盖的代码粘贴处(可执行区)
};
//声明：钩子函数所需参数
extern HOOKPARAM g_HookParam_Present;
extern HOOKPARAM g_HookParam_DrawIndexed;
extern HOOKPARAM g_HookParam_MessageBoxA;
extern HOOKPARAM g_HookParam_VirtualProtect;
extern HOOKPARAM g_HookParam_GetThreadContext;
extern HOOKPARAM g_HookParam_CreateQuery;


//function
VOID InlineHook_X86(const CHAR* destDllName, const CHAR* destFuncName, DWORD64 hookFuncAddr, int byteLen);
VOID InlineHook_X64(DWORD64 destFunc, int byteLen, DWORD64 hookFunc, PVOID pHandleCoverdCode);

VOID InlineHook_X64_HandleCoverdCode_MessageBoxA(DWORD64 originFunc, int byteLen);
VOID InlineHook_X64_HandleCoverdCode_D3D11Present(DWORD64 originFunc, int byteLen);
VOID InlineHook_X64_HandleCoverdCode_D3D11DrawIndexed(DWORD64 originFunc, int byteLen);
VOID InlineHook_X64_HandleCoverdCode_D3D11CreateQuery(DWORD64 originFunc, int byteLen);
VOID InlineHook_X64_HandleCoverdCode_VirtualProtect(DWORD64 originFunc, int byteLen);
VOID InlineHook_X64_HandleCoverdCode_GetThreadContext(DWORD64 originFunc, int byteLen);

VOID InlineHook_X64_MyMessageBoxA();
VOID InlineHook_X86_MyMessageBoxA();
VOID InlineHook_X64_MyPresent();
VOID InlineHook_X64_MyDrawIndexed();
VOID InlineHook_X64_MyVirtualProtect();
VOID InlineHook_X64_MyGetThreadContext();
VOID InlineHook_X64_MyCreateQuery();

VOID CalcMaxMinAddr_BubbleSort(DWORD64 arr[], int len, OUT DWORD64& max, OUT DWORD64& min);
