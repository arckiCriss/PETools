#include "stdafx.h"
//8个32位通用寄存器
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
DWORD srcFuncAddr = 0;				//原函数的入口地址
DWORD retFuncAddr = 0;				//返回至原函数的地址
REGISTER_X86 register_x86 = { 0 };	//保存寄存器状态
PBYTE pSrcCodeBuffer = 0;			//保存被HOOK的代码句

/**
 * MyMessageBoxA_X86
 */
DWORD param1_MyMessageBoxA = 0;
DWORD param2_MyMessageBoxA = 0;
DWORD param3_MyMessageBoxA = 0;
DWORD param4_MyMessageBoxA = 0;


#if MY_X86 
	_declspec(naked) 
#endif 
void  InlineHook_MyMessageBoxA_X86()	//裸函数：自己处理堆栈平衡
{
#if MY_X86
	_asm
	{
		//寄存器入栈保存
		pushfd  //将32位标志寄存器EFLAGS压栈
		pushad	//将所有的32位通用寄存器压栈
	}

	//>>>>>>>> begin :执行自己的代码>>>>>>>>
	//打印寄存器
	_asm
	{
		mov register_x86.eax, eax
		mov register_x86.ebx, ebx
		mov register_x86.ecx, ecx
		mov register_x86.edx, edx
		mov register_x86.esp, esp
		mov register_x86.ebp, ebp
		mov register_x86.esi, esi
		mov register_x86.edi, edi
	}
	printf("8个通用寄存器：eax=%08X,ebx=%08X,ecx=%08X,edx=%08X,esp=%08X,ebp=%08X,esi=%08X,edi=%08X \n", register_x86.eax, register_x86.ebx, register_x86.ecx, register_x86.edx, register_x86.esp, register_x86.ebp, register_x86.esi, register_x86.edi);
	//打印参数
	_asm
	{
		//MessageBox函数共有4个参数入栈，且还有8个通用寄存器和1个EL寄存器入栈
		//堆栈中esp+(8+1)*0x4+0x10 是第1个入栈的参数
		mov eax, DWORD PTR SS : [esp + 0x34]
		mov param1_MyMessageBoxA, eax
		//堆栈中esp+(8+1)*0x4+0xC 是第2个入栈的参数
		mov eax, DWORD PTR SS : [esp + 0x30]
		mov param2_MyMessageBoxA, eax
		//堆栈中esp+(8+1)*0x4+0x8 是第3个入栈的参数
		mov eax, DWORD PTR SS : [esp + 0x2C]
		mov param3_MyMessageBoxA, eax
		//堆栈中esp+(8+1)*0x4+0x4 是第4个入栈的参数
		mov eax, DWORD PTR SS : [esp + 0x28]
		mov param4_MyMessageBoxA, eax
	}
	printf("MessageBoxA的参数: 参数1=%d , 参数2=%s， 参数3=%s, 参数4=%d \n", param1_MyMessageBoxA, param2_MyMessageBoxA, param3_MyMessageBoxA, param4_MyMessageBoxA);
	//>>>>>>>> end :执行自己的代码>>>>>>>>

	_asm
	{
		//寄存器出栈恢复现场
		popad
		popfd

		//执行被覆盖的原代码
		//	MessageBoxA的前五字节:
		//  75F57E60 8B FF                mov         edi, edi
		//	75F57E62 55                   push        ebp
		//	75F57E63 8B EC                mov         ebp, esp
		mov         edi, edi
		push        ebp
		mov         ebp, esp

		//跳转回原函数
		jmp retFuncAddr
	}

#endif
}



/**
 * InlineHook
 * 参数 destDllName
 * 参数 destFuncName
 * 参数 hookFuncAddr
 * 参数 byteLen	指定用原函数前(byteLen)字节的代码替换成jmp指令，最少为5字节(被Hook函数的前byteLen字节必须是完整的代码句)
 */
void InlineHook_X86(CHAR* destDllName, CHAR* destFuncName, DWORD hookFuncAddr, int byteLen)
{
	//获取目标函数的入口地址
	HMODULE destDll = GetModuleHandle(destDllName);
	if (destDll == 0)
	{
		printf("错误：不存在目标模块%s \n", destDllName);
		return;
	}
	srcFuncAddr = (DWORD)GetProcAddress(destDll, destFuncName);
	if (srcFuncAddr == 0)
	{
		printf("错误：目标模块中不存在目标函数%s \n", destFuncName);
		return;
	}

	//计算Hook结束时返回的地址
	retFuncAddr = srcFuncAddr + byteLen;

	//保存前(byteLen)字节的代码
	pSrcCodeBuffer = (PBYTE)malloc(byteLen);
	memset(pSrcCodeBuffer, 0x0, byteLen);
	memcpy(pSrcCodeBuffer, (void*)srcFuncAddr, byteLen);

	//修改前(byteLen)字节的代码为 JMP XXX 
	DWORD oldProtect = 0; DWORD newProtect = 0;
	VirtualProtect((LPVOID)srcFuncAddr, byteLen, PAGE_EXECUTE_READWRITE, &oldProtect);
	*(PBYTE)(srcFuncAddr) = 0xE9; //jmp
	*(DWORD*)(srcFuncAddr + 1) = hookFuncAddr - srcFuncAddr - 5; //jmp X  
	VirtualProtect((LPVOID)srcFuncAddr, byteLen, oldProtect, &newProtect);

	//测试调用
	MessageBox(0, TEXT("testText"), TEXT("testCaption"), 0);

}
