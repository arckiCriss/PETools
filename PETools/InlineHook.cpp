#include "pch.h"


REGISTER_X86 reg_x86 = { 0 };				//32位寄存器
PBYTE pSrcCodeBuffer = 0;					//保存被HOOK的代码句

//定义：钩子函数所需参数
HOOKPARAM g_HookParam_Present;
HOOKPARAM g_HookParam_DrawIndexed;
HOOKPARAM g_HookParam_MessageBoxA;
HOOKPARAM g_HookParam_VirtualProtect;
HOOKPARAM g_HookParam_GetThreadContext;
HOOKPARAM g_HookParam_CreateQuery;

/**
 * MyMessageBoxA_X86
 */
DWORD param1_MyMessageBoxA_X86 = 0;
DWORD param2_MyMessageBoxA_X86 = 0;
DWORD param3_MyMessageBoxA_X86 = 0;
DWORD param4_MyMessageBoxA_X86 = 0;
#if _IS_X86 
_declspec(naked)
#endif 
VOID  InlineHook_X86_MyMessageBoxA()	//裸函数：自己处理堆栈平衡
{
#if _IS_X86
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
		mov reg_x86.eax, eax
		mov reg_x86.ebx, ebx
		mov reg_x86.ecx, ecx
		mov reg_x86.edx, edx
		mov reg_x86.esp, esp
		mov reg_x86.ebp, ebp
		mov reg_x86.esi, esi
		mov reg_x86.edi, edi
	}
	printf("8个通用寄存器：eax=%08X,ebx=%08X,ecx=%08X,edx=%08X,esp=%08X,ebp=%08X,esi=%08X,edi=%08X \n", reg_x86.eax, reg_x86.ebx, reg_x86.ecx, reg_x86.edx, reg_x86.esp, reg_x86.ebp, reg_x86.esi, reg_x86.edi);
	//打印参数
	_asm
	{
		//MessageBox函数共有4个参数入栈，且还有8个通用寄存器和1个EL寄存器入栈
		//堆栈中esp+(8+1)*0x4+0x10 是第1个入栈的参数
		mov eax, DWORD PTR SS : [esp + 0x34]
		mov param1_MyMessageBoxA_X86, eax
		//堆栈中esp+(8+1)*0x4+0xC 是第2个入栈的参数
		mov eax, DWORD PTR SS : [esp + 0x30]
		mov param2_MyMessageBoxA_X86, eax
		//堆栈中esp+(8+1)*0x4+0x8 是第3个入栈的参数
		mov eax, DWORD PTR SS : [esp + 0x2C]
		mov param3_MyMessageBoxA_X86, eax
		//堆栈中esp+(8+1)*0x4+0x4 是第4个入栈的参数
		mov eax, DWORD PTR SS : [esp + 0x28]
		mov param4_MyMessageBoxA_X86, eax
	}
	printf("MessageBoxA的参数: 参数1=%d , 参数2=%s， 参数3=%s, 参数4=%d \n", param1_MyMessageBoxA_X86, param2_MyMessageBoxA_X86, param3_MyMessageBoxA_X86, param4_MyMessageBoxA_X86);
	//>>>>>>>> end :执行自己的代码>>>>>>>>

	_asm
	{
		//寄存器出栈恢复现场
		popad
		popfd

		//执行被覆盖的原代码
		//	MessageBoxA(X86)的前5字节:
		//  75F57E60 8B FF                mov         edi, edi
		//	75F57E62 55                   push        ebp
		//	75F57E63 8B EC                mov         ebp, esp
		mov         edi, edi
		push        ebp
		mov         ebp, esp

		//跳转回原函数
		jmp backAddr
	}

#endif
}


/**
 * InlineHook (32位)
 * 参数 destDllName
 * 参数 destFuncName
 * 参数 hookFuncAddr
 * 参数 byteLen	指定用原函数前(byteLen)字节的代码替换成jmp指令，最少为5字节(被Hook函数的前byteLen字节必须是完整的代码句)
 */
VOID InlineHook_X86(const CHAR* destDllName, const CHAR* destFuncName, DWORD64 hookFuncAddr, int byteLen)
{
	//MessageBox(0, TEXT("testText"), TEXT("testCaption"), 0);
	//printf("\n开始Inline Hook ... \n");
	////获取目标函数的入口地址
	//HMODULE destDll = GetModuleHandle(destDllName);
	//if (destDll == 0)
	//{
	//	printf("错误：不存在目标模块%s \n", destDllName);
	//	return;
	//}
	//originFunc = (DWORD64)GetProcAddress(destDll, destFuncName);
	//if (originFunc == 0)
	//{
	//	printf("错误：目标模块中不存在目标函数%s \n", destFuncName);
	//	return;
	//}

	////计算原始函数剩余代码的位置
	//remainAddr = originFunc + byteLen;

	////保存前(byteLen)字节的代码
	//pSrcCodeBuffer = (PBYTE)malloc(byteLen);
	//memset(pSrcCodeBuffer, 0x0, byteLen);
	//memcpy(pSrcCodeBuffer, (void*)originFunc, byteLen);

	////修改前(byteLen)字节的代码为 JMP XXX 
	//DWORD oldProtect = 0; DWORD newProtect = 0;
	//VirtualProtect((LPVOID)originFunc, byteLen, PAGE_EXECUTE_READWRITE, &oldProtect);
	//*(PBYTE)(originFunc) = 0xE9; //jmp
	//*(DWORD*)(originFunc + 1) = hookFuncAddr - originFunc - 5; //jmp X  
	//VirtualProtect((LPVOID)originFunc, byteLen, oldProtect, &newProtect);

	////测试调用
	//MessageBox(0, TEXT("testText"), TEXT("testCaption"), 0);
}


/**
 * MessageBoxA的钩子函数 (64位)
 * 1.因为x64不能写裸函数，所以钩子函数的调用地址需要修正到函数体
 * 2.在本函数中不能使用局部变量，因为局部变量的赋值会使用寄存器。
 *   而调用本函数时为了模拟裸函数，跳过了编译器在函数头部的堆栈操作，使得寄存器的值等于裸函数调用前的值
 *   例如局部变量赋值的语句 MOV [rbp+4h],666h ，一旦寄存器在裸函数调用前的值等于0，就会发生访问冲突异常。
 * 3.在本函数中，必须确保rbp是16字节对齐(0x10整数倍)，这就要求rsp也是16字节对齐，在手动提升堆栈时需注意。
 */
VOID InlineHook_X64_MyMessageBoxA()
{
	//保存所有寄存器至全局变量
	ASM_SaveReg(&::g_HookParam_MessageBoxA);
	//printf("原寄存器的值：\n[rax]=%016llX [rbx]=%016llX [rcx]=%016llX [rdx]=%016llX \n[rsi]=%016llX [rdi]=%016llX [rsp]=%016llX [rbp]=%016llX \n[r8 ]=%016llX [r9 ]=%016llX [r10]=%016llX [r11]=%016llX \n[r12]=%016llX [r13]=%016llX [r14]=%016llX [r15]=%016llX \n[efl]=%016llX \n", reg_x64.rax, reg_x64.rbx, reg_x64.rcx, reg_x64.rdx, reg_x64.rsi, reg_x64.rdi, reg_x64.rsp, reg_x64.rbp, reg_x64.r8, reg_x64.r9, reg_x64.r10, reg_x64.r11, reg_x64.r12, reg_x64.r13, reg_x64.r14, reg_x64.r15, reg_x64.efl);

	//Malware
	printf("打印MessageBoxA()参数：标题=%s , 文本=%s \n", ::g_HookParam_MessageBoxA.reg_x64.r8, ::g_HookParam_MessageBoxA.reg_x64.rdx);

	//恢复寄存器、跳转至被覆盖的代码
	ASM_RecoverReg(&::g_HookParam_MessageBoxA, ::g_HookParam_MessageBoxA.pCoverdCode);
}

/**
 * GetThreadContext的钩子函数 (64位)
 * 1.因为x64不能写裸函数，所以钩子函数的调用地址需要修正到函数体
 * 2.在本函数中不能使用局部变量，因为局部变量的赋值会使用寄存器。
 *   而调用本函数时为了模拟裸函数，跳过了编译器在函数头部的堆栈操作，使得寄存器的值等于裸函数调用前的值
 *   例如局部变量赋值的语句 MOV [rbp+4h],666h ，一旦寄存器在裸函数调用前的值等于0，就会发生访问冲突异常。
 * 3.在本函数中，必须确保rbp是16字节对齐(0x10整数倍)，这就要求rsp也是16字节对齐，在手动提升堆栈时需注意。
 */
VOID InlineHook_X64_MyGetThreadContext()
{
	//保存所有寄存器至全局变量
	ASM_SaveReg(&::g_HookParam_GetThreadContext);

	//Malware
	//函数原型：WINBASEAPI BOOL WINAPI GetThreadContext(_In_ HANDLE hThread, _Inout_ LPCONTEXT lpContext);
	//00007FF75C414299 33 D2                xor         edx, edx	;参数2 rdx lpContext
	//00007FF75C41429B 33 C9                xor         ecx, ecx	;参数1 rcx hThread
	//00007FF75C41429D FF 15 15 8E 04 00    call        qword ptr[__imp_GetThreadContext(07FF75C45D0B8h)]
	HANDLE hThread = (HANDLE)g_HookParam_GetThreadContext.reg_x64.rcx;
	LPCONTEXT lpContext = (LPCONTEXT)g_HookParam_GetThreadContext.reg_x64.rdx;
	printf("打印GetThreadContext()参数：hThread=%016llX , lpContext=%016llX \n", hThread, lpContext);

	//恢复寄存器、跳转至被覆盖的代码
	ASM_RecoverReg(&::g_HookParam_GetThreadContext, ::g_HookParam_GetThreadContext.pCoverdCode);
}


/**
 * D3D11 Present的钩子函数 (64位)
 * 1.因为x64不能写裸函数，所以钩子函数的调用地址需要修正到函数体
 * 2.在本函数中不能使用局部变量，因为局部变量的赋值会使用寄存器。
 *   而调用本函数时为了模拟裸函数，跳过了编译器在函数头部的堆栈操作，使得寄存器的值等于裸函数调用前的值
 *   例如局部变量赋值的语句 MOV [rbp+4h],666h ，一旦寄存器在裸函数调用前的值等于0，就会发生访问冲突异常。
 * 3.在本函数中，必须确保rbp是16字节对齐(0x10整数倍)，这就要求rsp也是16字节对齐，在手动提升堆栈时需注意。
 */
VOID InlineHook_X64_MyPresent()
{
	//保存所有寄存器至全局变量
	ASM_SaveReg(&::g_HookParam_Present);
	//printf("原寄存器的值：\n[rax]=%016llX [rbx]=%016llX [rcx]=%016llX [rdx]=%016llX \n[rsi]=%016llX [rdi]=%016llX [rsp]=%016llX [rbp]=%016llX \n[r8 ]=%016llX [r9 ]=%016llX [r10]=%016llX [r11]=%016llX \n[r12]=%016llX [r13]=%016llX [r14]=%016llX [r15]=%016llX \n[efl]=%016llX \n", reg_x64.rax, reg_x64.rbx, reg_x64.rcx, reg_x64.rdx, reg_x64.rsi, reg_x64.rdi, reg_x64.rsp, reg_x64.rbp, reg_x64.r8, reg_x64.r9, reg_x64.r10, reg_x64.r11, reg_x64.r12, reg_x64.r13, reg_x64.r14, reg_x64.r15, reg_x64.efl);

	//Malware
	ChreatD3D11_MyPresent(&g_HookParam_Present.reg_x64);

	//恢复寄存器、跳转回被覆盖的代码
	ASM_RecoverReg(&g_HookParam_Present, g_HookParam_Present.pCoverdCode);
}
/**
 * D3D11 DrawIndexed的钩子函数 (64位)
 * 1.因为x64不能写裸函数，所以钩子函数的调用地址需要修正到函数体
 * 2.在本函数中不能使用局部变量，因为局部变量的赋值会使用寄存器。
 *   而调用本函数时为了模拟裸函数，跳过了编译器在函数头部的堆栈操作，使得寄存器的值等于裸函数调用前的值
 *   例如局部变量赋值的语句 MOV [rbp+4h],666h ，一旦寄存器在裸函数调用前的值等于0，就会发生访问0x0000000000000004冲突异常。
 * 3.在本函数中，必须确保rbp是16字节对齐(0x10整数倍)，这就要求rsp也是16字节对齐，在手动提升堆栈时需注意。
 */
VOID InlineHook_X64_MyDrawIndexed()
{
	//保存所有寄存器至全局变量
	ASM_SaveReg(&g_HookParam_DrawIndexed);
	//printf("原寄存器的值：\n[rax]=%016llX [rbx]=%016llX [rcx]=%016llX [rdx]=%016llX \n[rsi]=%016llX [rdi]=%016llX [rsp]=%016llX [rbp]=%016llX \n[r8 ]=%016llX [r9 ]=%016llX [r10]=%016llX [r11]=%016llX \n[r12]=%016llX [r13]=%016llX [r14]=%016llX [r15]=%016llX \n[efl]=%016llX \n", reg_x64.rax, reg_x64.rbx, reg_x64.rcx, reg_x64.rdx, reg_x64.rsi, reg_x64.rdi, reg_x64.rsp, reg_x64.rbp, reg_x64.r8, reg_x64.r9, reg_x64.r10, reg_x64.r11, reg_x64.r12, reg_x64.r13, reg_x64.r14, reg_x64.r15, reg_x64.efl);

	//Malware
	if (FALSE == ChreatD3D11_MyDrawIndexed(&g_HookParam_DrawIndexed.reg_x64, ::g_HookParam_DrawIndexed.pCoverdCode))
	{	//直接结束原始函数
		ASM_EndOrigin(&g_HookParam_DrawIndexed);
	}

	//恢复寄存器、跳转回被覆盖的代码
	ASM_RecoverReg(&::g_HookParam_DrawIndexed, ::g_HookParam_DrawIndexed.pCoverdCode);
}
/**
 * D3D11-CreateQuery的钩子函数 (64位)
 * 1.因为x64不能写裸函数，所以钩子函数的调用地址需要修正到函数体
 * 2.在本函数中不能使用局部变量，因为局部变量的赋值会使用寄存器。
 *   而调用本函数时为了模拟裸函数，跳过了编译器在函数头部的堆栈操作，使得寄存器的值等于裸函数调用前的值
 *   例如局部变量赋值的语句 MOV [rbp+4h],666h ，一旦寄存器在裸函数调用前的值等于0，就会发生访问0x0000000000000004冲突异常。
 * 3.在本函数中，必须确保rbp是16字节对齐(0x10整数倍)，这就要求rsp也是16字节对齐，在手动提升堆栈时需注意。
 */
VOID InlineHook_X64_MyCreateQuery()
{
	//保存所有寄存器至全局变量
	ASM_SaveReg(&g_HookParam_CreateQuery);
	
	//Malware
	if (FALSE == ChreatD3D11_MyCreateQuery(&g_HookParam_CreateQuery.reg_x64, ::g_HookParam_CreateQuery.pCoverdCode))
	{	//直接结束原始函数
		ASM_EndOrigin(&g_HookParam_CreateQuery);
	}

	//恢复寄存器、跳转回被覆盖的代码
	ASM_RecoverReg(&::g_HookParam_CreateQuery, ::g_HookParam_CreateQuery.pCoverdCode);
}

/**
 * VirtualProtect的钩子函数 (64位)
 * 1.因为x64不能写裸函数，所以钩子函数的调用地址需要修正到函数体
 * 2.在本函数中不能使用局部变量，因为局部变量的赋值会使用寄存器。
 *   而调用本函数时为了模拟裸函数，跳过了编译器在函数头部的堆栈操作，使得寄存器的值等于裸函数调用前的值
 *   例如局部变量赋值的语句 MOV [rbp+4h],666h ，一旦寄存器在裸函数调用前的值等于0，就会发生访问0x0000000000000004冲突异常。
 * 3.在本函数中，必须确保rbp是16字节对齐(0x10整数倍)，这就要求rsp也是16字节对齐，在手动提升堆栈时需注意。
 */
VOID InlineHook_X64_MyVirtualProtect()
{
	//保存所有寄存器至全局变量
	ASM_SaveReg(&g_HookParam_VirtualProtect);

	//Malware
	printf("【info】进入MyVirtualProtect...\n");

	//恢复寄存器、跳转回被覆盖的代码
	ASM_RecoverReg(&::g_HookParam_VirtualProtect, ::g_HookParam_VirtualProtect.pCoverdCode);

}

/**
 * 申请与指令集的差距小于2GB的地址空间 (64位)
 * 参数 minInstructionAddr	//被覆盖的指令集中用到的最前（最小）的地址
 * 参数 maxInstructionAddr	//被覆盖的指令集中用到的最后（最大）的地址
 */
DWORD64 AllocMemWithin2GB(DWORD64 minInstructionAddr, DWORD64 maxInstructionAddr, int needLen)
{
	printf("【info】开始申请2GB范围内的空间，被挂钩函数被覆盖代码中用到的最小地址=%016llX  最大地址=%016llX \n", minInstructionAddr, maxInstructionAddr);
	//根据最前和最后的指令计算2GB范围内的地址
	DWORD64 pFront = maxInstructionAddr - 0x7FFFFFFF; //在2GB内能寻址的最前地址
	DWORD64 pBack = minInstructionAddr + 0x7FFFFFFF; //在2GB内能寻址的最后地址
	pFront += (0x10000 - (pFront % 0x10000));      //最前地址修正为下个64kb对齐的地址
	DWORD64 pCoverdCode = 0;
	while (true)
	{
		//申请的地址值必须是以64kb对齐(即0x10000整数倍的地址值)
		//如果传入参数不是64kb对齐的则会自动取整，例如传入0x36666时会自动修正为申请0x30000的内存区域
		pCoverdCode = (DWORD64)VirtualAllocEx(GetCurrentProcess(), (LPVOID)pFront, needLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		//申请下一个64kb对齐的地址
		pFront += 0x10000;
		if (pCoverdCode != 0)
		{
			printf("【info】申请成功，被覆盖代码的粘贴地址=%016llX \n", pCoverdCode);
			return pCoverdCode;
		}

		if (pFront + 14 >= pBack)
		{
			printf("【info】申请失败，前后2GB范围内找不到可用地址 \n");
			return 0;
		}
	};
}

/**
 * 专门处理64位被HOOK函数的被覆盖代码：MessageBoxA
 */
VOID InlineHook_X64_HandleCoverdCode_MessageBoxA(DWORD64 originFunc, int byteLen)
{

	//原始 MessageBoxA 16字节
	//00007FFDE5E5E7A0 48 83 EC 38          sub         rsp, 38h
	//00007FFDE5E5E7A4 45 33 DB             xor         r11d, r11d
	//00007FFDE5E5E7A7 44 39 1D 0A 59 03 00 cmp         dword ptr[7FFDE5E940B8h], r11d------相对寻址(下条指令+操作数)
	//00007FFDE5E5E7AE 74 2E                je          00007FFDE5E5E7DE-----------相对寻址(下条指令+操作数)

	//修改后共占15字节
	//newAddr			sub         rsp, 38h
	//newAddr+0x4		xor         r11d, r11d
	//newAddr+0x7		cmp         dword ptr[原目标地址], r11d
	//newAddr+0xE		je			newAddr+0x15	;跳到下下条指令
	//newAddr+0x10		jmp			backAddr		;跳回原函数
	//newAddr+0x15		jmp			oldJEDestAddr	;跳到原JE要跳的地方
	//newAddr+0x1A

	//计算Hook结束后要返回到哪个地址继续执行剩余代码
	::g_HookParam_MessageBoxA.originFunc = originFunc;
	::g_HookParam_MessageBoxA.remainFunc = originFunc + byteLen;

	//原始CMP的Opcode	(4字节)****
	DWORD oldCmp_Opcode = *(DWORD*)(originFunc + 0xA);

	//原始CMP的目标地址 = 偏移+ CMP下个指令地址
	DWORD64 oldCmp_DestAddr = oldCmp_Opcode + (originFunc + 0xE);

	//得到被覆盖的指令集中用到的最前地址
	DWORD64 frontAddr = (originFunc + 0x10) + *(BYTE*)(originFunc + 0xF);
	//得到被覆盖的指令集中用到的最后地址
	DWORD64 backAddr = oldCmp_DestAddr;

	//申请范围在2GB内的虚拟内存 ,MessageBoxA需要0x15字节
	::g_HookParam_MessageBoxA.pCoverdCode = AllocMemWithin2GB(frontAddr, backAddr, 0x15);//*

	//原始CMP指令前3字节的硬编码 (3字节)****
	DWORD64 oldCmp = 0x1D3944;

	//新CMP的相对寻址偏移= 目标地址 - CMP下个指令地址
	DWORD64 newCmpDestOff = oldCmp_DestAddr - (::g_HookParam_MessageBoxA.pCoverdCode + 0xE);//*

	//原始JE
	HardCode_JCC oldJCC;
	oldJCC.JC = 0x74;
	oldJCC.Opcode = *(DWORD*)(originFunc + 0xF);

	// 原始JE要跳转的目标地址
	DWORD64 oldJeDest = originFunc + 0x10 + oldJCC.Opcode;

	//新JE****
	HardCode_JCC newJCC;
	newJCC.JC = 0x74;
	newJCC.Opcode = 0x5; //JC的Opcode= 目标地址 - JC下条指令地址

	//新JMP_1，跳回原函数********
	HardCode_JMP newJMP1;
	newJMP1.JMP = 0xE9;
	newJMP1.Opcode = ::g_HookParam_MessageBoxA.remainFunc - (::g_HookParam_MessageBoxA.pCoverdCode + 0x15);

	//新JMP_2，跳到原JE要跳的位置********
	HardCode_JMP newJMP2;
	newJMP2.JMP = 0xE9;
	newJMP2.Opcode = oldJeDest - (::g_HookParam_MessageBoxA.pCoverdCode + 0x1A);

	//写入修改后的原函数代码
	memcpy((PVOID)::g_HookParam_MessageBoxA.pCoverdCode, (PVOID)originFunc, 0x7); //*
	memcpy((PVOID)(::g_HookParam_MessageBoxA.pCoverdCode + 0x7), &oldCmp, 0x3);//*
	memcpy((PVOID)(::g_HookParam_MessageBoxA.pCoverdCode + 0x7 + 0x3), &newCmpDestOff, 0x4);//*
	memcpy((PVOID)(::g_HookParam_MessageBoxA.pCoverdCode + 0x7 + 0x3 + 0x4), &newJCC, sizeof(newJCC));//*
	memcpy((PVOID)(::g_HookParam_MessageBoxA.pCoverdCode + 0x7 + 0x3 + 0x4 + 0x2), &newJMP1, sizeof(newJMP1));//*
	memcpy((PVOID)(::g_HookParam_MessageBoxA.pCoverdCode + 0x7 + 0x3 + 0x4 + 0x2 + 0x5), &newJMP2, sizeof(newJMP2));//*

}
/**
 * 专门处理64位被HOOK函数的被覆盖代码：D3D11的Present
 */
VOID InlineHook_X64_HandleCoverdCode_D3D11Present(DWORD64 originFunc, int byteLen)
{
	//原始 Present 19字节的完整代码 (必须大于16字节)
	//00007FFC8F245070 48 89 5C 24 10       mov         qword ptr[rsp + 10h], rbx
	//00007FFC8F245075 48 89 74 24 20       mov         qword ptr[rsp + 20h], rsi
	//00007FFC8F24507A 55                   push        rbp
	//00007FFC8F24507B 57                   push        rdi
	//00007FFC8F24507C 41 56                push        r14
	//00007FFC8F24507E 48 8D 6C 24 90       lea         rbp, [rsp - 70h]

	//修改后共占19+14字节	(因为被覆盖的代码中无"相对寻址"，所以粘贴位置没有2GB的范围限制)
	//newAddr				mov         qword ptr[rsp + 10h], rbx
	//newAddr+5h			mov         qword ptr[rsp + 20h], rsi
	//newAddr+Ah            push        rbp
	//newAddr+Bh			push        rdi
	//newAddr+Ch			push        r14
	//newAddr+Eh			lea         rbp, [rsp - 70h]
	//newAddr+13h			PUSH		Low32RetAddr
	//newAddr+18h			MOV			High32RetAddr
	//newAddr+20h			RET		

	//计算Hook结束后要返回到哪个地址继续执行剩余代码
	::g_HookParam_Present.originFunc = originFunc;
	::g_HookParam_Present.remainFunc = originFunc + byteLen;

	//构造"远跳"指令
	HardCode_FarJMP FarJmp;
	FarJmp.PUSH = 0x68;
	FarJmp.Addr_Low32 = (DWORD)::g_HookParam_Present.remainFunc; //*
	FarJmp.MOV_DWORD_PTR_SS = 0x042444C7;
	FarJmp.Addr_High32 = ::g_HookParam_Present.remainFunc >> 32;//*
	FarJmp.RET = 0xC3;

	//申请空间，粘贴被覆盖的代码
	::g_HookParam_Present.pCoverdCode = (DWORD64)VirtualAllocEx(GetCurrentProcess(), NULL, 19 + 14, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);//*
	printf("【info】被覆盖代码粘贴位置=%016llX \n", ::g_HookParam_Present.pCoverdCode);//*
	memcpy((PVOID)::g_HookParam_Present.pCoverdCode, (PVOID)originFunc, 19);//*

	//在末尾粘贴"远跳"指令
	memcpy((PVOID)(::g_HookParam_Present.pCoverdCode + 19), &FarJmp, sizeof(FarJmp));//*

}

/**
 * 专门处理64位被HOOK函数的被覆盖代码：D3D11的DrawIndexed
 */
VOID InlineHook_X64_HandleCoverdCode_D3D11DrawIndexed(DWORD64 originFunc, int byteLen)
{
	//原始 DrawIndexed 19字节的完整代码 (必须大于16字节)
	//00007FFC8CA37D80 48 83 EC 38          sub         rsp, 38h
	//00007FFC8CA37D84 44 8B DA             mov         r11d, edx
	//00007FFC8CA37D87 48 81 C1 28 FF FF FF add         rcx, 0FFFFFFFFFFFFFF28h
	//00007FFC8CA37D8E BA 00 A0 00 00       mov         edx, 0A000h

	//修改后共占19+14字节	(因为被覆盖的代码中无"相对寻址"，所以粘贴位置没有2GB的范围限制)
	//newAddr       sub         rsp, 38h
	//newAddr+4h    mov         r11d, edx
	//newAddr+7h	add         rcx, 0FFFFFFFFFFFFFF28h
	//newAddr+Eh	mov         edx, 0A000h
	//newAddr+13h	PUSH		Low32RetAddr	5 byte
	//newAddr+18h	MOV			High32RetAddr	8 byte
	//newAddr+20h	RET							1 byte


	//计算Hook结束后要返回到哪个地址继续执行剩余代码
	::g_HookParam_DrawIndexed.originFunc = originFunc;				//*
	::g_HookParam_DrawIndexed.remainFunc = originFunc + byteLen;	//*

	//构造"远跳"指令
	HardCode_FarJMP FarJmp;
	FarJmp.PUSH = 0x68;
	FarJmp.Addr_Low32 = (DWORD)g_HookParam_DrawIndexed.remainFunc; //*
	FarJmp.MOV_DWORD_PTR_SS = 0x042444C7;
	FarJmp.Addr_High32 = g_HookParam_DrawIndexed.remainFunc >> 32; //*
	FarJmp.RET = 0xC3;

	//申请空间，粘贴被覆盖的代码
	g_HookParam_DrawIndexed.pCoverdCode = (DWORD64)VirtualAllocEx(GetCurrentProcess(), NULL, 19 + 14, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);//*
	memcpy((PVOID)g_HookParam_DrawIndexed.pCoverdCode, (PVOID)originFunc, 19); //*

	//在末尾粘贴"远跳"指令
	memcpy((PVOID)(g_HookParam_DrawIndexed.pCoverdCode + 19), &FarJmp, sizeof(FarJmp)); //*

}

/**
 * 专门处理64位被HOOK函数的被覆盖代码：VirtualProtect
 */
VOID InlineHook_X64_HandleCoverdCode_VirtualProtect(DWORD64 originFunc, int byteLen)
{
	//原始 VirtualProtect 17(0x11)字节的完整代码 (必须大于16字节)
	//00007FFCEC48C9C0 48 8B C4             mov         rax, rsp
	//00007FFCEC48C9C3 48 89 58 18          mov         qword ptr[rax + 18h], rbx
	//00007FFCEC48C9C7 55                   push        rbp
	//00007FFCEC48C9C8 56                   push        rsi
	//00007FFCEC48C9C9 57                   push        rdi
	//00007FFCEC48C9CA 48 83 EC 30          sub         rsp, 30h
	//00007FFCEC48C9CE 49 8B F1             mov         rsi, r9

	//修改后共占17+14(0x1F)字节	(因为被覆盖的代码中无"相对寻址"，所以粘贴位置没有2GB的范围限制)
	//newAddr	  				mov         rax, rsp
	//newAddr+3h				mov			qword ptr[rax + 18h], rbx
	//newAddr+7h                push        rbp
	//newAddr+8h                push        rsi
	//newAddr+9h                push        rdi
	//newAddr+Ah				sub         rsp, 30h
	//newAddr+Eh		        mov         rsi, r9
	//newAddr+11h				PUSH		Low32RetAddr	5 byte
	//newAddr+16h				MOV			High32RetAddr	8 byte
	//newAddr+1Eh				RET							1 byte

	//计算Hook结束后要返回到哪个地址继续执行剩余代码
	::g_HookParam_VirtualProtect.originFunc = originFunc;				//*
	::g_HookParam_VirtualProtect.remainFunc = originFunc + byteLen;		//*

	//构造"远跳"指令
	HardCode_FarJMP FarJmp;
	FarJmp.PUSH = 0x68;
	FarJmp.Addr_Low32 = (DWORD)g_HookParam_VirtualProtect.remainFunc; //*
	FarJmp.MOV_DWORD_PTR_SS = 0x042444C7;
	FarJmp.Addr_High32 = g_HookParam_VirtualProtect.remainFunc >> 32; //*
	FarJmp.RET = 0xC3;

	//申请空间，粘贴被覆盖的代码
	g_HookParam_VirtualProtect.pCoverdCode = (DWORD64)VirtualAllocEx(GetCurrentProcess(), NULL, 17 + 14, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);//*
	printf("【info】原始函数被覆盖代码的粘贴位置=%016llX \n", g_HookParam_VirtualProtect.pCoverdCode);	//*
	memcpy((PVOID)g_HookParam_VirtualProtect.pCoverdCode, (PVOID)originFunc, 17);				//*

	//在末尾粘贴"远跳"指令
	memcpy((PVOID)(g_HookParam_VirtualProtect.pCoverdCode + 17), &FarJmp, sizeof(FarJmp));		//*
}
/**
 * 冒泡排序计算最小地址值、最大地址值
 * 参数 arr
 * 参数 len  注意: len=sizeof(arr) / sizeof(DWORD64)
 * 参数 max
 * 参数 min
 */
VOID CalcMaxMinAddr_BubbleSort(DWORD64 arr[], int len, OUT DWORD64& max, OUT DWORD64& min)
{
	if (len < 2) { printf("【error】数组大小错误...\n"); return; }
	//冒泡排序
	for (int j = 0; j < len - 1; j++)
	{
		for (int i = 0; i < len - 1 - j; i++)
		{
			if (arr[i] > arr[i + 1])
			{
				DWORD64 temp = arr[i];
				arr[i] = arr[i + 1];
				arr[i + 1] = temp;
			}
		}
	}
	min = arr[0];
	max = arr[len - 1];
	return;
}

/**
 * 专门处理64位被HOOK函数的被覆盖代码：GetThreadContext
 */
VOID InlineHook_X64_HandleCoverdCode_GetThreadContext(DWORD64 originFunc, int byteLen)
{
	//原始 GetThreadContext 18(0x12)字节的完整代码 (必须大于16字节)
	//00007FFAB2BDEDB0 48 83 EC 28          sub         rsp, 28h
	//00007FFAB2BDEDB4 FF 15 4E 43 11 00    call        qword ptr[7FFAB2CF3108h]-----相对寻址=下条指令地址+操作数
	//00007FFAB2BDEDBA 85 C0                test        eax, eax
	//00007FFAB2BDEDBC 0F 88 68 FB 02 00    js          00007FFAB2C0E92A-------------相对寻址=下条指令地址+操作数

	//修改后共占18+14(0x20)字节	(因为被覆盖的代码中有"相对寻址"，所以粘贴位置有2GB的范围限制)
	//newAddr					sub         rsp, 28h
	//newAddr+ 0x4				call        qword ptr[7FFAB2CF3108h]	;需修正opcode
	//newAddr+ 0xA              test        eax, eax
	//newAddr+ 0xC				js          00007FFAB2C0E92A			;需修正opcode
	//newAddr+ 0x12				jmp			remainAddr					;跳转至被挂钩函数剩余代码的地址  (5字节)
	//newAddr+ 0x17				

	//计算Hook结束后要返回到哪个地址继续执行剩余代码
	::g_HookParam_GetThreadContext.originFunc = originFunc;				//*
	::g_HookParam_GetThreadContext.remainFunc = originFunc + byteLen;	//*

	//原call指令的opcode
	DWORD opcode_old_call = *(DWORD*)(originFunc + 0x4 + 0x2);
	//原call指令的目标地址 = opcode + 下条指令的地址
	DWORD64 destAddr_old_call = opcode_old_call + (originFunc + 0xA);
	//原js指令的opcode
	DWORD opcode_old_js = *(DWORD*)(originFunc + 0xC + 0x2);
	//原js指令的目标地址 = opcode + 下条指令的地址
	DWORD64 destAddr_old_js = opcode_old_js + (originFunc + 0x12);

	//计算被挂钩函数被覆盖指令中用到的最小、最大地址 
	DWORD64 arr[3] = { 0 };
	arr[0] = destAddr_old_call;
	arr[1] = destAddr_old_js;
	arr[2] = g_HookParam_GetThreadContext.remainFunc;
	DWORD64 maxAddr = 0;
	DWORD64 minAddr = 0;
	CalcMaxMinAddr_BubbleSort(arr, sizeof(arr) / sizeof(DWORD64), maxAddr, minAddr);

	//申请范围在2GB内的虚拟内存 , GetThreadContext()需要0x20字节
	::g_HookParam_GetThreadContext.pCoverdCode = AllocMemWithin2GB(minAddr, maxAddr, 0x20);

	//根据指令粘贴地址，计算新操作数opcode
	DWORD opcode_new_call = destAddr_old_call - (g_HookParam_GetThreadContext.pCoverdCode + 0xA);
	DWORD opcode_new_js = destAddr_old_js - (g_HookParam_GetThreadContext.pCoverdCode + 0x12);
	DWORD opcode_jmp = g_HookParam_GetThreadContext.remainFunc - (g_HookParam_GetThreadContext.pCoverdCode + 0x17);

	//构造JMP硬编码
	HardCode_JMP newJMP = { 0 };
	newJMP.JMP = 0xE9;
	newJMP.Opcode = opcode_jmp;

	//粘贴被覆盖代码
	memcpy((PVOID)::g_HookParam_GetThreadContext.pCoverdCode, (PVOID)originFunc, 0x12);
	//修改被覆盖代码的部分操作数opcode
	*(DWORD*)(g_HookParam_GetThreadContext.pCoverdCode + 0x4 + 0x2) = opcode_new_call;
	*(DWORD*)(g_HookParam_GetThreadContext.pCoverdCode + 0xC + 0x2) = opcode_new_js;
	//在被覆盖代码的末尾增加JMP近跳转指令
	memcpy((PVOID)(::g_HookParam_GetThreadContext.pCoverdCode + 0x12), &newJMP, sizeof(newJMP));

}
/**
 * 专门处理64位被HOOK函数的被覆盖代码：D3D11-CreateQuery
 */
VOID InlineHook_X64_HandleCoverdCode_D3D11CreateQuery(DWORD64 originFunc, int byteLen)
{
	//原始 GetThreadContext 19(0x13)字节的完整代码 (必须大于16字节)
	//00007FFAAE576B50 48 83 EC 58          sub         rsp, 58h
	//00007FFAAE576B54 48 8B 05 15 89 2C 00 mov         rax, qword ptr[7FFAAE83F470h]-----相对寻址=下条指令地址+操作数
	//00007FFAAE576B5B 48 33 C4             xor         rax, rsp
	//00007FFAAE576B5E 48 89 44 24 40       mov         qword ptr[rsp + 40h], rax
	//00007FFAAE576B63 

	//修改后共占19+14(0x21)字节	(因为被覆盖的代码中有"相对寻址"，所以粘贴位置有2GB的范围限制)
	//newAddr					sub         rsp, 58h
	//newAddr+ 0x4				mov         rax, qword ptr[7FFAAE83F470h]-----需修正opcode
	//newAddr+ 0xB				xor         rax, rsp
	//newAddr+ 0xE				mov         qword ptr[rsp + 40h], rax
	//newAddr+ 0x13				jmp			remainAddr					;跳转至被挂钩函数剩余代码的地址  (5字节)
	//newAddr+ 0x18			

	//计算Hook结束后要返回到哪个地址继续执行剩余代码
	::g_HookParam_CreateQuery.originFunc = originFunc;				//*
	::g_HookParam_CreateQuery.remainFunc = originFunc + byteLen;	//*

	//原mov指令的opcode
	DWORD opcode_old_mov = *(DWORD*)(originFunc + 0x4 + 0x3);
	//原call指令的目标地址 = opcode + 下条指令的地址
	DWORD64 destAddr_old_mov = opcode_old_mov + (originFunc + 0xB);

	//计算被挂钩函数被覆盖指令中用到的最小、最大地址 
	DWORD64 arr[2] = { 0 };
	arr[0] = destAddr_old_mov;
	arr[1] = g_HookParam_CreateQuery.remainFunc;
	DWORD64 maxAddr = 0;
	DWORD64 minAddr = 0;
	CalcMaxMinAddr_BubbleSort(arr, sizeof(arr) / sizeof(DWORD64), maxAddr, minAddr);

	//申请范围在2GB内的虚拟内存 , GetThreadContext()需要0x20字节
	::g_HookParam_CreateQuery.pCoverdCode = AllocMemWithin2GB(minAddr, maxAddr, 0x20);

	//根据指令粘贴地址，计算新操作数opcode
	DWORD opcode_new_mov = destAddr_old_mov - (g_HookParam_CreateQuery.pCoverdCode + 0xB);
	DWORD opcode_jmp = g_HookParam_CreateQuery.remainFunc - (g_HookParam_CreateQuery.pCoverdCode + 0x18);

	//构造JMP硬编码
	HardCode_JMP newJMP = { 0 };
	newJMP.JMP = 0xE9;
	newJMP.Opcode = opcode_jmp;

	//粘贴被覆盖代码
	memcpy((PVOID)::g_HookParam_CreateQuery.pCoverdCode, (PVOID)originFunc, 0x13);
	//修改被覆盖代码的部分操作数opcode
	*(DWORD*)(g_HookParam_CreateQuery.pCoverdCode + 0x4 + 0x3) = opcode_new_mov;
	//在被覆盖代码的末尾增加JMP近跳转指令
	memcpy((PVOID)(::g_HookParam_CreateQuery.pCoverdCode + 0x13), &newJMP, sizeof(newJMP));

}



/**
 * InlineHook (64位)
 * 参数 originFunc	//原始函数地址
 * 参数 byteLen		//被Hook的函数被替换的完整代码字节数，至少是16字节(14字节远跳转、2字节传参)
 * 参数 hookFunc		//钩子函数地址(此函数内修正)
 * 参数 hookFunc		//用于处理被覆盖代码的函数地址
 * byteLen：	【MessageBoxA		16字节】	【D3D11-Present		19字节】
 *			【D3D11-DrawIndexed 19字节】 【VirtualProtect	17字节】
 *			【GetThreadContext  18字节】 【D3D11-CreateQuery 19字节】
 * 注意，项目DEBUG编译时需要关闭堆栈安全检查，否则会导致 Run-Time Check Failure #2 异常
 */
VOID InlineHook_X64(DWORD64 originFunc, int byteLen, DWORD64 hookFunc, PVOID pHandleCoverdCode)
{
	printf("\n【info】开始Inline Hook ...原始函数地址=%016llX  钩子函数的地址=%016llX \n", originFunc, hookFunc);
	if (byteLen < 16) { printf("【error】参数byteLen至少为16 ... \n"); return; }

	//检查被挂钩函数的前3字节是否为JMP间接调用(0x25FF48)
	if (((*(DWORD*)originFunc) & 0x00FFFFFF) == 0x25FF48)
	{
		DWORD originFunc_opcode = *(DWORD*)(originFunc + 0x3);
		DWORD64* originFunc_realAddr_saveWhere = (DWORD64*)(originFunc_opcode + (originFunc + 0x3 + 0x4));
		originFunc = *originFunc_realAddr_saveWhere;
		printf("【info】修正原始函数地址=%016llX (越过JMP)\n", originFunc);
	}

	//模拟裸函数：修正钩子函数地址，从而不执行编译器写的堆栈平衡代码
	DWORD64 hookFunc_realAddr = 0;
	DWORD64 hookFunc_naked = 0;
#if _DEBUG
	printf("【info】检测到DEBUG编译版本，请确保项目关闭堆栈安全检查以避免Run-Time Check Failure #2 异常...\n");

	//Debug版本获取的函数地址需越过JMP指令才进入函数，并要跳过编译器提升堆栈的那部分代码
	//获取JMP指令的Opcode
	DWORD hookFunc_opCode = *(DWORD*)(hookFunc + 1);
	//获取函数真实地址：要跳转的函数真实地址=JMP指令的下条指令所在地址+Opcode=(hookFunc+5)+Opcode
	hookFunc_realAddr = hookFunc + 5 + hookFunc_opCode;
	printf("【info】修正钩子函数地址=%016llX (越过JMP)\n", hookFunc_realAddr);
	//编译器帮我们提升堆栈的代码是变化的，随我们自己的代码而变化，不能以固定的偏移作为裸函数入口。
	//由于钩子函数都调用了CALL ASM_SaveReg()，所以就此函数调用语句减0x7处作为裸函数入口(因为ASM_SaveReg有个参数)
	DWORD64 ASM_SaveReg_Opcode = *(DWORD*)((DWORD64)ASM_SaveReg + 1);
	DWORD64 ASM_SaveReg_realAddr = (DWORD64)ASM_SaveReg + 0x5 + ASM_SaveReg_Opcode;
	for (DWORD64 addr = hookFunc_realAddr; addr < hookFunc_realAddr + 100; addr++)
	{
		if (*(BYTE*)addr == 0xE8)
		{
			DWORD E8opCode = *(DWORD*)(addr + 1);
			if (E8opCode == (DWORD)((DWORD64)ASM_SaveReg - (addr + 0x5)))
			{
				hookFunc_naked = addr - 0x7;
				printf("【info】修正钩子函数地址=%016llX (越过提升堆栈等，模拟裸函数)\n", hookFunc_naked);
				break;
			}
		}
	}
#elif NDEBUG
	//release版本获取的函数地址不需要额外JMP
	//模拟裸函数，得到地址值
	hookFunc_naked = hookFunc_realAddr + 0x7;
	printf("【fail】release版本的裸函数地址修正尚未完成...");
	return;
#endif

	if (hookFunc_naked == 0x0)
	{
		printf("【error】修正钩子函数地址失败..检查该函数是否为钩子函数 \n");
		return;
	}

	//粘贴、修正被覆盖的原函数代码至2GB范围的位置
	BOOL(*HandleCoverdCode)(DWORD64, int) = (BOOL(*)(DWORD64, int))pHandleCoverdCode;
	if (!HandleCoverdCode(originFunc, byteLen)) return;

	//修改内存保护属性：可读写可执行
	DWORD oldProtect = 0; DWORD newProtect = 0;
	VirtualProtect((LPVOID)originFunc, byteLen, PAGE_EXECUTE_READWRITE, &oldProtect);

	//计算钩子函数的地址的低32位和高32位，用于远JMP (这样会破坏栈顶上方的没用数据，安全检查时导致 Run-Time Check Failure #2 异常)
	DWORD hookFunc_Low32 = (DWORD)hookFunc_naked;
	DWORD hookFunc_High32 = hookFunc_naked >> 32;
	//定义硬编码
	BYTE PUSH_RCX[1] = { 0x51 };
	BYTE POP_RCX[1] = { 0x59 };
	BYTE PUSH[1] = { 0x68 };
	BYTE MOV_DWORD_PTR_SS[4] = { 0xC7,0x44,0x24,0x04 };
	BYTE RET[1] = { 0xC3 };
	//初始化原始函数的前byteLen字节代码为 NOP 
	memset((PBYTE)originFunc, 0x90, byteLen);
	//修改原始函数的第1~5字节为：PUSH 低32位地址
	memcpy((PVOID)(originFunc), PUSH, sizeof(PUSH));
	memcpy((PVOID)(originFunc + 1), &hookFunc_Low32, 4);
	//修改原始函数的第6~13字节为：MOV dword ptr ss:[rsp+0x4],高32位地址
	memcpy((PVOID)(originFunc + 5), MOV_DWORD_PTR_SS, sizeof(MOV_DWORD_PTR_SS));
	memcpy((PVOID)(originFunc + 9), &hookFunc_High32, 4);
	//修改原始函数的第14字节为：PUSH rcx (将rcx的值存放于栈顶-8处，因为钩子函数中需要用rcx来存放参数，如果解决ASM文件全局变量的问题，就可以不这么麻烦了)
	memcpy((PVOID)(originFunc + 13), PUSH_RCX, sizeof(PUSH_RCX));
	//修改原始函数的第15字节为：POP  rcx
	memcpy((PVOID)(originFunc + 14), POP_RCX, sizeof(POP_RCX));
	//修改原始函数的第 16 字节为：RET
	memcpy((PVOID)(originFunc + 15), RET, sizeof(RET));
	//恢复内存保护属性
	VirtualProtect((LPVOID)originFunc, byteLen, oldProtect, &newProtect);

	//测试：MessageBoxA
	//MessageBox(0, "TestContent", "TestCaption", 0);
}