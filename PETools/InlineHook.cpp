#include "pch.h"


REGISTER_X86 reg_x86 = { 0 };				//32λ�Ĵ���
PBYTE pSrcCodeBuffer = 0;					//���汻HOOK�Ĵ����

//���壺���Ӻ����������
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
VOID  InlineHook_X86_MyMessageBoxA()	//�㺯�����Լ������ջƽ��
{
#if _IS_X86
	_asm
	{
		//�Ĵ�����ջ����
		pushfd  //��32λ��־�Ĵ���EFLAGSѹջ
		pushad	//�����е�32λͨ�üĴ���ѹջ
	}

	//>>>>>>>> begin :ִ���Լ��Ĵ���>>>>>>>>
	//��ӡ�Ĵ���
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
	printf("8��ͨ�üĴ�����eax=%08X,ebx=%08X,ecx=%08X,edx=%08X,esp=%08X,ebp=%08X,esi=%08X,edi=%08X \n", reg_x86.eax, reg_x86.ebx, reg_x86.ecx, reg_x86.edx, reg_x86.esp, reg_x86.ebp, reg_x86.esi, reg_x86.edi);
	//��ӡ����
	_asm
	{
		//MessageBox��������4��������ջ���һ���8��ͨ�üĴ�����1��EL�Ĵ�����ջ
		//��ջ��esp+(8+1)*0x4+0x10 �ǵ�1����ջ�Ĳ���
		mov eax, DWORD PTR SS : [esp + 0x34]
		mov param1_MyMessageBoxA_X86, eax
		//��ջ��esp+(8+1)*0x4+0xC �ǵ�2����ջ�Ĳ���
		mov eax, DWORD PTR SS : [esp + 0x30]
		mov param2_MyMessageBoxA_X86, eax
		//��ջ��esp+(8+1)*0x4+0x8 �ǵ�3����ջ�Ĳ���
		mov eax, DWORD PTR SS : [esp + 0x2C]
		mov param3_MyMessageBoxA_X86, eax
		//��ջ��esp+(8+1)*0x4+0x4 �ǵ�4����ջ�Ĳ���
		mov eax, DWORD PTR SS : [esp + 0x28]
		mov param4_MyMessageBoxA_X86, eax
	}
	printf("MessageBoxA�Ĳ���: ����1=%d , ����2=%s�� ����3=%s, ����4=%d \n", param1_MyMessageBoxA_X86, param2_MyMessageBoxA_X86, param3_MyMessageBoxA_X86, param4_MyMessageBoxA_X86);
	//>>>>>>>> end :ִ���Լ��Ĵ���>>>>>>>>

	_asm
	{
		//�Ĵ�����ջ�ָ��ֳ�
		popad
		popfd

		//ִ�б����ǵ�ԭ����
		//	MessageBoxA(X86)��ǰ5�ֽ�:
		//  75F57E60 8B FF                mov         edi, edi
		//	75F57E62 55                   push        ebp
		//	75F57E63 8B EC                mov         ebp, esp
		mov         edi, edi
		push        ebp
		mov         ebp, esp

		//��ת��ԭ����
		jmp backAddr
	}

#endif
}


/**
 * InlineHook (32λ)
 * ���� destDllName
 * ���� destFuncName
 * ���� hookFuncAddr
 * ���� byteLen	ָ����ԭ����ǰ(byteLen)�ֽڵĴ����滻��jmpָ�����Ϊ5�ֽ�(��Hook������ǰbyteLen�ֽڱ����������Ĵ����)
 */
VOID InlineHook_X86(const CHAR* destDllName, const CHAR* destFuncName, DWORD64 hookFuncAddr, int byteLen)
{
	//MessageBox(0, TEXT("testText"), TEXT("testCaption"), 0);
	//printf("\n��ʼInline Hook ... \n");
	////��ȡĿ�꺯������ڵ�ַ
	//HMODULE destDll = GetModuleHandle(destDllName);
	//if (destDll == 0)
	//{
	//	printf("���󣺲�����Ŀ��ģ��%s \n", destDllName);
	//	return;
	//}
	//originFunc = (DWORD64)GetProcAddress(destDll, destFuncName);
	//if (originFunc == 0)
	//{
	//	printf("����Ŀ��ģ���в�����Ŀ�꺯��%s \n", destFuncName);
	//	return;
	//}

	////����ԭʼ����ʣ������λ��
	//remainAddr = originFunc + byteLen;

	////����ǰ(byteLen)�ֽڵĴ���
	//pSrcCodeBuffer = (PBYTE)malloc(byteLen);
	//memset(pSrcCodeBuffer, 0x0, byteLen);
	//memcpy(pSrcCodeBuffer, (void*)originFunc, byteLen);

	////�޸�ǰ(byteLen)�ֽڵĴ���Ϊ JMP XXX 
	//DWORD oldProtect = 0; DWORD newProtect = 0;
	//VirtualProtect((LPVOID)originFunc, byteLen, PAGE_EXECUTE_READWRITE, &oldProtect);
	//*(PBYTE)(originFunc) = 0xE9; //jmp
	//*(DWORD*)(originFunc + 1) = hookFuncAddr - originFunc - 5; //jmp X  
	//VirtualProtect((LPVOID)originFunc, byteLen, oldProtect, &newProtect);

	////���Ե���
	//MessageBox(0, TEXT("testText"), TEXT("testCaption"), 0);
}


/**
 * MessageBoxA�Ĺ��Ӻ��� (64λ)
 * 1.��Ϊx64����д�㺯�������Թ��Ӻ����ĵ��õ�ַ��Ҫ������������
 * 2.�ڱ������в���ʹ�þֲ���������Ϊ�ֲ������ĸ�ֵ��ʹ�üĴ�����
 *   �����ñ�����ʱΪ��ģ���㺯���������˱������ں���ͷ���Ķ�ջ������ʹ�üĴ�����ֵ�����㺯������ǰ��ֵ
 *   ����ֲ�������ֵ����� MOV [rbp+4h],666h ��һ���Ĵ������㺯������ǰ��ֵ����0���ͻᷢ�����ʳ�ͻ�쳣��
 * 3.�ڱ������У�����ȷ��rbp��16�ֽڶ���(0x10������)�����Ҫ��rspҲ��16�ֽڶ��룬���ֶ�������ջʱ��ע�⡣
 */
VOID InlineHook_X64_MyMessageBoxA()
{
	//�������мĴ�����ȫ�ֱ���
	ASM_SaveReg(&::g_HookParam_MessageBoxA);
	//printf("ԭ�Ĵ�����ֵ��\n[rax]=%016llX [rbx]=%016llX [rcx]=%016llX [rdx]=%016llX \n[rsi]=%016llX [rdi]=%016llX [rsp]=%016llX [rbp]=%016llX \n[r8 ]=%016llX [r9 ]=%016llX [r10]=%016llX [r11]=%016llX \n[r12]=%016llX [r13]=%016llX [r14]=%016llX [r15]=%016llX \n[efl]=%016llX \n", reg_x64.rax, reg_x64.rbx, reg_x64.rcx, reg_x64.rdx, reg_x64.rsi, reg_x64.rdi, reg_x64.rsp, reg_x64.rbp, reg_x64.r8, reg_x64.r9, reg_x64.r10, reg_x64.r11, reg_x64.r12, reg_x64.r13, reg_x64.r14, reg_x64.r15, reg_x64.efl);

	//Malware
	printf("��ӡMessageBoxA()����������=%s , �ı�=%s \n", ::g_HookParam_MessageBoxA.reg_x64.r8, ::g_HookParam_MessageBoxA.reg_x64.rdx);

	//�ָ��Ĵ�������ת�������ǵĴ���
	ASM_RecoverReg(&::g_HookParam_MessageBoxA, ::g_HookParam_MessageBoxA.pCoverdCode);
}

/**
 * GetThreadContext�Ĺ��Ӻ��� (64λ)
 * 1.��Ϊx64����д�㺯�������Թ��Ӻ����ĵ��õ�ַ��Ҫ������������
 * 2.�ڱ������в���ʹ�þֲ���������Ϊ�ֲ������ĸ�ֵ��ʹ�üĴ�����
 *   �����ñ�����ʱΪ��ģ���㺯���������˱������ں���ͷ���Ķ�ջ������ʹ�üĴ�����ֵ�����㺯������ǰ��ֵ
 *   ����ֲ�������ֵ����� MOV [rbp+4h],666h ��һ���Ĵ������㺯������ǰ��ֵ����0���ͻᷢ�����ʳ�ͻ�쳣��
 * 3.�ڱ������У�����ȷ��rbp��16�ֽڶ���(0x10������)�����Ҫ��rspҲ��16�ֽڶ��룬���ֶ�������ջʱ��ע�⡣
 */
VOID InlineHook_X64_MyGetThreadContext()
{
	//�������мĴ�����ȫ�ֱ���
	ASM_SaveReg(&::g_HookParam_GetThreadContext);

	//Malware
	//����ԭ�ͣ�WINBASEAPI BOOL WINAPI GetThreadContext(_In_ HANDLE hThread, _Inout_ LPCONTEXT lpContext);
	//00007FF75C414299 33 D2                xor         edx, edx	;����2 rdx lpContext
	//00007FF75C41429B 33 C9                xor         ecx, ecx	;����1 rcx hThread
	//00007FF75C41429D FF 15 15 8E 04 00    call        qword ptr[__imp_GetThreadContext(07FF75C45D0B8h)]
	HANDLE hThread = (HANDLE)g_HookParam_GetThreadContext.reg_x64.rcx;
	LPCONTEXT lpContext = (LPCONTEXT)g_HookParam_GetThreadContext.reg_x64.rdx;
	printf("��ӡGetThreadContext()������hThread=%016llX , lpContext=%016llX \n", hThread, lpContext);

	//�ָ��Ĵ�������ת�������ǵĴ���
	ASM_RecoverReg(&::g_HookParam_GetThreadContext, ::g_HookParam_GetThreadContext.pCoverdCode);
}


/**
 * D3D11 Present�Ĺ��Ӻ��� (64λ)
 * 1.��Ϊx64����д�㺯�������Թ��Ӻ����ĵ��õ�ַ��Ҫ������������
 * 2.�ڱ������в���ʹ�þֲ���������Ϊ�ֲ������ĸ�ֵ��ʹ�üĴ�����
 *   �����ñ�����ʱΪ��ģ���㺯���������˱������ں���ͷ���Ķ�ջ������ʹ�üĴ�����ֵ�����㺯������ǰ��ֵ
 *   ����ֲ�������ֵ����� MOV [rbp+4h],666h ��һ���Ĵ������㺯������ǰ��ֵ����0���ͻᷢ�����ʳ�ͻ�쳣��
 * 3.�ڱ������У�����ȷ��rbp��16�ֽڶ���(0x10������)�����Ҫ��rspҲ��16�ֽڶ��룬���ֶ�������ջʱ��ע�⡣
 */
VOID InlineHook_X64_MyPresent()
{
	//�������мĴ�����ȫ�ֱ���
	ASM_SaveReg(&::g_HookParam_Present);
	//printf("ԭ�Ĵ�����ֵ��\n[rax]=%016llX [rbx]=%016llX [rcx]=%016llX [rdx]=%016llX \n[rsi]=%016llX [rdi]=%016llX [rsp]=%016llX [rbp]=%016llX \n[r8 ]=%016llX [r9 ]=%016llX [r10]=%016llX [r11]=%016llX \n[r12]=%016llX [r13]=%016llX [r14]=%016llX [r15]=%016llX \n[efl]=%016llX \n", reg_x64.rax, reg_x64.rbx, reg_x64.rcx, reg_x64.rdx, reg_x64.rsi, reg_x64.rdi, reg_x64.rsp, reg_x64.rbp, reg_x64.r8, reg_x64.r9, reg_x64.r10, reg_x64.r11, reg_x64.r12, reg_x64.r13, reg_x64.r14, reg_x64.r15, reg_x64.efl);

	//Malware
	ChreatD3D11_MyPresent(&g_HookParam_Present.reg_x64);

	//�ָ��Ĵ�������ת�ر����ǵĴ���
	ASM_RecoverReg(&g_HookParam_Present, g_HookParam_Present.pCoverdCode);
}
/**
 * D3D11 DrawIndexed�Ĺ��Ӻ��� (64λ)
 * 1.��Ϊx64����д�㺯�������Թ��Ӻ����ĵ��õ�ַ��Ҫ������������
 * 2.�ڱ������в���ʹ�þֲ���������Ϊ�ֲ������ĸ�ֵ��ʹ�üĴ�����
 *   �����ñ�����ʱΪ��ģ���㺯���������˱������ں���ͷ���Ķ�ջ������ʹ�üĴ�����ֵ�����㺯������ǰ��ֵ
 *   ����ֲ�������ֵ����� MOV [rbp+4h],666h ��һ���Ĵ������㺯������ǰ��ֵ����0���ͻᷢ������0x0000000000000004��ͻ�쳣��
 * 3.�ڱ������У�����ȷ��rbp��16�ֽڶ���(0x10������)�����Ҫ��rspҲ��16�ֽڶ��룬���ֶ�������ջʱ��ע�⡣
 */
VOID InlineHook_X64_MyDrawIndexed()
{
	//�������мĴ�����ȫ�ֱ���
	ASM_SaveReg(&g_HookParam_DrawIndexed);
	//printf("ԭ�Ĵ�����ֵ��\n[rax]=%016llX [rbx]=%016llX [rcx]=%016llX [rdx]=%016llX \n[rsi]=%016llX [rdi]=%016llX [rsp]=%016llX [rbp]=%016llX \n[r8 ]=%016llX [r9 ]=%016llX [r10]=%016llX [r11]=%016llX \n[r12]=%016llX [r13]=%016llX [r14]=%016llX [r15]=%016llX \n[efl]=%016llX \n", reg_x64.rax, reg_x64.rbx, reg_x64.rcx, reg_x64.rdx, reg_x64.rsi, reg_x64.rdi, reg_x64.rsp, reg_x64.rbp, reg_x64.r8, reg_x64.r9, reg_x64.r10, reg_x64.r11, reg_x64.r12, reg_x64.r13, reg_x64.r14, reg_x64.r15, reg_x64.efl);

	//Malware
	if (FALSE == ChreatD3D11_MyDrawIndexed(&g_HookParam_DrawIndexed.reg_x64, ::g_HookParam_DrawIndexed.pCoverdCode))
	{	//ֱ�ӽ���ԭʼ����
		ASM_EndOrigin(&g_HookParam_DrawIndexed);
	}

	//�ָ��Ĵ�������ת�ر����ǵĴ���
	ASM_RecoverReg(&::g_HookParam_DrawIndexed, ::g_HookParam_DrawIndexed.pCoverdCode);
}
/**
 * D3D11-CreateQuery�Ĺ��Ӻ��� (64λ)
 * 1.��Ϊx64����д�㺯�������Թ��Ӻ����ĵ��õ�ַ��Ҫ������������
 * 2.�ڱ������в���ʹ�þֲ���������Ϊ�ֲ������ĸ�ֵ��ʹ�üĴ�����
 *   �����ñ�����ʱΪ��ģ���㺯���������˱������ں���ͷ���Ķ�ջ������ʹ�üĴ�����ֵ�����㺯������ǰ��ֵ
 *   ����ֲ�������ֵ����� MOV [rbp+4h],666h ��һ���Ĵ������㺯������ǰ��ֵ����0���ͻᷢ������0x0000000000000004��ͻ�쳣��
 * 3.�ڱ������У�����ȷ��rbp��16�ֽڶ���(0x10������)�����Ҫ��rspҲ��16�ֽڶ��룬���ֶ�������ջʱ��ע�⡣
 */
VOID InlineHook_X64_MyCreateQuery()
{
	//�������мĴ�����ȫ�ֱ���
	ASM_SaveReg(&g_HookParam_CreateQuery);
	
	//Malware
	if (FALSE == ChreatD3D11_MyCreateQuery(&g_HookParam_CreateQuery.reg_x64, ::g_HookParam_CreateQuery.pCoverdCode))
	{	//ֱ�ӽ���ԭʼ����
		ASM_EndOrigin(&g_HookParam_CreateQuery);
	}

	//�ָ��Ĵ�������ת�ر����ǵĴ���
	ASM_RecoverReg(&::g_HookParam_CreateQuery, ::g_HookParam_CreateQuery.pCoverdCode);
}

/**
 * VirtualProtect�Ĺ��Ӻ��� (64λ)
 * 1.��Ϊx64����д�㺯�������Թ��Ӻ����ĵ��õ�ַ��Ҫ������������
 * 2.�ڱ������в���ʹ�þֲ���������Ϊ�ֲ������ĸ�ֵ��ʹ�üĴ�����
 *   �����ñ�����ʱΪ��ģ���㺯���������˱������ں���ͷ���Ķ�ջ������ʹ�üĴ�����ֵ�����㺯������ǰ��ֵ
 *   ����ֲ�������ֵ����� MOV [rbp+4h],666h ��һ���Ĵ������㺯������ǰ��ֵ����0���ͻᷢ������0x0000000000000004��ͻ�쳣��
 * 3.�ڱ������У�����ȷ��rbp��16�ֽڶ���(0x10������)�����Ҫ��rspҲ��16�ֽڶ��룬���ֶ�������ջʱ��ע�⡣
 */
VOID InlineHook_X64_MyVirtualProtect()
{
	//�������мĴ�����ȫ�ֱ���
	ASM_SaveReg(&g_HookParam_VirtualProtect);

	//Malware
	printf("��info������MyVirtualProtect...\n");

	//�ָ��Ĵ�������ת�ر����ǵĴ���
	ASM_RecoverReg(&::g_HookParam_VirtualProtect, ::g_HookParam_VirtualProtect.pCoverdCode);

}

/**
 * ������ָ��Ĳ��С��2GB�ĵ�ַ�ռ� (64λ)
 * ���� minInstructionAddr	//�����ǵ�ָ����õ�����ǰ����С���ĵ�ַ
 * ���� maxInstructionAddr	//�����ǵ�ָ����õ��������󣩵ĵ�ַ
 */
DWORD64 AllocMemWithin2GB(DWORD64 minInstructionAddr, DWORD64 maxInstructionAddr, int needLen)
{
	printf("��info����ʼ����2GB��Χ�ڵĿռ䣬���ҹ����������Ǵ������õ�����С��ַ=%016llX  ����ַ=%016llX \n", minInstructionAddr, maxInstructionAddr);
	//������ǰ������ָ�����2GB��Χ�ڵĵ�ַ
	DWORD64 pFront = maxInstructionAddr - 0x7FFFFFFF; //��2GB����Ѱַ����ǰ��ַ
	DWORD64 pBack = minInstructionAddr + 0x7FFFFFFF; //��2GB����Ѱַ������ַ
	pFront += (0x10000 - (pFront % 0x10000));      //��ǰ��ַ����Ϊ�¸�64kb����ĵ�ַ
	DWORD64 pCoverdCode = 0;
	while (true)
	{
		//����ĵ�ֵַ��������64kb����(��0x10000�������ĵ�ֵַ)
		//��������������64kb���������Զ�ȡ�������紫��0x36666ʱ���Զ�����Ϊ����0x30000���ڴ�����
		pCoverdCode = (DWORD64)VirtualAllocEx(GetCurrentProcess(), (LPVOID)pFront, needLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		//������һ��64kb����ĵ�ַ
		pFront += 0x10000;
		if (pCoverdCode != 0)
		{
			printf("��info������ɹ��������Ǵ����ճ����ַ=%016llX \n", pCoverdCode);
			return pCoverdCode;
		}

		if (pFront + 14 >= pBack)
		{
			printf("��info������ʧ�ܣ�ǰ��2GB��Χ���Ҳ������õ�ַ \n");
			return 0;
		}
	};
}

/**
 * ר�Ŵ���64λ��HOOK�����ı����Ǵ��룺MessageBoxA
 */
VOID InlineHook_X64_HandleCoverdCode_MessageBoxA(DWORD64 originFunc, int byteLen)
{

	//ԭʼ MessageBoxA 16�ֽ�
	//00007FFDE5E5E7A0 48 83 EC 38          sub         rsp, 38h
	//00007FFDE5E5E7A4 45 33 DB             xor         r11d, r11d
	//00007FFDE5E5E7A7 44 39 1D 0A 59 03 00 cmp         dword ptr[7FFDE5E940B8h], r11d------���Ѱַ(����ָ��+������)
	//00007FFDE5E5E7AE 74 2E                je          00007FFDE5E5E7DE-----------���Ѱַ(����ָ��+������)

	//�޸ĺ�ռ15�ֽ�
	//newAddr			sub         rsp, 38h
	//newAddr+0x4		xor         r11d, r11d
	//newAddr+0x7		cmp         dword ptr[ԭĿ���ַ], r11d
	//newAddr+0xE		je			newAddr+0x15	;����������ָ��
	//newAddr+0x10		jmp			backAddr		;����ԭ����
	//newAddr+0x15		jmp			oldJEDestAddr	;����ԭJEҪ���ĵط�
	//newAddr+0x1A

	//����Hook������Ҫ���ص��ĸ���ַ����ִ��ʣ�����
	::g_HookParam_MessageBoxA.originFunc = originFunc;
	::g_HookParam_MessageBoxA.remainFunc = originFunc + byteLen;

	//ԭʼCMP��Opcode	(4�ֽ�)****
	DWORD oldCmp_Opcode = *(DWORD*)(originFunc + 0xA);

	//ԭʼCMP��Ŀ���ַ = ƫ��+ CMP�¸�ָ���ַ
	DWORD64 oldCmp_DestAddr = oldCmp_Opcode + (originFunc + 0xE);

	//�õ������ǵ�ָ����õ�����ǰ��ַ
	DWORD64 frontAddr = (originFunc + 0x10) + *(BYTE*)(originFunc + 0xF);
	//�õ������ǵ�ָ����õ�������ַ
	DWORD64 backAddr = oldCmp_DestAddr;

	//���뷶Χ��2GB�ڵ������ڴ� ,MessageBoxA��Ҫ0x15�ֽ�
	::g_HookParam_MessageBoxA.pCoverdCode = AllocMemWithin2GB(frontAddr, backAddr, 0x15);//*

	//ԭʼCMPָ��ǰ3�ֽڵ�Ӳ���� (3�ֽ�)****
	DWORD64 oldCmp = 0x1D3944;

	//��CMP�����Ѱַƫ��= Ŀ���ַ - CMP�¸�ָ���ַ
	DWORD64 newCmpDestOff = oldCmp_DestAddr - (::g_HookParam_MessageBoxA.pCoverdCode + 0xE);//*

	//ԭʼJE
	HardCode_JCC oldJCC;
	oldJCC.JC = 0x74;
	oldJCC.Opcode = *(DWORD*)(originFunc + 0xF);

	// ԭʼJEҪ��ת��Ŀ���ַ
	DWORD64 oldJeDest = originFunc + 0x10 + oldJCC.Opcode;

	//��JE****
	HardCode_JCC newJCC;
	newJCC.JC = 0x74;
	newJCC.Opcode = 0x5; //JC��Opcode= Ŀ���ַ - JC����ָ���ַ

	//��JMP_1������ԭ����********
	HardCode_JMP newJMP1;
	newJMP1.JMP = 0xE9;
	newJMP1.Opcode = ::g_HookParam_MessageBoxA.remainFunc - (::g_HookParam_MessageBoxA.pCoverdCode + 0x15);

	//��JMP_2������ԭJEҪ����λ��********
	HardCode_JMP newJMP2;
	newJMP2.JMP = 0xE9;
	newJMP2.Opcode = oldJeDest - (::g_HookParam_MessageBoxA.pCoverdCode + 0x1A);

	//д���޸ĺ��ԭ��������
	memcpy((PVOID)::g_HookParam_MessageBoxA.pCoverdCode, (PVOID)originFunc, 0x7); //*
	memcpy((PVOID)(::g_HookParam_MessageBoxA.pCoverdCode + 0x7), &oldCmp, 0x3);//*
	memcpy((PVOID)(::g_HookParam_MessageBoxA.pCoverdCode + 0x7 + 0x3), &newCmpDestOff, 0x4);//*
	memcpy((PVOID)(::g_HookParam_MessageBoxA.pCoverdCode + 0x7 + 0x3 + 0x4), &newJCC, sizeof(newJCC));//*
	memcpy((PVOID)(::g_HookParam_MessageBoxA.pCoverdCode + 0x7 + 0x3 + 0x4 + 0x2), &newJMP1, sizeof(newJMP1));//*
	memcpy((PVOID)(::g_HookParam_MessageBoxA.pCoverdCode + 0x7 + 0x3 + 0x4 + 0x2 + 0x5), &newJMP2, sizeof(newJMP2));//*

}
/**
 * ר�Ŵ���64λ��HOOK�����ı����Ǵ��룺D3D11��Present
 */
VOID InlineHook_X64_HandleCoverdCode_D3D11Present(DWORD64 originFunc, int byteLen)
{
	//ԭʼ Present 19�ֽڵ��������� (�������16�ֽ�)
	//00007FFC8F245070 48 89 5C 24 10       mov         qword ptr[rsp + 10h], rbx
	//00007FFC8F245075 48 89 74 24 20       mov         qword ptr[rsp + 20h], rsi
	//00007FFC8F24507A 55                   push        rbp
	//00007FFC8F24507B 57                   push        rdi
	//00007FFC8F24507C 41 56                push        r14
	//00007FFC8F24507E 48 8D 6C 24 90       lea         rbp, [rsp - 70h]

	//�޸ĺ�ռ19+14�ֽ�	(��Ϊ�����ǵĴ�������"���Ѱַ"������ճ��λ��û��2GB�ķ�Χ����)
	//newAddr				mov         qword ptr[rsp + 10h], rbx
	//newAddr+5h			mov         qword ptr[rsp + 20h], rsi
	//newAddr+Ah            push        rbp
	//newAddr+Bh			push        rdi
	//newAddr+Ch			push        r14
	//newAddr+Eh			lea         rbp, [rsp - 70h]
	//newAddr+13h			PUSH		Low32RetAddr
	//newAddr+18h			MOV			High32RetAddr
	//newAddr+20h			RET		

	//����Hook������Ҫ���ص��ĸ���ַ����ִ��ʣ�����
	::g_HookParam_Present.originFunc = originFunc;
	::g_HookParam_Present.remainFunc = originFunc + byteLen;

	//����"Զ��"ָ��
	HardCode_FarJMP FarJmp;
	FarJmp.PUSH = 0x68;
	FarJmp.Addr_Low32 = (DWORD)::g_HookParam_Present.remainFunc; //*
	FarJmp.MOV_DWORD_PTR_SS = 0x042444C7;
	FarJmp.Addr_High32 = ::g_HookParam_Present.remainFunc >> 32;//*
	FarJmp.RET = 0xC3;

	//����ռ䣬ճ�������ǵĴ���
	::g_HookParam_Present.pCoverdCode = (DWORD64)VirtualAllocEx(GetCurrentProcess(), NULL, 19 + 14, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);//*
	printf("��info�������Ǵ���ճ��λ��=%016llX \n", ::g_HookParam_Present.pCoverdCode);//*
	memcpy((PVOID)::g_HookParam_Present.pCoverdCode, (PVOID)originFunc, 19);//*

	//��ĩβճ��"Զ��"ָ��
	memcpy((PVOID)(::g_HookParam_Present.pCoverdCode + 19), &FarJmp, sizeof(FarJmp));//*

}

/**
 * ר�Ŵ���64λ��HOOK�����ı����Ǵ��룺D3D11��DrawIndexed
 */
VOID InlineHook_X64_HandleCoverdCode_D3D11DrawIndexed(DWORD64 originFunc, int byteLen)
{
	//ԭʼ DrawIndexed 19�ֽڵ��������� (�������16�ֽ�)
	//00007FFC8CA37D80 48 83 EC 38          sub         rsp, 38h
	//00007FFC8CA37D84 44 8B DA             mov         r11d, edx
	//00007FFC8CA37D87 48 81 C1 28 FF FF FF add         rcx, 0FFFFFFFFFFFFFF28h
	//00007FFC8CA37D8E BA 00 A0 00 00       mov         edx, 0A000h

	//�޸ĺ�ռ19+14�ֽ�	(��Ϊ�����ǵĴ�������"���Ѱַ"������ճ��λ��û��2GB�ķ�Χ����)
	//newAddr       sub         rsp, 38h
	//newAddr+4h    mov         r11d, edx
	//newAddr+7h	add         rcx, 0FFFFFFFFFFFFFF28h
	//newAddr+Eh	mov         edx, 0A000h
	//newAddr+13h	PUSH		Low32RetAddr	5 byte
	//newAddr+18h	MOV			High32RetAddr	8 byte
	//newAddr+20h	RET							1 byte


	//����Hook������Ҫ���ص��ĸ���ַ����ִ��ʣ�����
	::g_HookParam_DrawIndexed.originFunc = originFunc;				//*
	::g_HookParam_DrawIndexed.remainFunc = originFunc + byteLen;	//*

	//����"Զ��"ָ��
	HardCode_FarJMP FarJmp;
	FarJmp.PUSH = 0x68;
	FarJmp.Addr_Low32 = (DWORD)g_HookParam_DrawIndexed.remainFunc; //*
	FarJmp.MOV_DWORD_PTR_SS = 0x042444C7;
	FarJmp.Addr_High32 = g_HookParam_DrawIndexed.remainFunc >> 32; //*
	FarJmp.RET = 0xC3;

	//����ռ䣬ճ�������ǵĴ���
	g_HookParam_DrawIndexed.pCoverdCode = (DWORD64)VirtualAllocEx(GetCurrentProcess(), NULL, 19 + 14, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);//*
	memcpy((PVOID)g_HookParam_DrawIndexed.pCoverdCode, (PVOID)originFunc, 19); //*

	//��ĩβճ��"Զ��"ָ��
	memcpy((PVOID)(g_HookParam_DrawIndexed.pCoverdCode + 19), &FarJmp, sizeof(FarJmp)); //*

}

/**
 * ר�Ŵ���64λ��HOOK�����ı����Ǵ��룺VirtualProtect
 */
VOID InlineHook_X64_HandleCoverdCode_VirtualProtect(DWORD64 originFunc, int byteLen)
{
	//ԭʼ VirtualProtect 17(0x11)�ֽڵ��������� (�������16�ֽ�)
	//00007FFCEC48C9C0 48 8B C4             mov         rax, rsp
	//00007FFCEC48C9C3 48 89 58 18          mov         qword ptr[rax + 18h], rbx
	//00007FFCEC48C9C7 55                   push        rbp
	//00007FFCEC48C9C8 56                   push        rsi
	//00007FFCEC48C9C9 57                   push        rdi
	//00007FFCEC48C9CA 48 83 EC 30          sub         rsp, 30h
	//00007FFCEC48C9CE 49 8B F1             mov         rsi, r9

	//�޸ĺ�ռ17+14(0x1F)�ֽ�	(��Ϊ�����ǵĴ�������"���Ѱַ"������ճ��λ��û��2GB�ķ�Χ����)
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

	//����Hook������Ҫ���ص��ĸ���ַ����ִ��ʣ�����
	::g_HookParam_VirtualProtect.originFunc = originFunc;				//*
	::g_HookParam_VirtualProtect.remainFunc = originFunc + byteLen;		//*

	//����"Զ��"ָ��
	HardCode_FarJMP FarJmp;
	FarJmp.PUSH = 0x68;
	FarJmp.Addr_Low32 = (DWORD)g_HookParam_VirtualProtect.remainFunc; //*
	FarJmp.MOV_DWORD_PTR_SS = 0x042444C7;
	FarJmp.Addr_High32 = g_HookParam_VirtualProtect.remainFunc >> 32; //*
	FarJmp.RET = 0xC3;

	//����ռ䣬ճ�������ǵĴ���
	g_HookParam_VirtualProtect.pCoverdCode = (DWORD64)VirtualAllocEx(GetCurrentProcess(), NULL, 17 + 14, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);//*
	printf("��info��ԭʼ���������Ǵ����ճ��λ��=%016llX \n", g_HookParam_VirtualProtect.pCoverdCode);	//*
	memcpy((PVOID)g_HookParam_VirtualProtect.pCoverdCode, (PVOID)originFunc, 17);				//*

	//��ĩβճ��"Զ��"ָ��
	memcpy((PVOID)(g_HookParam_VirtualProtect.pCoverdCode + 17), &FarJmp, sizeof(FarJmp));		//*
}
/**
 * ð�����������С��ֵַ������ֵַ
 * ���� arr
 * ���� len  ע��: len=sizeof(arr) / sizeof(DWORD64)
 * ���� max
 * ���� min
 */
VOID CalcMaxMinAddr_BubbleSort(DWORD64 arr[], int len, OUT DWORD64& max, OUT DWORD64& min)
{
	if (len < 2) { printf("��error�������С����...\n"); return; }
	//ð������
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
 * ר�Ŵ���64λ��HOOK�����ı����Ǵ��룺GetThreadContext
 */
VOID InlineHook_X64_HandleCoverdCode_GetThreadContext(DWORD64 originFunc, int byteLen)
{
	//ԭʼ GetThreadContext 18(0x12)�ֽڵ��������� (�������16�ֽ�)
	//00007FFAB2BDEDB0 48 83 EC 28          sub         rsp, 28h
	//00007FFAB2BDEDB4 FF 15 4E 43 11 00    call        qword ptr[7FFAB2CF3108h]-----���Ѱַ=����ָ���ַ+������
	//00007FFAB2BDEDBA 85 C0                test        eax, eax
	//00007FFAB2BDEDBC 0F 88 68 FB 02 00    js          00007FFAB2C0E92A-------------���Ѱַ=����ָ���ַ+������

	//�޸ĺ�ռ18+14(0x20)�ֽ�	(��Ϊ�����ǵĴ�������"���Ѱַ"������ճ��λ����2GB�ķ�Χ����)
	//newAddr					sub         rsp, 28h
	//newAddr+ 0x4				call        qword ptr[7FFAB2CF3108h]	;������opcode
	//newAddr+ 0xA              test        eax, eax
	//newAddr+ 0xC				js          00007FFAB2C0E92A			;������opcode
	//newAddr+ 0x12				jmp			remainAddr					;��ת�����ҹ�����ʣ�����ĵ�ַ  (5�ֽ�)
	//newAddr+ 0x17				

	//����Hook������Ҫ���ص��ĸ���ַ����ִ��ʣ�����
	::g_HookParam_GetThreadContext.originFunc = originFunc;				//*
	::g_HookParam_GetThreadContext.remainFunc = originFunc + byteLen;	//*

	//ԭcallָ���opcode
	DWORD opcode_old_call = *(DWORD*)(originFunc + 0x4 + 0x2);
	//ԭcallָ���Ŀ���ַ = opcode + ����ָ��ĵ�ַ
	DWORD64 destAddr_old_call = opcode_old_call + (originFunc + 0xA);
	//ԭjsָ���opcode
	DWORD opcode_old_js = *(DWORD*)(originFunc + 0xC + 0x2);
	//ԭjsָ���Ŀ���ַ = opcode + ����ָ��ĵ�ַ
	DWORD64 destAddr_old_js = opcode_old_js + (originFunc + 0x12);

	//���㱻�ҹ�����������ָ�����õ�����С������ַ 
	DWORD64 arr[3] = { 0 };
	arr[0] = destAddr_old_call;
	arr[1] = destAddr_old_js;
	arr[2] = g_HookParam_GetThreadContext.remainFunc;
	DWORD64 maxAddr = 0;
	DWORD64 minAddr = 0;
	CalcMaxMinAddr_BubbleSort(arr, sizeof(arr) / sizeof(DWORD64), maxAddr, minAddr);

	//���뷶Χ��2GB�ڵ������ڴ� , GetThreadContext()��Ҫ0x20�ֽ�
	::g_HookParam_GetThreadContext.pCoverdCode = AllocMemWithin2GB(minAddr, maxAddr, 0x20);

	//����ָ��ճ����ַ�������²�����opcode
	DWORD opcode_new_call = destAddr_old_call - (g_HookParam_GetThreadContext.pCoverdCode + 0xA);
	DWORD opcode_new_js = destAddr_old_js - (g_HookParam_GetThreadContext.pCoverdCode + 0x12);
	DWORD opcode_jmp = g_HookParam_GetThreadContext.remainFunc - (g_HookParam_GetThreadContext.pCoverdCode + 0x17);

	//����JMPӲ����
	HardCode_JMP newJMP = { 0 };
	newJMP.JMP = 0xE9;
	newJMP.Opcode = opcode_jmp;

	//ճ�������Ǵ���
	memcpy((PVOID)::g_HookParam_GetThreadContext.pCoverdCode, (PVOID)originFunc, 0x12);
	//�޸ı����Ǵ���Ĳ��ֲ�����opcode
	*(DWORD*)(g_HookParam_GetThreadContext.pCoverdCode + 0x4 + 0x2) = opcode_new_call;
	*(DWORD*)(g_HookParam_GetThreadContext.pCoverdCode + 0xC + 0x2) = opcode_new_js;
	//�ڱ����Ǵ����ĩβ����JMP����תָ��
	memcpy((PVOID)(::g_HookParam_GetThreadContext.pCoverdCode + 0x12), &newJMP, sizeof(newJMP));

}
/**
 * ר�Ŵ���64λ��HOOK�����ı����Ǵ��룺D3D11-CreateQuery
 */
VOID InlineHook_X64_HandleCoverdCode_D3D11CreateQuery(DWORD64 originFunc, int byteLen)
{
	//ԭʼ GetThreadContext 19(0x13)�ֽڵ��������� (�������16�ֽ�)
	//00007FFAAE576B50 48 83 EC 58          sub         rsp, 58h
	//00007FFAAE576B54 48 8B 05 15 89 2C 00 mov         rax, qword ptr[7FFAAE83F470h]-----���Ѱַ=����ָ���ַ+������
	//00007FFAAE576B5B 48 33 C4             xor         rax, rsp
	//00007FFAAE576B5E 48 89 44 24 40       mov         qword ptr[rsp + 40h], rax
	//00007FFAAE576B63 

	//�޸ĺ�ռ19+14(0x21)�ֽ�	(��Ϊ�����ǵĴ�������"���Ѱַ"������ճ��λ����2GB�ķ�Χ����)
	//newAddr					sub         rsp, 58h
	//newAddr+ 0x4				mov         rax, qword ptr[7FFAAE83F470h]-----������opcode
	//newAddr+ 0xB				xor         rax, rsp
	//newAddr+ 0xE				mov         qword ptr[rsp + 40h], rax
	//newAddr+ 0x13				jmp			remainAddr					;��ת�����ҹ�����ʣ�����ĵ�ַ  (5�ֽ�)
	//newAddr+ 0x18			

	//����Hook������Ҫ���ص��ĸ���ַ����ִ��ʣ�����
	::g_HookParam_CreateQuery.originFunc = originFunc;				//*
	::g_HookParam_CreateQuery.remainFunc = originFunc + byteLen;	//*

	//ԭmovָ���opcode
	DWORD opcode_old_mov = *(DWORD*)(originFunc + 0x4 + 0x3);
	//ԭcallָ���Ŀ���ַ = opcode + ����ָ��ĵ�ַ
	DWORD64 destAddr_old_mov = opcode_old_mov + (originFunc + 0xB);

	//���㱻�ҹ�����������ָ�����õ�����С������ַ 
	DWORD64 arr[2] = { 0 };
	arr[0] = destAddr_old_mov;
	arr[1] = g_HookParam_CreateQuery.remainFunc;
	DWORD64 maxAddr = 0;
	DWORD64 minAddr = 0;
	CalcMaxMinAddr_BubbleSort(arr, sizeof(arr) / sizeof(DWORD64), maxAddr, minAddr);

	//���뷶Χ��2GB�ڵ������ڴ� , GetThreadContext()��Ҫ0x20�ֽ�
	::g_HookParam_CreateQuery.pCoverdCode = AllocMemWithin2GB(minAddr, maxAddr, 0x20);

	//����ָ��ճ����ַ�������²�����opcode
	DWORD opcode_new_mov = destAddr_old_mov - (g_HookParam_CreateQuery.pCoverdCode + 0xB);
	DWORD opcode_jmp = g_HookParam_CreateQuery.remainFunc - (g_HookParam_CreateQuery.pCoverdCode + 0x18);

	//����JMPӲ����
	HardCode_JMP newJMP = { 0 };
	newJMP.JMP = 0xE9;
	newJMP.Opcode = opcode_jmp;

	//ճ�������Ǵ���
	memcpy((PVOID)::g_HookParam_CreateQuery.pCoverdCode, (PVOID)originFunc, 0x13);
	//�޸ı����Ǵ���Ĳ��ֲ�����opcode
	*(DWORD*)(g_HookParam_CreateQuery.pCoverdCode + 0x4 + 0x3) = opcode_new_mov;
	//�ڱ����Ǵ����ĩβ����JMP����תָ��
	memcpy((PVOID)(::g_HookParam_CreateQuery.pCoverdCode + 0x13), &newJMP, sizeof(newJMP));

}



/**
 * InlineHook (64λ)
 * ���� originFunc	//ԭʼ������ַ
 * ���� byteLen		//��Hook�ĺ������滻�����������ֽ�����������16�ֽ�(14�ֽ�Զ��ת��2�ֽڴ���)
 * ���� hookFunc		//���Ӻ�����ַ(�˺���������)
 * ���� hookFunc		//���ڴ������Ǵ���ĺ�����ַ
 * byteLen��	��MessageBoxA		16�ֽڡ�	��D3D11-Present		19�ֽڡ�
 *			��D3D11-DrawIndexed 19�ֽڡ� ��VirtualProtect	17�ֽڡ�
 *			��GetThreadContext  18�ֽڡ� ��D3D11-CreateQuery 19�ֽڡ�
 * ע�⣬��ĿDEBUG����ʱ��Ҫ�رն�ջ��ȫ��飬����ᵼ�� Run-Time Check Failure #2 �쳣
 */
VOID InlineHook_X64(DWORD64 originFunc, int byteLen, DWORD64 hookFunc, PVOID pHandleCoverdCode)
{
	printf("\n��info����ʼInline Hook ...ԭʼ������ַ=%016llX  ���Ӻ����ĵ�ַ=%016llX \n", originFunc, hookFunc);
	if (byteLen < 16) { printf("��error������byteLen����Ϊ16 ... \n"); return; }

	//��鱻�ҹ�������ǰ3�ֽ��Ƿ�ΪJMP��ӵ���(0x25FF48)
	if (((*(DWORD*)originFunc) & 0x00FFFFFF) == 0x25FF48)
	{
		DWORD originFunc_opcode = *(DWORD*)(originFunc + 0x3);
		DWORD64* originFunc_realAddr_saveWhere = (DWORD64*)(originFunc_opcode + (originFunc + 0x3 + 0x4));
		originFunc = *originFunc_realAddr_saveWhere;
		printf("��info������ԭʼ������ַ=%016llX (Խ��JMP)\n", originFunc);
	}

	//ģ���㺯�����������Ӻ�����ַ���Ӷ���ִ�б�����д�Ķ�ջƽ�����
	DWORD64 hookFunc_realAddr = 0;
	DWORD64 hookFunc_naked = 0;
#if _DEBUG
	printf("��info����⵽DEBUG����汾����ȷ����Ŀ�رն�ջ��ȫ����Ա���Run-Time Check Failure #2 �쳣...\n");

	//Debug�汾��ȡ�ĺ�����ַ��Խ��JMPָ��Ž��뺯������Ҫ����������������ջ���ǲ��ִ���
	//��ȡJMPָ���Opcode
	DWORD hookFunc_opCode = *(DWORD*)(hookFunc + 1);
	//��ȡ������ʵ��ַ��Ҫ��ת�ĺ�����ʵ��ַ=JMPָ�������ָ�����ڵ�ַ+Opcode=(hookFunc+5)+Opcode
	hookFunc_realAddr = hookFunc + 5 + hookFunc_opCode;
	printf("��info���������Ӻ�����ַ=%016llX (Խ��JMP)\n", hookFunc_realAddr);
	//������������������ջ�Ĵ����Ǳ仯�ģ��������Լ��Ĵ�����仯�������Թ̶���ƫ����Ϊ�㺯����ڡ�
	//���ڹ��Ӻ�����������CALL ASM_SaveReg()�����Ծʹ˺�����������0x7����Ϊ�㺯�����(��ΪASM_SaveReg�и�����)
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
				printf("��info���������Ӻ�����ַ=%016llX (Խ��������ջ�ȣ�ģ���㺯��)\n", hookFunc_naked);
				break;
			}
		}
	}
#elif NDEBUG
	//release�汾��ȡ�ĺ�����ַ����Ҫ����JMP
	//ģ���㺯�����õ���ֵַ
	hookFunc_naked = hookFunc_realAddr + 0x7;
	printf("��fail��release�汾���㺯����ַ������δ���...");
	return;
#endif

	if (hookFunc_naked == 0x0)
	{
		printf("��error���������Ӻ�����ַʧ��..���ú����Ƿ�Ϊ���Ӻ��� \n");
		return;
	}

	//ճ�������������ǵ�ԭ����������2GB��Χ��λ��
	BOOL(*HandleCoverdCode)(DWORD64, int) = (BOOL(*)(DWORD64, int))pHandleCoverdCode;
	if (!HandleCoverdCode(originFunc, byteLen)) return;

	//�޸��ڴ汣�����ԣ��ɶ�д��ִ��
	DWORD oldProtect = 0; DWORD newProtect = 0;
	VirtualProtect((LPVOID)originFunc, byteLen, PAGE_EXECUTE_READWRITE, &oldProtect);

	//���㹳�Ӻ����ĵ�ַ�ĵ�32λ�͸�32λ������ԶJMP (�������ƻ�ջ���Ϸ���û�����ݣ���ȫ���ʱ���� Run-Time Check Failure #2 �쳣)
	DWORD hookFunc_Low32 = (DWORD)hookFunc_naked;
	DWORD hookFunc_High32 = hookFunc_naked >> 32;
	//����Ӳ����
	BYTE PUSH_RCX[1] = { 0x51 };
	BYTE POP_RCX[1] = { 0x59 };
	BYTE PUSH[1] = { 0x68 };
	BYTE MOV_DWORD_PTR_SS[4] = { 0xC7,0x44,0x24,0x04 };
	BYTE RET[1] = { 0xC3 };
	//��ʼ��ԭʼ������ǰbyteLen�ֽڴ���Ϊ NOP 
	memset((PBYTE)originFunc, 0x90, byteLen);
	//�޸�ԭʼ�����ĵ�1~5�ֽ�Ϊ��PUSH ��32λ��ַ
	memcpy((PVOID)(originFunc), PUSH, sizeof(PUSH));
	memcpy((PVOID)(originFunc + 1), &hookFunc_Low32, 4);
	//�޸�ԭʼ�����ĵ�6~13�ֽ�Ϊ��MOV dword ptr ss:[rsp+0x4],��32λ��ַ
	memcpy((PVOID)(originFunc + 5), MOV_DWORD_PTR_SS, sizeof(MOV_DWORD_PTR_SS));
	memcpy((PVOID)(originFunc + 9), &hookFunc_High32, 4);
	//�޸�ԭʼ�����ĵ�14�ֽ�Ϊ��PUSH rcx (��rcx��ֵ�����ջ��-8������Ϊ���Ӻ�������Ҫ��rcx����Ų�����������ASM�ļ�ȫ�ֱ��������⣬�Ϳ��Բ���ô�鷳��)
	memcpy((PVOID)(originFunc + 13), PUSH_RCX, sizeof(PUSH_RCX));
	//�޸�ԭʼ�����ĵ�15�ֽ�Ϊ��POP  rcx
	memcpy((PVOID)(originFunc + 14), POP_RCX, sizeof(POP_RCX));
	//�޸�ԭʼ�����ĵ� 16 �ֽ�Ϊ��RET
	memcpy((PVOID)(originFunc + 15), RET, sizeof(RET));
	//�ָ��ڴ汣������
	VirtualProtect((LPVOID)originFunc, byteLen, oldProtect, &newProtect);

	//���ԣ�MessageBoxA
	//MessageBox(0, "TestContent", "TestCaption", 0);
}