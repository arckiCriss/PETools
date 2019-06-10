#include "stdafx.h"
//8��32λͨ�üĴ���
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
DWORD srcFuncAddr = 0;				//ԭ��������ڵ�ַ
DWORD retFuncAddr = 0;				//������ԭ�����ĵ�ַ
REGISTER_X86 register_x86 = { 0 };	//����Ĵ���״̬
PBYTE pSrcCodeBuffer = 0;			//���汻HOOK�Ĵ����

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
void  InlineHook_MyMessageBoxA_X86()	//�㺯�����Լ������ջƽ��
{
#if MY_X86
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
		mov register_x86.eax, eax
		mov register_x86.ebx, ebx
		mov register_x86.ecx, ecx
		mov register_x86.edx, edx
		mov register_x86.esp, esp
		mov register_x86.ebp, ebp
		mov register_x86.esi, esi
		mov register_x86.edi, edi
	}
	printf("8��ͨ�üĴ�����eax=%08X,ebx=%08X,ecx=%08X,edx=%08X,esp=%08X,ebp=%08X,esi=%08X,edi=%08X \n", register_x86.eax, register_x86.ebx, register_x86.ecx, register_x86.edx, register_x86.esp, register_x86.ebp, register_x86.esi, register_x86.edi);
	//��ӡ����
	_asm
	{
		//MessageBox��������4��������ջ���һ���8��ͨ�üĴ�����1��EL�Ĵ�����ջ
		//��ջ��esp+(8+1)*0x4+0x10 �ǵ�1����ջ�Ĳ���
		mov eax, DWORD PTR SS : [esp + 0x34]
		mov param1_MyMessageBoxA, eax
		//��ջ��esp+(8+1)*0x4+0xC �ǵ�2����ջ�Ĳ���
		mov eax, DWORD PTR SS : [esp + 0x30]
		mov param2_MyMessageBoxA, eax
		//��ջ��esp+(8+1)*0x4+0x8 �ǵ�3����ջ�Ĳ���
		mov eax, DWORD PTR SS : [esp + 0x2C]
		mov param3_MyMessageBoxA, eax
		//��ջ��esp+(8+1)*0x4+0x4 �ǵ�4����ջ�Ĳ���
		mov eax, DWORD PTR SS : [esp + 0x28]
		mov param4_MyMessageBoxA, eax
	}
	printf("MessageBoxA�Ĳ���: ����1=%d , ����2=%s�� ����3=%s, ����4=%d \n", param1_MyMessageBoxA, param2_MyMessageBoxA, param3_MyMessageBoxA, param4_MyMessageBoxA);
	//>>>>>>>> end :ִ���Լ��Ĵ���>>>>>>>>

	_asm
	{
		//�Ĵ�����ջ�ָ��ֳ�
		popad
		popfd

		//ִ�б����ǵ�ԭ����
		//	MessageBoxA��ǰ���ֽ�:
		//  75F57E60 8B FF                mov         edi, edi
		//	75F57E62 55                   push        ebp
		//	75F57E63 8B EC                mov         ebp, esp
		mov         edi, edi
		push        ebp
		mov         ebp, esp

		//��ת��ԭ����
		jmp retFuncAddr
	}

#endif
}



/**
 * InlineHook
 * ���� destDllName
 * ���� destFuncName
 * ���� hookFuncAddr
 * ���� byteLen	ָ����ԭ����ǰ(byteLen)�ֽڵĴ����滻��jmpָ�����Ϊ5�ֽ�(��Hook������ǰbyteLen�ֽڱ����������Ĵ����)
 */
void InlineHook_X86(CHAR* destDllName, CHAR* destFuncName, DWORD hookFuncAddr, int byteLen)
{
	//��ȡĿ�꺯������ڵ�ַ
	HMODULE destDll = GetModuleHandle(destDllName);
	if (destDll == 0)
	{
		printf("���󣺲�����Ŀ��ģ��%s \n", destDllName);
		return;
	}
	srcFuncAddr = (DWORD)GetProcAddress(destDll, destFuncName);
	if (srcFuncAddr == 0)
	{
		printf("����Ŀ��ģ���в�����Ŀ�꺯��%s \n", destFuncName);
		return;
	}

	//����Hook����ʱ���صĵ�ַ
	retFuncAddr = srcFuncAddr + byteLen;

	//����ǰ(byteLen)�ֽڵĴ���
	pSrcCodeBuffer = (PBYTE)malloc(byteLen);
	memset(pSrcCodeBuffer, 0x0, byteLen);
	memcpy(pSrcCodeBuffer, (void*)srcFuncAddr, byteLen);

	//�޸�ǰ(byteLen)�ֽڵĴ���Ϊ JMP XXX 
	DWORD oldProtect = 0; DWORD newProtect = 0;
	VirtualProtect((LPVOID)srcFuncAddr, byteLen, PAGE_EXECUTE_READWRITE, &oldProtect);
	*(PBYTE)(srcFuncAddr) = 0xE9; //jmp
	*(DWORD*)(srcFuncAddr + 1) = hookFuncAddr - srcFuncAddr - 5; //jmp X  
	VirtualProtect((LPVOID)srcFuncAddr, byteLen, oldProtect, &newProtect);

	//���Ե���
	MessageBox(0, TEXT("testText"), TEXT("testCaption"), 0);

}
