#pragma once
#include "pch.h"

//=====================================��������=======================================================================
#define Ӳ��_��ִ�� 0x55		    //�ֲ��ϵ�+ִ�жϵ� (��Ч)
#define Ӳ��_��д�� 0x55550055	//�ֲ��ϵ�+д��ϵ㣨��Ч��
#define Ӳ��_����д 0xFFFF0055   //�ֲ��ϵ�+����д�ϵ㣨��Ч��

//���ڷֱ����4��DRX���쳣������
LONG NTAPI MyVectoredExceptionHandle(struct _EXCEPTION_POINTERS* ExceptionInfo);//���ڷֱ����4���쳣�������ĺ���
//����ָ�룺����VEH����
typedef LONG(NTAPI* PVEH_Func)(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params);

//�ṹ�壺Ӳ���ϵ������ȫ�ֲ���
typedef struct HardwareBP_Params
{
	LPVOID BreakPointAddress;
	PVEH_Func pVEHFunc;
	LPVOID pFirstCode;
};

//ö�٣�4�����ԼĴ���
enum DRX
{
	Dr0, Dr1, Dr2, Dr3
};

//�����VEH����
LONG NTAPI VEH_AddVectoredExceptionHandler(struct _EXCEPTION_POINTERS* ExceptionInfo, HardwareBP_Params HardwareBP_Params);
LONG NTAPI VEH_D3D11Present(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params);
LONG NTAPI VEH_D3D11DrawIndexed(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params);
LONG NTAPI VEH_GetThreadContext(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params);
LONG NTAPI VEH_IsDebuggerPresent(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params);
LONG NTAPI VEH_CreateQuery(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params);
LONG NTAPI VEH_PSSetShaderResources(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params);
LONG NTAPI VEH_DEBUG(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params);

//����ȫ�ֱ�����4�����ԼĴ����������쳣����������Ĳ���
extern HardwareBP_Params g_HardwareBP_Params_DR0;
extern HardwareBP_Params g_HardwareBP_Params_DR1;
extern HardwareBP_Params g_HardwareBP_Params_DR2;
extern HardwareBP_Params g_HardwareBP_Params_DR3;

//==================================================================================================================

//=========================================�ඨ��====================================================================
class HardwareBP
{
private:
	LPVOID BreakPointAddress;		//�¶�λ��
	DRX Drx;						//Ӳ�����õĵ��ԼĴ���
	PVEH_Func pVEHFunc;				//��ǰ���ԼĴ��������õ��쳣������
	int firstCodeLen;				//�׾����ĳ���		(���ý�ִ�жϵ�ʱ)
	LPVOID pFirstCode;				//�׾����ĸ���λ��	(���ý�ִ�жϵ�ʱ)

	/**
		* �������߳���Ӳ���ϵ�(��ǰ�̳߳���)
		* ���� Drx-���ĸ����ԼĴ�����Ӳ��
		* ���� Dr7Type-Ӳ���ϵ������
		*	#define Ӳ��_��ִ�� 0x55
		*	#define Ӳ��_��д�� 0x55550055
		*	#define Ӳ��_����д 0xFFFF0055
	*/
	BOOL HookAllThread(enum DRX Drx, DWORD64 Dr7Type);

public:
	/**
		* ��������Ӳ���ϵ�
		* ���� BreakPointAddress
		* ���� pVEHFunc
		* ���� Drx-ָ������Ӳ���ϵ�ĵ��ԼĴ���
		* ���� firstCodeLen	��Hook�������׾������ռ�ֽ��� 
			��MessageBoxA-4�ֽڡ���DrawIndexed-4�ֽڡ���Present-5�ֽڡ���CreateQuery-4����PSSetShaderResources-3��
			��AddVectoredExceptionHandler-3����GetThreadContext-3����IsDebuggerPresent-9��
	*/
	HardwareBP(LPVOID BreakPointAddress, PVEH_Func pVEHFunc, enum DRX Drx, int firstCodeLen);
	/**
		* ����Ӳ�ϣ����������쳣�������
		* ���� Dr7Type Ӳ���ϵ������
	*/
	VOID WINAPI SetVEHHook(DWORD64 Dr7Type);
};
//==================================================================================================================