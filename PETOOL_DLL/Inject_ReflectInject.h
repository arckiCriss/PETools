#pragma once
#include "stdafx.h"

DWORD WINAPI Malware_Core_x86(LPVOID lpThreadParameter);	//��Ŀ�������ִ�еĶ������(�踺���޸�IAT��)
VOID Malware_HandleParam(PEBody PEBody, DWORD virtualAddr);	// Ϊmalwareȫ�ֲ�����ֵ
VOID ReflectInject_X86(CHAR* processName);	//����ʽע��(X86)

//>>>>>>>>>>>>>>>>>>MalWare����Ĳ���>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
struct IAT_MALWARE
{
	DWORD funcAddr[200];	//������ַ(���㹻��)
	int numOfItem_pri;		//˽�У���ʶ��ǰIAT�����м�����
};
struct INT_MALWARE
{
	//��ֵ����߶�����λ=1��������λ���"�����������"
	//��ֵ����߶�����λ=0������RVAֵ��ָ��һ��_IMAGE_IMPORT_BY_NAME�ṹ(ϵͳ����Ѷ���˽ṹ)
	DWORD IMAGE_THUNK_DATA[200]; //���㹻��
	int numOfItem_pri;			 //˽�У���ʶ��ǰINT�����м�����
};
struct MALWARE_PARAM
{
	int numOfImportDirectory;
	DWORD virtualAddr;		//��Ŀ����������뵽�Ļ�ַ
	ImportDirectory ImportDirectory[100];		//���㹻��
	IAT_MALWARE IAT_Malware[100];				//���㹻��
	INT_MALWARE INT_Malware[100];				//���㹻��
};
//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>