#pragma once
#include "pch.h"


extern "C" _declspec(dllexport)  DWORD WINAPI Malware_Core(LPVOID lpThreadParameter);//��Ŀ�������ִ�еĶ������(�踺���޸�IAT��)
extern "C" _declspec(dllexport)  LPVOID GetMalwareParam();			//���ڵ���ȫ�ֱ����ĵ�ַ
VOID Malware_HandleParam(PEBODY PEBody, DWORD64 virtualAddr);		//���ڴ���malware��ȫ�ֱ�������
VOID ReflectInject_EXE(const CHAR* processName);					//ע�뵱ǰexeģ�飨�������Ϊreleaseʱ��exe�����ض�λ��
VOID ReflectInject_EXE_AntiDetect_20190606(const CHAR* processName);//ע�뵱ǰexeģ�飬��OW�����ƣ��������Ϊreleaseʱ��exe�����ض�λ��
VOID ReflectInject_DLL_AntiDetect_20190606(const CHAR* processName,const char* dllPath);//ע���ⲿDLLģ�飬��OW������

//===================MalWare����Ĳ���===================================================
struct MALWARE_IAT
{
	DWORD funcAddr[200];	//������ַ(���㹻��)
	int numOfItem_pri;		//˽�У���ʶ��ǰIAT�����м�����
};
struct MALWARE_INT
{
	//��ֵ����߶�����λ=1��������λ���"�����������"
	//��ֵ����߶�����λ=0������RVAֵ��ָ��һ��_IMAGE_IMPORT_BY_NAME�ṹ(ϵͳ����Ѷ���˽ṹ)
	DWORD IMAGE_THUNK_DATA[200]; //���㹻��
	int numOfItem_pri;			 //˽�У���ʶ��ǰINT�����м�����
};
struct MALWARE_PARAM
{
	int numOfImportDirectory;
	DWORD64 virtualAddr;		//��Ŀ����������뵽�Ļ�ַ
	IMPORT_DIRECTORY ImportDirectory[100];		//���㹻��
	MALWARE_IAT IAT_Malware[100];				//���㹻��
	MALWARE_INT INT_Malware[100];				//���㹻��
};
//========================================================================================
