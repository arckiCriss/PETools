#pragma once
#include "pch.h"

//ͨ���������򿪽���
HANDLE OpenProcessByName(const TCHAR* processName, DWORD ACCESS);

//����Ȩ��(Ҫ�ù���ԱȨ������EXE)
bool Up();

//ԭ��ת����ʮ�����Ƶ������ַ���
CHAR* HexToStr(DWORD srcHex);
CHAR* DecToStr(DWORD srcDec);

//��ӡʮ����������hex��msg��OutputDebugString (���ֽڵ�hex��)
void ShowDbg(const char* msgStr, DWORD hex);
