#pragma once
#include "pch.h"

extern"C" DWORD64 ASM_SaveReg(PVOID pRegister);

extern"C" DWORD64 ASM_RecoverReg(PVOID pRegister, DWORD64 pCoverdCode);

//��ת��DrwaIndexed���׾���룬�����ת��ʣ�����ִ�У���󷵻���Fake_DrwaIndexed�ĵ��ô�
extern"C" void __stdcall ASM_Fake_DrwaIndexed(ID3D11DeviceContext* pContext, _In_  UINT IndexCount, _In_  UINT StartIndexLocation, _In_  INT BaseVertexLocation, DWORD64 remainAddr);

extern"C" DWORD64 ASM_EndOrigin(PVOID pRegister);





