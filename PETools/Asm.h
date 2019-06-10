#pragma once
#include "pch.h"

extern"C" DWORD64 ASM_SaveReg(PVOID pRegister);

extern"C" DWORD64 ASM_RecoverReg(PVOID pRegister, DWORD64 pCoverdCode);

//跳转至DrwaIndexed的首句代码，随后跳转至剩余代码执行，最后返回至Fake_DrwaIndexed的调用处
extern"C" void __stdcall ASM_Fake_DrwaIndexed(ID3D11DeviceContext* pContext, _In_  UINT IndexCount, _In_  UINT StartIndexLocation, _In_  INT BaseVertexLocation, DWORD64 remainAddr);

extern"C" DWORD64 ASM_EndOrigin(PVOID pRegister);





