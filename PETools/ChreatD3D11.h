#pragma once
#include "pch.h"

//Present函数的原型：HRESULT __stdcall hkD3D11Present(IDXGISwapChain* pSwapChain, UINT SyscInterval, UINT Flags)
VOID ChreatD3D11_MyPresent(REGISTER_X64* pReg);

//DrawIndexed函数原型：void __stdcall DrawIndexed(_In_  UINT IndexCount,_In_  UINT StartIndexLocation,_In_  INT BaseVertexLocation)
BOOL ChreatD3D11_MyDrawIndexed(REGISTER_X64* pReg, DWORD64 pCoverCode);


BOOL ChreatD3D11_MyCreateQuery(REGISTER_X64* pReg, DWORD64 pCoverCode);
