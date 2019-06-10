#include "pch.h"

VOID ChreatD3D11_MyPresent(REGISTER_X64* pReg)
{

	//Present函数函数的原型：HRESULT __stdcall hkD3D11Present(IDXGISwapChain* pSwapChain, UINT SyscInterval, UINT Flags)
	//rcx 参数1：this结构体对象指针，交换链对象的地址
	//edx 参数2: UINT SyscInterval
	//r8d 参数3: UINT Flags
	pSwapChain_Game = (IDXGISwapChain*)pReg->rcx;
	UINT SyscInterval = (DWORD)pReg->rdx;
	UINT Flags = (DWORD)pReg->r8;

	if (ISFIRST_PRESENT)
	{
		ISFIRST_PRESENT = FALSE;
		printf("\n首次进入Present，游戏内的pSwapChain=%016llX \n", pSwapChain_Game);
		//根据游戏的交换链获取游戏的设备指针
		if (SUCCEEDED(pSwapChain_Game->GetDevice(__uuidof(ID3D11Device), (void **)(&pDevice_Game))))
		{
			pSwapChain_Game->GetDevice(__uuidof(pDevice_Game), (void **)(&pDevice_Game));
			pDevice_Game->GetImmediateContext(&pContext_Game);
		}
		InitDEPTHSTENCIL();
	}

}
int off;
bool guolv()
{
	//====================================测试1：过滤指定Stride下的ByteWidth===============
	if (GetAsyncKeyState('P') & 0x1)
	{
		off = 10000;
		Ban_ByteWidth += off;
		printf("按了P Ban_ByteWidth= %d  \n", Ban_ByteWidth);
	}
	if (GetAsyncKeyState('O') & 0x1)
	{
		off = 10000;
		Ban_ByteWidth -= off;
		printf("按了O Ban_ByteWidth= %d \n", Ban_ByteWidth);
	}
	if (GetAsyncKeyState(VK_OEM_7) & 0x1)
	{
		off = 100;
		Ban_ByteWidth -= off;
		printf("按了'\" Ban_ByteWidth= %d  \n", Ban_ByteWidth);
	}
	if (GetAsyncKeyState(VK_OEM_5) & 0x1)
	{
		off = 100;
		Ban_ByteWidth += off;
		printf("按了\\| Ban_ByteWidth= %d  \n", Ban_ByteWidth);
	}

	if (GetAsyncKeyState(VK_OEM_4) & 0x1)
	{
		off = 1000;
		Ban_ByteWidth -= off;
		printf("按了[ Ban_ByteWidth= %d  \n", Ban_ByteWidth);
	}
	if (GetAsyncKeyState(VK_OEM_6) & 0x1)
	{
		off = 1000;
		Ban_ByteWidth += off;
		printf("按了] Ban_ByteWidth= %d \n", Ban_ByteWidth);
	}
	if (stride == 20
		&& indesc.ByteWidth >= Ban_ByteWidth
		&& indesc.ByteWidth <= Ban_ByteWidth + off)
	{
		printf("%d \n", indesc.ByteWidth);
		return FALSE;
	}
	else
	{
		return TRUE;
	}
	//====================================================================
}

BOOL ChreatD3D11_MyDrawIndexed(REGISTER_X64* pReg, DWORD64 pCoverCode_DrawIndexed)
{
	//函数原型 ：void __stdcall DrawIndexed(ID3D11DeviceContext* pContext,_In_  UINT IndexCount,_In_  UINT StartIndexLocation,_In_  INT BaseVertexLocation)
	//rcx 参数1：this结构体对象指针，上下文对象的地址
	//edx 参数2: UINT IndexCount
	//r8d 参数3: UINT StartIndexLocation
	//r9d 参数4：INT BaseVertexLocation
	ID3D11DeviceContext* pContext = (ID3D11DeviceContext *)pReg->rcx;
	UINT IndexCount = (DWORD)pReg->rdx;
	UINT StartIndexLocation = (DWORD)pReg->r8;
	UINT BaseVertexLocation = (DWORD)pReg->r9;

	//获取数据.
	if (pContext == 0) { MessageBox(0, "pContext", 0, 0); return TRUE; }
	pContext->IAGetVertexBuffers(0, 1, &veBuffer, &stride, &veBufferOffset);//获取顶点缓冲区、获取stride数 (步长，每像素占用的字节数)
	pContext->IAGetIndexBuffer(&inBuffer, &inFormat, &inOffset);			//获取索引缓冲区
	if (veBuffer == 0) { MessageBox(0, "veBuffer", 0, 0); return TRUE; }
	if (inBuffer == 0) { MessageBox(0, "inBuffer", 0, 0); return TRUE; }
	veBuffer->GetDesc(&vedesc);
	inBuffer->GetDesc(&indesc);
	veBuffer->Release();
	inBuffer->Release();
	veBuffer = __nullptr;
	inBuffer = __nullptr;

	//return guolv();
	if (GetAsyncKeyState(VK_F5) & 0x1)
	{
		START_WallHack = TRUE;
		printf("开启透视... \n");
	}
	if (GetAsyncKeyState(VK_F6) & 0x1)
	{
		START_WallHack = FALSE;
		printf("关闭透视... \n");
	}
	//透视守望先锋stride=20下的所有模型
	if (stride == 20 && START_WallHack)
	{
		//过滤掉不需要透视的模型
		if (indesc.ByteWidth != 30240		//猩猩罩子
			&& indesc.ByteWidth != 8688		//奥丽莎盾
			&& indesc.ByteWidth != 65028	//麦克雷-侠盗皮肤-第一人称视角的手
			&& indesc.ByteWidth != 107520	//麦克雷-侠盗皮肤-第一人称视角的枪
			)
		{
			SetDepthStencilState(DISABLED);
			ASM_Fake_DrwaIndexed(pContext, IndexCount, StartIndexLocation, BaseVertexLocation, pCoverCode_DrawIndexed);
			SetDepthStencilState(ENABLED);
		}
	}

	return TRUE;
}

BOOL ChreatD3D11_MyCreateQuery(REGISTER_X64* pReg, DWORD64 pCoverCode)
{
	//CreateQuery函数函数的原型：void __stdcall D3D11CreateQueryHook (ID3D11Device* pDevice, const D3D11_QUERY_DESC *pQueryDesc, ID3D11Query **ppQuery);
	//rcx 参数1：pDevice 对象指针
	//rdx 参数2: pQueryDesc
	//r8  参数3: ppQuery
	ID3D11Device* pDevice = (ID3D11Device*)pReg->rcx;
	D3D11_QUERY_DESC * pQueryDesc = (D3D11_QUERY_DESC *)pReg->rdx;
	ID3D11Query ** ppQuery = (ID3D11Query **)pReg->r8;

	//Disable Occlusion which prevents rendering player models through certain objects
	if (pQueryDesc->Query == D3D11_QUERY_OCCLUSION)
	{
		//printf("【info】禁用遮挡查询...\n");
		//修改描述参数
		D3D11_QUERY_DESC oqueryDesc = CD3D11_QUERY_DESC();
		(&oqueryDesc)->MiscFlags = pQueryDesc->MiscFlags;
		(&oqueryDesc)->Query = D3D11_QUERY_TIMESTAMP;
		pReg->rdx = (DWORD64)&oqueryDesc;
	}

	//继续执行原始函数
	return TRUE;
}

