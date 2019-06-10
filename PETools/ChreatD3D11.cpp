#include "pch.h"

VOID ChreatD3D11_MyPresent(REGISTER_X64* pReg)
{

	//Present����������ԭ�ͣ�HRESULT __stdcall hkD3D11Present(IDXGISwapChain* pSwapChain, UINT SyscInterval, UINT Flags)
	//rcx ����1��this�ṹ�����ָ�룬����������ĵ�ַ
	//edx ����2: UINT SyscInterval
	//r8d ����3: UINT Flags
	pSwapChain_Game = (IDXGISwapChain*)pReg->rcx;
	UINT SyscInterval = (DWORD)pReg->rdx;
	UINT Flags = (DWORD)pReg->r8;

	if (ISFIRST_PRESENT)
	{
		ISFIRST_PRESENT = FALSE;
		printf("\n�״ν���Present����Ϸ�ڵ�pSwapChain=%016llX \n", pSwapChain_Game);
		//������Ϸ�Ľ�������ȡ��Ϸ���豸ָ��
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
	//====================================����1������ָ��Stride�µ�ByteWidth===============
	if (GetAsyncKeyState('P') & 0x1)
	{
		off = 10000;
		Ban_ByteWidth += off;
		printf("����P Ban_ByteWidth= %d  \n", Ban_ByteWidth);
	}
	if (GetAsyncKeyState('O') & 0x1)
	{
		off = 10000;
		Ban_ByteWidth -= off;
		printf("����O Ban_ByteWidth= %d \n", Ban_ByteWidth);
	}
	if (GetAsyncKeyState(VK_OEM_7) & 0x1)
	{
		off = 100;
		Ban_ByteWidth -= off;
		printf("����'\" Ban_ByteWidth= %d  \n", Ban_ByteWidth);
	}
	if (GetAsyncKeyState(VK_OEM_5) & 0x1)
	{
		off = 100;
		Ban_ByteWidth += off;
		printf("����\\| Ban_ByteWidth= %d  \n", Ban_ByteWidth);
	}

	if (GetAsyncKeyState(VK_OEM_4) & 0x1)
	{
		off = 1000;
		Ban_ByteWidth -= off;
		printf("����[ Ban_ByteWidth= %d  \n", Ban_ByteWidth);
	}
	if (GetAsyncKeyState(VK_OEM_6) & 0x1)
	{
		off = 1000;
		Ban_ByteWidth += off;
		printf("����] Ban_ByteWidth= %d \n", Ban_ByteWidth);
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
	//����ԭ�� ��void __stdcall DrawIndexed(ID3D11DeviceContext* pContext,_In_  UINT IndexCount,_In_  UINT StartIndexLocation,_In_  INT BaseVertexLocation)
	//rcx ����1��this�ṹ�����ָ�룬�����Ķ���ĵ�ַ
	//edx ����2: UINT IndexCount
	//r8d ����3: UINT StartIndexLocation
	//r9d ����4��INT BaseVertexLocation
	ID3D11DeviceContext* pContext = (ID3D11DeviceContext *)pReg->rcx;
	UINT IndexCount = (DWORD)pReg->rdx;
	UINT StartIndexLocation = (DWORD)pReg->r8;
	UINT BaseVertexLocation = (DWORD)pReg->r9;

	//��ȡ����.
	if (pContext == 0) { MessageBox(0, "pContext", 0, 0); return TRUE; }
	pContext->IAGetVertexBuffers(0, 1, &veBuffer, &stride, &veBufferOffset);//��ȡ���㻺��������ȡstride�� (������ÿ����ռ�õ��ֽ���)
	pContext->IAGetIndexBuffer(&inBuffer, &inFormat, &inOffset);			//��ȡ����������
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
		printf("����͸��... \n");
	}
	if (GetAsyncKeyState(VK_F6) & 0x1)
	{
		START_WallHack = FALSE;
		printf("�ر�͸��... \n");
	}
	//͸�������ȷ�stride=20�µ�����ģ��
	if (stride == 20 && START_WallHack)
	{
		//���˵�����Ҫ͸�ӵ�ģ��
		if (indesc.ByteWidth != 30240		//��������
			&& indesc.ByteWidth != 8688		//����ɯ��
			&& indesc.ByteWidth != 65028	//�����-����Ƥ��-��һ�˳��ӽǵ���
			&& indesc.ByteWidth != 107520	//�����-����Ƥ��-��һ�˳��ӽǵ�ǹ
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
	//CreateQuery����������ԭ�ͣ�void __stdcall D3D11CreateQueryHook (ID3D11Device* pDevice, const D3D11_QUERY_DESC *pQueryDesc, ID3D11Query **ppQuery);
	//rcx ����1��pDevice ����ָ��
	//rdx ����2: pQueryDesc
	//r8  ����3: ppQuery
	ID3D11Device* pDevice = (ID3D11Device*)pReg->rcx;
	D3D11_QUERY_DESC * pQueryDesc = (D3D11_QUERY_DESC *)pReg->rdx;
	ID3D11Query ** ppQuery = (ID3D11Query **)pReg->r8;

	//Disable Occlusion which prevents rendering player models through certain objects
	if (pQueryDesc->Query == D3D11_QUERY_OCCLUSION)
	{
		//printf("��info�������ڵ���ѯ...\n");
		//�޸���������
		D3D11_QUERY_DESC oqueryDesc = CD3D11_QUERY_DESC();
		(&oqueryDesc)->MiscFlags = pQueryDesc->MiscFlags;
		(&oqueryDesc)->Query = D3D11_QUERY_TIMESTAMP;
		pReg->rdx = (DWORD64)&oqueryDesc;
	}

	//����ִ��ԭʼ����
	return TRUE;
}

