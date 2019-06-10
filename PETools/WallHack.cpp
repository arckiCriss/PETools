#include "pch.h"
#include <iostream>

//����ȫ�ֱ��������ؿ���
BOOL START_WallHack = FALSE;
BOOL ISFIRST_PRESENT = TRUE;

//����ȫ�ֱ�����D3D11����
IDXGISwapChain* pSwapChain_Game = 0;
ID3D11Device* pDevice_Game = 0;
ID3D11DeviceContext* pContext_Game = 0;
ID3D11RenderTargetView* pRenderTargetView_Game = 0;
ID3D11DepthStencilState* myDepthStencilStates[static_cast<int>(eDepthState::_DEPTH_COUNT)];
ID3D11PixelShader* psRed = NULL;
ID3D11PixelShader* psGreen = NULL;

//����ȫ�ֱ�����vertex
ID3D11Buffer* veBuffer;
UINT stride = 0;
UINT veBufferOffset = 0;
D3D11_BUFFER_DESC vedesc;

//����ȫ�ֱ�����index
ID3D11Buffer* inBuffer;
DXGI_FORMAT inFormat;
UINT        inOffset;
D3D11_BUFFER_DESC indesc;

//����ȫ�ֱ��������˲������
int Ban_Stride = 0;	//Ҫ���˵Ĳ�����
int Ban_Index = 0;	//Ҫ���˵�������
int Ban_ByteWidth = 0;

//͸�ӣ��ҵ�Present����
BOOL WallHack_MyPresent(IDXGISwapChain* pSwapChain, UINT SyscInterval, UINT Flags)
{
	if (ISFIRST_PRESENT)
	{
		ISFIRST_PRESENT = FALSE;
		printf("��info-D3D����1�ν���Present()...��Ϸ������pSwapChain=%llx�����Ի�ȡ�豸ָ��...", pSwapChain_Game);
		//������Ϸ�Ľ�������ȡ��Ϸ���豸ָ��
		if (SUCCEEDED(pSwapChain_Game->GetDevice(__uuidof(ID3D11Device), (void**)(&pDevice_Game))))
		{
			pSwapChain_Game->GetDevice(__uuidof(pDevice_Game), (void**)(&pDevice_Game));
			pDevice_Game->GetImmediateContext(&pContext_Game);
			printf("pDevice=%llx \n", pDevice_Game);
		}
		//��ʼ����Ȼ���ģ��
		InitDEPTHSTENCIL();
		//��ʼ���ҵ���ɫ��
		//if (!psRed)GenerateShader(pDevice_Game, &psRed, 1.0f, 0.0f, 0.0f);
		//if (!psGreen)GenerateShader(pDevice_Game, &psGreen, 0.0f, 1.0f, 0.0f);
		return TRUE;
	}
	return FALSE;
}

//����������Ⱦ��
HRESULT GenerateShader(ID3D11Device* pD3DDevice, ID3D11PixelShader** pShader, float r, float g, float b)
{
	char szCast[] = "struct VS_OUT"
		"{"
		" float4 Position : SV_Position;"
		" float4 Color : COLOR0;"
		"};"

		"float4 main( VS_OUT input ) : SV_Target"
		"{"
		" float4 fake;"
		" fake.a = 1.0f;"
		" fake.r = %f;"
		" fake.g = %f;"
		" fake.b = %f;"
		" return fake;"
		"}";
	ID3D10Blob* pBlob;
	char szPixelShader[1000];

	sprintf(szPixelShader, szCast, r, g, b);

	ID3DBlob* d3dErrorMsgBlob;

	HRESULT hr = D3DCompile(szPixelShader, sizeof(szPixelShader), "shader", NULL, NULL, "main", "ps_4_0", NULL, NULL, &pBlob, &d3dErrorMsgBlob);

	if (FAILED(hr))
		return hr;

	hr = pD3DDevice->CreatePixelShader((DWORD*)pBlob->GetBufferPointer(), pBlob->GetBufferSize(), NULL, pShader);

	if (FAILED(hr))
		return hr;

	return S_OK;
}

//������Ȼ���ģ��
void SetDepthStencilState(eDepthState aState)
{
	//��present��ȡ�������ĺ�������������Ȳ���ģ��
	if (pContext_Game == 0x0) { return; }
	pContext_Game->OMSetDepthStencilState(myDepthStencilStates[aState], 1);

}

//��ʼ����Ȳ���ģ��
VOID InitDEPTHSTENCIL()
{
	//--------------------------------------------
	D3D11_DEPTH_STENCIL_DESC  stencilDesc;
	stencilDesc.DepthFunc = D3D11_COMPARISON_LESS;
	stencilDesc.StencilEnable = true;// �Ƿ���ģ����� stencil test
	stencilDesc.StencilReadMask = 0xFF; // ģ��ֵд������ The StencilReadMask used in the stencil test:
	stencilDesc.StencilWriteMask = 0xFF;// ģ��ֵ��ȡ����
	// �����泯��������ν������/ģ���������
	stencilDesc.FrontFace.StencilFailOp = D3D11_STENCIL_OP_KEEP;		//����Ŀ��ģ��ֵ����
	stencilDesc.FrontFace.StencilDepthFailOp = D3D11_STENCIL_OP_INCR;	//����Ŀ��ģ��ֵΪ0
	stencilDesc.FrontFace.StencilPassOp = D3D11_STENCIL_OP_KEEP;
	stencilDesc.FrontFace.StencilFunc = D3D11_COMPARISON_ALWAYS;
	// �Ա��泯��������ν������/ģ�����������
	stencilDesc.BackFace.StencilFailOp = D3D11_STENCIL_OP_KEEP;
	stencilDesc.BackFace.StencilDepthFailOp = D3D11_STENCIL_OP_DECR;
	stencilDesc.BackFace.StencilPassOp = D3D11_STENCIL_OP_KEEP;
	stencilDesc.BackFace.StencilFunc = D3D11_COMPARISON_ALWAYS;

	//ENABLED
	stencilDesc.DepthEnable = true; // �Ƿ�����Ȳ���
	stencilDesc.DepthWriteMask = D3D11_DEPTH_WRITE_MASK_ALL; // ���ֵд������
	pDevice_Game->CreateDepthStencilState(&stencilDesc, &myDepthStencilStates[static_cast<int>(eDepthState::ENABLED)]);

	//DISABLED
	stencilDesc.DepthEnable = false;
	stencilDesc.DepthWriteMask = D3D11_DEPTH_WRITE_MASK_ALL;
	pDevice_Game->CreateDepthStencilState(&stencilDesc, &myDepthStencilStates[static_cast<int>(eDepthState::DISABLED)]);

	//NO_READ_NO_WRITE
	stencilDesc.DepthEnable = false;
	stencilDesc.DepthWriteMask = D3D11_DEPTH_WRITE_MASK_ZERO;
	stencilDesc.StencilEnable = false;
	stencilDesc.StencilReadMask = UINT8(0xFF);
	stencilDesc.StencilWriteMask = 0x0;
	pDevice_Game->CreateDepthStencilState(&stencilDesc, &myDepthStencilStates[static_cast<int>(eDepthState::NO_READ_NO_WRITE)]);

	//READ_NO_WRITE
	stencilDesc.DepthEnable = true;
	stencilDesc.DepthWriteMask = D3D11_DEPTH_WRITE_MASK_ALL;
	stencilDesc.DepthFunc = D3D11_COMPARISON_GREATER_EQUAL;
	stencilDesc.StencilEnable = false;
	stencilDesc.StencilReadMask = UINT8(0xFF);
	stencilDesc.StencilWriteMask = 0x0;

	stencilDesc.FrontFace.StencilFailOp = D3D11_STENCIL_OP_ZERO;
	stencilDesc.FrontFace.StencilDepthFailOp = D3D11_STENCIL_OP_ZERO;
	stencilDesc.FrontFace.StencilPassOp = D3D11_STENCIL_OP_KEEP;
	stencilDesc.FrontFace.StencilFunc = D3D11_COMPARISON_EQUAL;

	stencilDesc.BackFace.StencilFailOp = D3D11_STENCIL_OP_ZERO;
	stencilDesc.BackFace.StencilDepthFailOp = D3D11_STENCIL_OP_ZERO;
	stencilDesc.BackFace.StencilPassOp = D3D11_STENCIL_OP_ZERO;
	stencilDesc.BackFace.StencilFunc = D3D11_COMPARISON_NEVER;
	pDevice_Game->CreateDepthStencilState(&stencilDesc, &myDepthStencilStates[static_cast<int>(eDepthState::READ_NO_WRITE)]);

	printf("��info����Ȼ���ģ���ʼ�����... \n");
}

LRESULT CALLBACK DXGIMsgProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) { return DefWindowProc(hwnd, uMsg, wParam, lParam); }

void WallHack_Hook()
{
	ID3D11Device* pDevice;
	ID3D11DeviceContext* pContext;
	IDXGISwapChain* pSwapChain;

	//�Խ����������ڴ���������
	WNDCLASSEXA wc = { sizeof(WNDCLASSEX), CS_CLASSDC, DXGIMsgProc, 0L, 0L, GetModuleHandleA(NULL), NULL, NULL, NULL, NULL, "DX", NULL };
	RegisterClassExA(&wc);
	HWND hWnd = CreateWindowA("DX", NULL, WS_OVERLAPPEDWINDOW, 100, 100, 300, 300, NULL, NULL, wc.hInstance, NULL);

	//���������������ڻ�ȡ������и������ĵ�ַ����Hook
	DXGI_SWAP_CHAIN_DESC scd;
	ZeroMemory(&scd, sizeof(DXGI_SWAP_CHAIN_DESC));   //���0
	scd.BufferCount = 1;                              //����ֻ����һ���󻺳壨˫���壩���Ϊ1
	scd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;  //������ɫ��ʽ,����ʹ��RGBA
	scd.BufferDesc.Scaling = DXGI_MODE_SCALING_UNSPECIFIED;  //���ű�
	scd.BufferDesc.ScanlineOrdering = DXGI_MODE_SCANLINE_ORDER_UNSPECIFIED; //ɨ����
	scd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;  //��ȾĿ�����
	scd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH; //����ģʽ�л�
	scd.OutputWindow = hWnd;  //����Ϸ�����ڲ���������һ������
	scd.SampleDesc.Count = 1;                      //1�ز���
	scd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;      //���ò���
	scd.Windowed = ((GetWindowLongPtr(hWnd, GWL_STYLE) & WS_POPUP) != 0) ? false : true;  //�Ƿ�ȫ��
	scd.BufferDesc.Width = 1920;
	scd.BufferDesc.Height = 1080;
	scd.BufferDesc.RefreshRate.Numerator = 144;     //ˢ����
	scd.BufferDesc.RefreshRate.Denominator = 1;     //��ĸ
	scd.SampleDesc.Quality = 0;                     //�����ȼ�
	D3D_FEATURE_LEVEL featrueLevel = D3D_FEATURE_LEVEL_11_0;
	D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, NULL, &featrueLevel, 1, D3D11_SDK_VERSION, &scd, &pSwapChain, &pDevice, NULL, &pContext);

	//Present()
	//ͨ������������麯��Presentʱ��
	//00007FF673951D5C 48 8B 45 48       mov         rax, qword ptr[pSwapChain] ;rax��š�����������ĵ�ַ��
	//00007FF673951D60 48 8B 00          mov         rax, qword ptr[rax]		;rax��š�����������ĵ�1����Ա��ֵ���������ĵ�ַ
	//00007FF673951D63 45 33 C0          xor         r8d, r8d					;r8d ����3
	//00007FF673951D66 33 D2             xor         edx, edx					;edx ����2
	//00007FF673951D68 48 8B 4D 48       mov         rcx, qword ptr[pSwapChain]	;rcx ����1 ���ݶ���ָ�롾����������ĵ�ַ��
	//00007FF673951D6C FF 50 40          call        qword ptr[rax + 40h]		;CALL���ǽ���������40h/8h-1=7h����Ա����
	DWORD64* dwPSwapChain = (DWORD64*)pSwapChain;						//תΪָ��
	DWORD64 pSwapChainVT = *dwPSwapChain;								//�õ����ĵ�ַ
	DWORD64 pPresent = *(DWORD64*)((BYTE*)pSwapChainVT + 0x8 * 0x8);	//�õ�����7h����Ա�����ĵ�ַ

	//DrawIndexed()
	//ͨ������������麯��DrawIndexedʱ��
	//00007FF7F79C1E0F 48 8B 05 3A 45 01 00 mov         rax, qword ptr[pContext];rax��š������Ķ���ĵ�ַ��
	//00007FF7F79C1E16 48 8B 00             mov         rax, qword ptr[rax]		;rax��š������Ķ����һ����Ա��ֵ���������ĵ�ַ
	//00007FF7F79C1E19 45 33 C9             xor         r9d, r9d				;r9d ����4
	//00007FF7F79C1E1C 45 33 C0             xor         r8d, r8d				;r8d ����3
	//00007FF7F79C1E1F BA 24 00 00 00       mov         edx, 24h				;edx ����2 
	//00007FF7F79C1E24 48 8B 0D 25 45 01 00 mov         rcx, qword ptr[pContext];rcx ����1 ��š������Ķ���ĵ�ַ��
	//00007FF7F79C1E2B FF 50 60             call        qword ptr[rax + 60h]	;CALL���������Ķ�������60h/8h-1=Bh����Ա����
	DWORD64* dwPContext = (DWORD64*)pContext;							//תΪָ��
	DWORD64 pContextVT = *dwPContext;									//�õ����ĵ�ַ
	DWORD64 pDrawIndexed = *(DWORD64*)((BYTE*)pContextVT + 0xC * 0x8);	//�õ�����Bh����Ա�����ĵ�ַ

	//CreateQuery()
	//	00007FF6228167C4 48 8B 45 08		  mov         rax, qword ptr[pDevice]
	//	00007FF6228167C8 48 8B 00             mov         rax, qword ptr[rax]
	//	00007FF6228167CB 45 33 C0             xor         r8d, r8d					//����3 r8
	//	00007FF6228167CE 33 D2                xor         edx, edx					//����2 rdx
	//	00007FF6228167D0 48 8B 4D 08          mov         rcx, qword ptr[pDevice]   //����1 rcx ����ָ��
	//	00007FF6228167D4 FF 90 C0 00 00 00    call        qword ptr[rax + 0C0h]
	DWORD64* dwPDevice = (DWORD64*)pDevice;								//תΪָ��
	DWORD64 pDeviceVT = *dwPDevice;										//�õ����ĵ�ַ
	DWORD64 pCreateQuery = *(DWORD64*)((BYTE*)pDeviceVT + 0x18 * 0x8);	//�õ�����Ա�����ĵ�ַ


	//PSSetShaderResources()
	//	00007FF785312A71 48 8B 45 28          mov         rax, qword ptr[pContext]
	//	00007FF785312A75 48 8B 00             mov         rax, qword ptr[rax]
	//	00007FF785312A78 45 33 C9             xor         r9d, r9d					//����4 r9
	//	00007FF785312A7B 45 33 C0             xor         r8d, r8d					//����3 r8
	//	00007FF785312A7E 33 D2                xor         edx, edx					//����2 rdx
	//	00007FF785312A80 48 8B 4D 28          mov         rcx, qword ptr[pContext]	//����1 rcx ����ָ��
	//	00007FF785312A84 FF 50 40             call        qword ptr[rax + 40h]
	DWORD64 pPSSetShaderResources = *(DWORD64*)((BYTE*)pContextVT + 0x8 * 0x8);

	//GetThreadContext()
	DWORD64 real_GetThreadContext = (DWORD64)GetThreadContext;
	if (((*(DWORD*)real_GetThreadContext) & 0x00FFFFFF) == 0x25FF48)
	{//��鱻�ҹ�������ǰ3�ֽ��Ƿ�Ϊ0x25FF48��������JMPһ�βŵ��ﺯ���壩
		DWORD originFunc_opcode = *(DWORD*)(real_GetThreadContext + 0x3);
		DWORD64* originFunc_realAddr_saveWhere = (DWORD64*)(originFunc_opcode + (real_GetThreadContext + 0x3 + 0x4));
		real_GetThreadContext = *originFunc_realAddr_saveWhere;
		//printf("��info������ǰ���ֽ�Ϊ[48 FF 25] ���������תһ�βŵ��ﺯ���壬������ĵ�ַ=%p \n", real_GetThreadContext);
	}

	//IsDebuggerPresent()
	DWORD64 real_IsDebuggerPresent = (DWORD64)IsDebuggerPresent;
	if (((*(DWORD*)real_IsDebuggerPresent) & 0x00FFFFFF) == 0x25FF48)
	{	//��鱻�ҹ�������ǰ3�ֽ��Ƿ�Ϊ0x25FF48��������JMPһ�βŵ��ﺯ���壩
		DWORD originFunc_opcode = *(DWORD*)(real_IsDebuggerPresent + 0x3);
		DWORD64* originFunc_realAddr_saveWhere = (DWORD64*)(originFunc_opcode + (real_IsDebuggerPresent + 0x3 + 0x4));
		real_IsDebuggerPresent = *originFunc_realAddr_saveWhere;
		//printf("��info������ǰ���ֽ�Ϊ[48 FF 25] ���������תһ�βŵ��ﺯ���壬������ĵ�ַ=%p \n", real_IsDebuggerPresent);
	}

	//Inline Hook
	//InlineHook_X64((DWORD64)pPresent, 19, (DWORD64)InlineHook_X64_MyPresent, InlineHook_X64_HandleCoverdCode_D3D11Present);
	//InlineHook_X64((DWORD64)pDrawIndexed, 19, (DWORD64)InlineHook_X64_MyDrawIndexed, InlineHook_X64_HandleCoverdCode_D3D11DrawIndexed);
	//InlineHook_X64((DWORD64)pCreateQuery, 19, (DWORD64)InlineHook_X64_MyCreateQuery, InlineHook_X64_HandleCoverdCode_D3D11CreateQuery);
	//InlineHook_X64((DWORD64)GetThreadContext, 18, (DWORD64)InlineHook_X64_MyGetThreadContext, InlineHook_X64_HandleCoverdCode_GetThreadContext);

	//Ӳ�ϣ�VEH Hook
	HardwareBP((LPVOID)AddVectoredExceptionHandler, VEH_AddVectoredExceptionHandler, DRX::Dr0, 3).SetVEHHook(Ӳ��_��ִ��);
	HardwareBP((LPVOID)pPresent, VEH_D3D11Present, DRX::Dr1, 5).SetVEHHook(Ӳ��_��ִ��);
	HardwareBP((LPVOID)pDrawIndexed, VEH_D3D11DrawIndexed, DRX::Dr2, 4).SetVEHHook(Ӳ��_��ִ��);
	HardwareBP((LPVOID)pCreateQuery, VEH_CreateQuery, DRX::Dr3, 4).SetVEHHook(Ӳ��_��ִ��);
	//HardwareBP((LPVOID)real_GetThreadContext, VEH_GetThreadContext, DRX::Dr3, 3).SetVEHHook(Ӳ��_��ִ��);
	//HardwareBP((LPVOID)real_IsDebuggerPresent, VEH_IsDebuggerPresent, DRX::Dr3, 9).SetVEHHook(Ӳ��_��ִ��);

}

//͸�ӣ��ҵ�DrawIndexed����
BOOL WallHack_MyDrawIndexed(LPVOID pFirstCode, ID3D11DeviceContext* pContext, UINT IndexCount, UINT StartIndexLocation, UINT BaseVertexLocation)
{
	//��ȡ����.
	pContext->IAGetVertexBuffers(0, 1, &veBuffer, &stride, &veBufferOffset);//��ȡ���㻺��������ȡstride�� (������ÿ����ռ�õ��ֽ���)
	pContext->IAGetIndexBuffer(&inBuffer, &inFormat, &inOffset);			//��ȡ����������
	veBuffer->GetDesc(&vedesc);
	inBuffer->GetDesc(&indesc);
	veBuffer->Release();
	inBuffer->Release();
	veBuffer = __nullptr;
	inBuffer = __nullptr;

	if (GetAsyncKeyState(VK_F5) & 0x1)
	{
		START_WallHack = TRUE;
		printf("[ F5 ]����͸��... \n");

	}
	if (GetAsyncKeyState(VK_F6) & 0x1)
	{
		START_WallHack = FALSE;
		printf("[ F6 ]�ر�͸��... \n");
	}

	//�����ģ�� stride=20  
	if (stride == 20 && START_WallHack)
	{
		//�ų�����Ҫ͸�ӵĶ���
		if (indesc.ByteWidth == 102924
			|| indesc.ByteWidth == 31488
			|| indesc.ByteWidth == 130428
			|| indesc.ByteWidth == 64104
			|| indesc.ByteWidth == 85494
			|| indesc.ByteWidth == 96450
			|| indesc.ByteWidth == 112254
			|| indesc.ByteWidth == 37764
			|| indesc.ByteWidth == 128094
			|| indesc.ByteWidth == 4176
			|| indesc.ByteWidth == 49440
			|| indesc.ByteWidth == 111300
			|| indesc.ByteWidth == 130374
			|| indesc.ByteWidth == 62178
			|| indesc.ByteWidth == 71658
			|| indesc.ByteWidth == 35304
			|| indesc.ByteWidth == 34524
			|| indesc.ByteWidth == 81276
			|| indesc.ByteWidth == 80268
			|| indesc.ByteWidth == 56712
			|| indesc.ByteWidth == 113724
			|| indesc.ByteWidth == 126882
			|| indesc.ByteWidth == 48384
			|| indesc.ByteWidth == 64224
			|| indesc.ByteWidth == 30240	//��������
			|| indesc.ByteWidth == 8688		//����ɯ��

			)
		{
			//�ָ�ִ��ԭ����
			return TRUE;
		}
		//��ɫ��͸��
		//pContext->PSSetShader(psRed, NULL, NULL);
		//SetDepthStencilState(DISABLED);
		//ASM_Fake_DrwaIndexed(pContext, IndexCount, StartIndexLocation, BaseVertexLocation, (DWORD64)g_DrxVEHHook_D3D11DrawIndexed.pFirstCode);
		//SetDepthStencilState(READ_NO_WRITE);
		//pContext->PSSetShader(psGreen, NULL, NULL);
		//return FALSE;//��ֹԭ����

		//����ɫ��͸��
		SetDepthStencilState(DISABLED);
		ASM_Fake_DrwaIndexed(pContext, IndexCount, StartIndexLocation, BaseVertexLocation, (DWORD64)pFirstCode);
		SetDepthStencilState(ENABLED);
		return TRUE;//�ָ�ִ��ԭ������������Ⱦһ�Σ�
	}
	//�ָ�ִ��ԭ����
	return TRUE;
}