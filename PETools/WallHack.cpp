#include "pch.h"
#include <iostream>

//定义全局变量：开关控制
BOOL START_WallHack = FALSE;
BOOL ISFIRST_PRESENT = TRUE;

//定义全局变量：D3D11对象
IDXGISwapChain* pSwapChain_Game = 0;
ID3D11Device* pDevice_Game = 0;
ID3D11DeviceContext* pContext_Game = 0;
ID3D11RenderTargetView* pRenderTargetView_Game = 0;
ID3D11DepthStencilState* myDepthStencilStates[static_cast<int>(eDepthState::_DEPTH_COUNT)];
ID3D11PixelShader* psRed = NULL;
ID3D11PixelShader* psGreen = NULL;

//定义全局变量：vertex
ID3D11Buffer* veBuffer;
UINT stride = 0;
UINT veBufferOffset = 0;
D3D11_BUFFER_DESC vedesc;

//定义全局变量：index
ID3D11Buffer* inBuffer;
DXGI_FORMAT inFormat;
UINT        inOffset;
D3D11_BUFFER_DESC indesc;

//定义全局变量：过滤测试相关
int Ban_Stride = 0;	//要过滤的步长数
int Ban_Index = 0;	//要过滤的索引数
int Ban_ByteWidth = 0;

//透视：我的Present函数
BOOL WallHack_MyPresent(IDXGISwapChain* pSwapChain, UINT SyscInterval, UINT Flags)
{
	if (ISFIRST_PRESENT)
	{
		ISFIRST_PRESENT = FALSE;
		printf("【info-D3D】第1次进入Present()...游戏交换链pSwapChain=%llx，尝试获取设备指针...", pSwapChain_Game);
		//根据游戏的交换链获取游戏的设备指针
		if (SUCCEEDED(pSwapChain_Game->GetDevice(__uuidof(ID3D11Device), (void**)(&pDevice_Game))))
		{
			pSwapChain_Game->GetDevice(__uuidof(pDevice_Game), (void**)(&pDevice_Game));
			pDevice_Game->GetImmediateContext(&pContext_Game);
			printf("pDevice=%llx \n", pDevice_Game);
		}
		//初始化深度缓冲模板
		InitDEPTHSTENCIL();
		//初始化我的着色器
		//if (!psRed)GenerateShader(pDevice_Game, &psRed, 1.0f, 0.0f, 0.0f);
		//if (!psGreen)GenerateShader(pDevice_Game, &psGreen, 0.0f, 1.0f, 0.0f);
		return TRUE;
	}
	return FALSE;
}

//生成像素渲染器
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

//设置深度缓冲模板
void SetDepthStencilState(eDepthState aState)
{
	//当present获取到上下文后再允许设置深度测试模板
	if (pContext_Game == 0x0) { return; }
	pContext_Game->OMSetDepthStencilState(myDepthStencilStates[aState], 1);

}

//初始化深度测试模板
VOID InitDEPTHSTENCIL()
{
	//--------------------------------------------
	D3D11_DEPTH_STENCIL_DESC  stencilDesc;
	stencilDesc.DepthFunc = D3D11_COMPARISON_LESS;
	stencilDesc.StencilEnable = true;// 是否开启模板测试 stencil test
	stencilDesc.StencilReadMask = 0xFF; // 模板值写入掩码 The StencilReadMask used in the stencil test:
	stencilDesc.StencilWriteMask = 0xFF;// 模板值读取掩码
	// 对正面朝向的三角形进行深度/模板操作描述
	stencilDesc.FrontFace.StencilFailOp = D3D11_STENCIL_OP_KEEP;		//保持目标模板值不变
	stencilDesc.FrontFace.StencilDepthFailOp = D3D11_STENCIL_OP_INCR;	//保持目标模板值为0
	stencilDesc.FrontFace.StencilPassOp = D3D11_STENCIL_OP_KEEP;
	stencilDesc.FrontFace.StencilFunc = D3D11_COMPARISON_ALWAYS;
	// 对背面朝向的三角形进行深度/模板操作的描述
	stencilDesc.BackFace.StencilFailOp = D3D11_STENCIL_OP_KEEP;
	stencilDesc.BackFace.StencilDepthFailOp = D3D11_STENCIL_OP_DECR;
	stencilDesc.BackFace.StencilPassOp = D3D11_STENCIL_OP_KEEP;
	stencilDesc.BackFace.StencilFunc = D3D11_COMPARISON_ALWAYS;

	//ENABLED
	stencilDesc.DepthEnable = true; // 是否开启深度测试
	stencilDesc.DepthWriteMask = D3D11_DEPTH_WRITE_MASK_ALL; // 深度值写入掩码
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

	printf("【info】深度缓冲模板初始化完成... \n");
}

LRESULT CALLBACK DXGIMsgProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) { return DefWindowProc(hwnd, uMsg, wParam, lParam); }

void WallHack_Hook()
{
	ID3D11Device* pDevice;
	ID3D11DeviceContext* pContext;
	IDXGISwapChain* pSwapChain;

	//自建个窗口用于创建交换链
	WNDCLASSEXA wc = { sizeof(WNDCLASSEX), CS_CLASSDC, DXGIMsgProc, 0L, 0L, GetModuleHandleA(NULL), NULL, NULL, NULL, NULL, "DX", NULL };
	RegisterClassExA(&wc);
	HWND hWnd = CreateWindowA("DX", NULL, WS_OVERLAPPEDWINDOW, 100, 100, 300, 300, NULL, NULL, wc.hInstance, NULL);

	//创建交换链，用于获取各虚表中各函数的地址而从Hook
	DXGI_SWAP_CHAIN_DESC scd;
	ZeroMemory(&scd, sizeof(DXGI_SWAP_CHAIN_DESC));   //填充0
	scd.BufferCount = 1;                              //我们只创建一个后缓冲（双缓冲）因此为1
	scd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;  //设置颜色格式,我们使用RGBA
	scd.BufferDesc.Scaling = DXGI_MODE_SCALING_UNSPECIFIED;  //缩放比
	scd.BufferDesc.ScanlineOrdering = DXGI_MODE_SCANLINE_ORDER_UNSPECIFIED; //扫描线
	scd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;  //渲染目标输出
	scd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH; //允许模式切换
	scd.OutputWindow = hWnd;  //在游戏窗体内部绘制另外一个窗口
	scd.SampleDesc.Count = 1;                      //1重采样
	scd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;      //常用参数
	scd.Windowed = ((GetWindowLongPtr(hWnd, GWL_STYLE) & WS_POPUP) != 0) ? false : true;  //是否全屏
	scd.BufferDesc.Width = 1920;
	scd.BufferDesc.Height = 1080;
	scd.BufferDesc.RefreshRate.Numerator = 144;     //刷新率
	scd.BufferDesc.RefreshRate.Denominator = 1;     //分母
	scd.SampleDesc.Quality = 0;                     //采样等级
	D3D_FEATURE_LEVEL featrueLevel = D3D_FEATURE_LEVEL_11_0;
	D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, NULL, &featrueLevel, 1, D3D11_SDK_VERSION, &scd, &pSwapChain, &pDevice, NULL, &pContext);

	//Present()
	//通过对象调用其虚函数Present时：
	//00007FF673951D5C 48 8B 45 48       mov         rax, qword ptr[pSwapChain] ;rax存放【交换链对象的地址】
	//00007FF673951D60 48 8B 00          mov         rax, qword ptr[rax]		;rax存放【交换链对象的第1个成员的值】，即虚表的地址
	//00007FF673951D63 45 33 C0          xor         r8d, r8d					;r8d 参数3
	//00007FF673951D66 33 D2             xor         edx, edx					;edx 参数2
	//00007FF673951D68 48 8B 4D 48       mov         rcx, qword ptr[pSwapChain]	;rcx 参数1 传递对象指针【交换链对象的地址】
	//00007FF673951D6C FF 50 40          call        qword ptr[rax + 40h]		;CALL的是交换链虚表第40h/8h-1=7h个成员函数
	DWORD64* dwPSwapChain = (DWORD64*)pSwapChain;						//转为指针
	DWORD64 pSwapChainVT = *dwPSwapChain;								//得到虚表的地址
	DWORD64 pPresent = *(DWORD64*)((BYTE*)pSwapChainVT + 0x8 * 0x8);	//得到虚表第7h个成员函数的地址

	//DrawIndexed()
	//通过对象调用其虚函数DrawIndexed时：
	//00007FF7F79C1E0F 48 8B 05 3A 45 01 00 mov         rax, qword ptr[pContext];rax存放【上下文对象的地址】
	//00007FF7F79C1E16 48 8B 00             mov         rax, qword ptr[rax]		;rax存放【上下文对象第一个成员的值】，即虚表的地址
	//00007FF7F79C1E19 45 33 C9             xor         r9d, r9d				;r9d 参数4
	//00007FF7F79C1E1C 45 33 C0             xor         r8d, r8d				;r8d 参数3
	//00007FF7F79C1E1F BA 24 00 00 00       mov         edx, 24h				;edx 参数2 
	//00007FF7F79C1E24 48 8B 0D 25 45 01 00 mov         rcx, qword ptr[pContext];rcx 参数1 存放【上下文对象的地址】
	//00007FF7F79C1E2B FF 50 60             call        qword ptr[rax + 60h]	;CALL的是上下文对象虚表第60h/8h-1=Bh个成员函数
	DWORD64* dwPContext = (DWORD64*)pContext;							//转为指针
	DWORD64 pContextVT = *dwPContext;									//得到虚表的地址
	DWORD64 pDrawIndexed = *(DWORD64*)((BYTE*)pContextVT + 0xC * 0x8);	//得到虚表第Bh个成员函数的地址

	//CreateQuery()
	//	00007FF6228167C4 48 8B 45 08		  mov         rax, qword ptr[pDevice]
	//	00007FF6228167C8 48 8B 00             mov         rax, qword ptr[rax]
	//	00007FF6228167CB 45 33 C0             xor         r8d, r8d					//参数3 r8
	//	00007FF6228167CE 33 D2                xor         edx, edx					//参数2 rdx
	//	00007FF6228167D0 48 8B 4D 08          mov         rcx, qword ptr[pDevice]   //参数1 rcx 对象指针
	//	00007FF6228167D4 FF 90 C0 00 00 00    call        qword ptr[rax + 0C0h]
	DWORD64* dwPDevice = (DWORD64*)pDevice;								//转为指针
	DWORD64 pDeviceVT = *dwPDevice;										//得到虚表的地址
	DWORD64 pCreateQuery = *(DWORD64*)((BYTE*)pDeviceVT + 0x18 * 0x8);	//得到虚表成员函数的地址


	//PSSetShaderResources()
	//	00007FF785312A71 48 8B 45 28          mov         rax, qword ptr[pContext]
	//	00007FF785312A75 48 8B 00             mov         rax, qword ptr[rax]
	//	00007FF785312A78 45 33 C9             xor         r9d, r9d					//参数4 r9
	//	00007FF785312A7B 45 33 C0             xor         r8d, r8d					//参数3 r8
	//	00007FF785312A7E 33 D2                xor         edx, edx					//参数2 rdx
	//	00007FF785312A80 48 8B 4D 28          mov         rcx, qword ptr[pContext]	//参数1 rcx 对象指针
	//	00007FF785312A84 FF 50 40             call        qword ptr[rax + 40h]
	DWORD64 pPSSetShaderResources = *(DWORD64*)((BYTE*)pContextVT + 0x8 * 0x8);

	//GetThreadContext()
	DWORD64 real_GetThreadContext = (DWORD64)GetThreadContext;
	if (((*(DWORD*)real_GetThreadContext) & 0x00FFFFFF) == 0x25FF48)
	{//检查被挂钩函数的前3字节是否为0x25FF48（即额外JMP一次才到达函数体）
		DWORD originFunc_opcode = *(DWORD*)(real_GetThreadContext + 0x3);
		DWORD64* originFunc_realAddr_saveWhere = (DWORD64*)(originFunc_opcode + (real_GetThreadContext + 0x3 + 0x4));
		real_GetThreadContext = *originFunc_realAddr_saveWhere;
		//printf("【info】函数前三字节为[48 FF 25] ，需额外跳转一次才到达函数体，修正后的地址=%p \n", real_GetThreadContext);
	}

	//IsDebuggerPresent()
	DWORD64 real_IsDebuggerPresent = (DWORD64)IsDebuggerPresent;
	if (((*(DWORD*)real_IsDebuggerPresent) & 0x00FFFFFF) == 0x25FF48)
	{	//检查被挂钩函数的前3字节是否为0x25FF48（即额外JMP一次才到达函数体）
		DWORD originFunc_opcode = *(DWORD*)(real_IsDebuggerPresent + 0x3);
		DWORD64* originFunc_realAddr_saveWhere = (DWORD64*)(originFunc_opcode + (real_IsDebuggerPresent + 0x3 + 0x4));
		real_IsDebuggerPresent = *originFunc_realAddr_saveWhere;
		//printf("【info】函数前三字节为[48 FF 25] ，需额外跳转一次才到达函数体，修正后的地址=%p \n", real_IsDebuggerPresent);
	}

	//Inline Hook
	//InlineHook_X64((DWORD64)pPresent, 19, (DWORD64)InlineHook_X64_MyPresent, InlineHook_X64_HandleCoverdCode_D3D11Present);
	//InlineHook_X64((DWORD64)pDrawIndexed, 19, (DWORD64)InlineHook_X64_MyDrawIndexed, InlineHook_X64_HandleCoverdCode_D3D11DrawIndexed);
	//InlineHook_X64((DWORD64)pCreateQuery, 19, (DWORD64)InlineHook_X64_MyCreateQuery, InlineHook_X64_HandleCoverdCode_D3D11CreateQuery);
	//InlineHook_X64((DWORD64)GetThreadContext, 18, (DWORD64)InlineHook_X64_MyGetThreadContext, InlineHook_X64_HandleCoverdCode_GetThreadContext);

	//硬断：VEH Hook
	HardwareBP((LPVOID)AddVectoredExceptionHandler, VEH_AddVectoredExceptionHandler, DRX::Dr0, 3).SetVEHHook(硬断_仅执行);
	HardwareBP((LPVOID)pPresent, VEH_D3D11Present, DRX::Dr1, 5).SetVEHHook(硬断_仅执行);
	HardwareBP((LPVOID)pDrawIndexed, VEH_D3D11DrawIndexed, DRX::Dr2, 4).SetVEHHook(硬断_仅执行);
	HardwareBP((LPVOID)pCreateQuery, VEH_CreateQuery, DRX::Dr3, 4).SetVEHHook(硬断_仅执行);
	//HardwareBP((LPVOID)real_GetThreadContext, VEH_GetThreadContext, DRX::Dr3, 3).SetVEHHook(硬断_仅执行);
	//HardwareBP((LPVOID)real_IsDebuggerPresent, VEH_IsDebuggerPresent, DRX::Dr3, 9).SetVEHHook(硬断_仅执行);

}

//透视：我的DrawIndexed函数
BOOL WallHack_MyDrawIndexed(LPVOID pFirstCode, ID3D11DeviceContext* pContext, UINT IndexCount, UINT StartIndexLocation, UINT BaseVertexLocation)
{
	//获取数据.
	pContext->IAGetVertexBuffers(0, 1, &veBuffer, &stride, &veBufferOffset);//获取顶点缓冲区、获取stride数 (步长，每像素占用的字节数)
	pContext->IAGetIndexBuffer(&inBuffer, &inFormat, &inOffset);			//获取索引缓冲区
	veBuffer->GetDesc(&vedesc);
	inBuffer->GetDesc(&indesc);
	veBuffer->Release();
	inBuffer->Release();
	veBuffer = __nullptr;
	inBuffer = __nullptr;

	if (GetAsyncKeyState(VK_F5) & 0x1)
	{
		START_WallHack = TRUE;
		printf("[ F5 ]开启透视... \n");

	}
	if (GetAsyncKeyState(VK_F6) & 0x1)
	{
		START_WallHack = FALSE;
		printf("[ F6 ]关闭透视... \n");
	}

	//人物等模型 stride=20  
	if (stride == 20 && START_WallHack)
	{
		//排除不需要透视的东西
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
			|| indesc.ByteWidth == 30240	//猩猩罩子
			|| indesc.ByteWidth == 8688		//奥丽莎盾

			)
		{
			//恢复执行原函数
			return TRUE;
		}
		//上色的透视
		//pContext->PSSetShader(psRed, NULL, NULL);
		//SetDepthStencilState(DISABLED);
		//ASM_Fake_DrwaIndexed(pContext, IndexCount, StartIndexLocation, BaseVertexLocation, (DWORD64)g_DrxVEHHook_D3D11DrawIndexed.pFirstCode);
		//SetDepthStencilState(READ_NO_WRITE);
		//pContext->PSSetShader(psGreen, NULL, NULL);
		//return FALSE;//终止原函数

		//不上色的透视
		SetDepthStencilState(DISABLED);
		ASM_Fake_DrwaIndexed(pContext, IndexCount, StartIndexLocation, BaseVertexLocation, (DWORD64)pFirstCode);
		SetDepthStencilState(ENABLED);
		return TRUE;//恢复执行原函数（即再渲染一次）
	}
	//恢复执行原函数
	return TRUE;
}