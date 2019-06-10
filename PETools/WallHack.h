#pragma once
#include"pch.h"

//枚举：深度缓冲模板
enum eDepthState
{
	ENABLED,
	DISABLED,
	READ_NO_WRITE,
	NO_READ_NO_WRITE,
	_DEPTH_COUNT
};
extern ID3D11DepthStencilState* myDepthStencilStates[static_cast<int>(eDepthState::_DEPTH_COUNT)];

//声明:全局变量
extern BOOL START_WallHack;
extern BOOL ISFIRST_PRESENT;
extern IDXGISwapChain* pSwapChain_Game;
extern ID3D11Device*  pDevice_Game;
extern ID3D11DeviceContext* pContext_Game;
extern ID3D11RenderTargetView * pRenderTargetView_Game;
extern ID3D11PixelShader* psRed ;
extern ID3D11PixelShader* psGreen ;
//vertex
extern ID3D11Buffer *veBuffer;
extern UINT stride;
extern UINT veBufferOffset;
extern D3D11_BUFFER_DESC vedesc;
//index
extern ID3D11Buffer *inBuffer;
extern DXGI_FORMAT inFormat;
extern UINT        inOffset;
extern D3D11_BUFFER_DESC indesc;

extern int Ban_Stride;	//要过滤的步长数
extern int Ban_Index;	//要过滤的索引数
extern int Ban_ByteWidth;

BOOL WallHack_MyDrawIndexed(LPVOID pFirstCode, ID3D11DeviceContext* pContext, UINT IndexCount, UINT StartIndexLocation, UINT BaseVertexLocation);//新的，用于封装后的VEH HOOK
BOOL WallHack_MyPresent(IDXGISwapChain* pSwapChain, UINT SyscInterval, UINT Flags);

VOID InitDEPTHSTENCIL();
VOID SetDepthStencilState(eDepthState aState);
HRESULT GenerateShader(ID3D11Device* pD3DDevice, ID3D11PixelShader** pShader, float r, float g, float b);
void WallHack_Hook();