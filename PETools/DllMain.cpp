#include "pch.h"

// <summary>
//	定义一个DLL初始化函数
// </summary>
// <param name="lpThreadParameter"></param>
DWORD WINAPI InitDLL(LPVOID lpThreadParameter)
{
#if _DEBUG
	//创建控制台
	AllocConsole();
	freopen("conout$", "w", stdout);
#endif
	//Malware

	//WallHack_Hook();
	//NamedPipe().OnClient();

	return 0;
}
//DLL的入口函数
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	HANDLE hThread = 0;
	switch (ul_reason_for_call)
	{
		//当DLL被进程第一次加载时
		case DLL_PROCESS_ATTACH:
			//hThread = CreateThread(NULL, 0, InitDLL, NULL, 0, NULL); break;	//在目标进程中开启一个线程
		//当进程终止时
		case DLL_PROCESS_DETACH:break;

		default:
			break;
	}
	return TRUE;
}