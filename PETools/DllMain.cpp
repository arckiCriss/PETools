#include "pch.h"

// <summary>
//	����һ��DLL��ʼ������
// </summary>
// <param name="lpThreadParameter"></param>
DWORD WINAPI InitDLL(LPVOID lpThreadParameter)
{
#if _DEBUG
	//��������̨
	AllocConsole();
	freopen("conout$", "w", stdout);
#endif
	//Malware

	//WallHack_Hook();
	//NamedPipe().OnClient();

	return 0;
}
//DLL����ں���
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	HANDLE hThread = 0;
	switch (ul_reason_for_call)
	{
		//��DLL�����̵�һ�μ���ʱ
		case DLL_PROCESS_ATTACH:
			//hThread = CreateThread(NULL, 0, InitDLL, NULL, 0, NULL); break;	//��Ŀ������п���һ���߳�
		//��������ֹʱ
		case DLL_PROCESS_DETACH:break;

		default:
			break;
	}
	return TRUE;
}