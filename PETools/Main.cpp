#include "pch.h"

//在分线程中挂起主线程，然后为主线程设置硬件断点
DWORD WINAPI TestDrxVEHHook(LPVOID lpThreadParameter)
{
	return 0;
}



int main()
{

	//测试1：PETools相关函数
	//PBYTE pFileBuffer = 0;
	//PBYTE pNewFileBuffer = 0;
	//PBYTE pImageBuffer = 0;
	//PEHEADER PEHeader = { 0 };
	//PEBODY PEBody = { 0 };
	//int fileLen = LoadFileBuffer("C:\\Users\\41388\\Desktop\\ColorPix_CHS.exe", &pFileBuffer);
	//AnalyzePE_ByFileBuffer(pFileBuffer, &PEHeader, &PEBody);
	//LoadImageBuffer(pFileBuffer, &pImageBuffer, PEHeader);
	//BackToFileBuffer(pImageBuffer, PEHeader, fileLen, &pNewFileBuffer);
	//SaveFile("C:\\Users\\41388\\Desktop\\newFile.exe", fileLen, pNewFileBuffer);
	//HANDLE hDestProcess = OpenProcessByName("StudyPE+ x64.exe", PROCESS_ALL_ACCESS);

	//测试2：远程线程注入		注入守望先锋成功，注入win10计算器时线程阻塞
	//RemoteThreadInject("Overwatch.exe", "C:\\Users\\41388\\source\\repos\\PETools\\x64\\Debug\\PETools.dll");
	//RemoteThreadInject("Overwatch.exe", "C:\\Users\\41388\\source\\repos\\PETools\\x64\\Release\\PETools.dll");
	//RemoteThreadInject("Welcome to Princeland.exe", "C:\\Users\\41388\\source\\repos\\PETools\\x64\\Debug\\PETools.dll");
	//RemoteThreadInject("Syndrome.exe", "C:\\Users\\41388\\source\\repos\\PETools\\x64\\Debug\\PETools.dll");

	//测试3：反射式注入
	//ReflectInject_EXE("StudyPE+ x64.exe");			
	//ReflectInject_DLL_AntiDetect_20190606("StudyPE+ x64.exe");	
	//ReflectInject_DLL_AntiDetect_20190606("Overwatch.exe", "C:\\Users\\41388\\source\\repos\\PETools\\x64\\Debug\\PETools.dll");
	//ReflectInject_EXE_AntiDetect_20190606("StudyPE+ x64.exe"); 
	ReflectInject_EXE_AntiDetect_20190606("Overwatch.exe");	

	//测试6：INLINE HOOK
	//InlineHook("USER32.dll", "MessageBoxA", (DWORD64)InlineHook_MyMessageBoxA_X86, 5);
	//InlineHook_X64((DWORD64)MessageBox, 16, (DWORD64)InlineHook_X64_MyMessageBoxA, InlineHook_X64_HandleCoverdCode_MessageBoxA);
	//InlineHook_X64((DWORD64)VirtualProtect , 17, (DWORD64)InlineHook_X64_MyVirtualProtect, InlineHook_X64_HandleCoverdCode_VirtualProtect);
	//InlineHook_X64((DWORD64)GetThreadContext, 18, (DWORD64)InlineHook_X64_MyGetThreadContext, InlineHook_X64_HandleCoverdCode_GetThreadContext);
	//WaitForSingleObject(CreateThread(NULL, 0, TestCCC, NULL, NULL, NULL), INFINITE);

	//测试7：VEH HOOK (在分线程中挂起主线程，然后为主线程设置硬件断点,需不同线程，并等待硬件断点设置完毕)
	//WaitForSingleObject(CreateThread(NULL, 0, TestDrxVEHHook, NULL, NULL, NULL), INFINITE);
	//printf("");
	//test = 0x999;
	//printf("");
	//test = 0x999;

	//测试8:建立命名管道
	//NamedPipe().OnServer();


	getchar();
	return 0;
}

