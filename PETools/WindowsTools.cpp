#include "pch.h"


/**
 * �򿪽��̣�ͨ��������
 * ���� ProcessName	������
 * ���� needAccess	�Ժ���Ȩ�޴򿪽��� (eg: PROCESS_TERMINATE|PROCESS_VM_READ or PROCESS_ALL_ACCESS)
 */
HANDLE OpenProcessByName(const TCHAR* processName, DWORD ACCESS)
{
	//����CreatToolhelp32Snapshot����ȡ����,��THREADENTRY32����ȡ�߳���Ϣ��
	HANDLE hSnapshot;
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	//���������е�һ�����̵���Ϣ
	PROCESSENTRY32 *info;
	info = new PROCESSENTRY32;
	info->dwSize = sizeof(PROCESSENTRY32);
	Process32First(hSnapshot, info);
	while (Process32Next(hSnapshot, info) != FALSE)
	{
		info->szExeFile;
		if (strcmp(processName, info->szExeFile) == 0)
		{
			HANDLE hProcess = OpenProcess(ACCESS, FALSE, info->th32ProcessID);
			if (hProcess == 0x0)
			{
				printf("��error���򿪽���[%s]ʧ�� , ErrorCode = %d \n", processName, GetLastError());
				return 0;
			}
			CloseHandle(hSnapshot);
			printf("��info���ɹ���Ŀ�����[%s]... \n", processName);
			return hProcess;
		}
	}
	CloseHandle(hSnapshot);
	printf("��error��δ�ҵ�����[%s]... \n", processName);
	return 0;
}

// <summary>
// ��ʮ�����Ƶ���תΪͬ�����ַ���
// 0x66AA->'66AA'
// </summary>
// <param name="srcHex"></param>
CHAR* HexToStr(DWORD srcHex)
{
	//�������ֵ�λ��
	int digit;
	for (int i = 1; ; i++)
	{
		int quotient = srcHex / (pow(16, i));
		if (quotient < 16)
		{
			digit = quotient == 0 ? i : i + 1;
			break;
		}
	}
	//�����ڴ�й©�����⣺������char����
	CHAR* res = (CHAR*)malloc(digit + 1);
	//����
	memset(res, 0x0, digit + 1);
	//��λתΪ�ַ�������char����
	for (int i = digit - 1; i >= 0; i--)
	{
		//ʮ�����Ƶ�A~F��+0x37
		*(res + i) = srcHex % 16 + ((srcHex % 16) < 0xA ? 0x30 : 0x37);
		srcHex = srcHex / 16;
	}
	return res;
}
// <summary>
// ��ʮ���Ƶ���תΪͬ�����ַ���
// 1234->'1234'
// </summary>
// <param name="srcDec"></param>
CHAR* DecToStr(DWORD srcDec)
{
	//�������ֵ�λ��
	int digit;
	for (int i = 1; ; i++)
	{
		int quotient = srcDec / (pow(10, i));
		if (quotient < 10)
		{
			digit = quotient == 0 ? i : i + 1;
			break;
		}
	}
	//�����ڴ�й©�����⣺������char����
	CHAR* res = (CHAR*)malloc(digit + 1);
	//����
	memset(res, 0x0, digit + 1);
	//��λתΪ�ַ�������char����
	for (int i = digit - 1; i >= 0; i--)
	{
		*(res + i) = srcDec % 10 + 48;
		srcDec = srcDec / 10;
	}
	return res;
}
// <summary>
// ��ӡʮ����������hex��msg��OutputDebugString (���ֽڵ�hex��)
// </summary>
// <param name="msgStr"></param>
// <param name="hex"></param>
void ShowDbg(const char* msgStr, DWORD hex)
{
	//�ѳ����ַ���const char* תΪchar*���������㹻��  
	char res[100] = { 0 }; //�۲췴��������_memset������_memsetʵ������ת���ⲿDLL(vcruntime140.dll)��memset����,���ڷ���ʽע��ʱ���������޸�IAT��
	strcpy(res, msgStr);

	//��ʮ��������תΪ�ַ�����Ȼ��ƴ��
	strcat(res, HexToStr(hex));

	//��ӡ��debug
	OutputDebugString(res);
}

//����Ȩ��(�ù���ԱȨ������EXE)
bool Up() {
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	TOKEN_PRIVILEGES oldtp;
	DWORD dwSize = sizeof(TOKEN_PRIVILEGES);
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		if (GetLastError() == ERROR_CALL_NOT_IMPLEMENTED)
		{
			printf("GetLastError() == ERROR_CALL_NOT_IMPLEMENTED \n");
			return true;
		}
		else
		{
			printf("GetLastError() == \n");
			return false;
		}
	}
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
	{
		CloseHandle(hToken);
		printf("LookupPrivilegeValue == FALSE \n");
		return false;
	}
	ZeroMemory(&tp, sizeof(tp));
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	/* Adjust Token Privileges */
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), &oldtp, &dwSize)) {
		CloseHandle(hToken);
		printf("AdjustTokenPrivileges == FALSE \n");
		return false;
	}
	// close handles
	printf("��info��Up is Success ! \n");
	CloseHandle(hToken);
	return true;
}