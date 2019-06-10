#include "pch.h"


/**
 * 打开进程：通过进程名
 * 参数 ProcessName	进程名
 * 参数 needAccess	以何种权限打开进程 (eg: PROCESS_TERMINATE|PROCESS_VM_READ or PROCESS_ALL_ACCESS)
 */
HANDLE OpenProcessByName(const TCHAR* processName, DWORD ACCESS)
{
	//调用CreatToolhelp32Snapshot来获取快照,用THREADENTRY32来获取线程信息等
	HANDLE hSnapshot;
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	//检索快照中第一个进程的信息
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
				printf("【error】打开进程[%s]失败 , ErrorCode = %d \n", processName, GetLastError());
				return 0;
			}
			CloseHandle(hSnapshot);
			printf("【info】成功打开目标进程[%s]... \n", processName);
			return hProcess;
		}
	}
	CloseHandle(hSnapshot);
	printf("【error】未找到进程[%s]... \n", processName);
	return 0;
}

// <summary>
// 将十六进制的数转为同样的字符串
// 0x66AA->'66AA'
// </summary>
// <param name="srcHex"></param>
CHAR* HexToStr(DWORD srcHex)
{
	//计算数字的位数
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
	//存在内存泄漏的问题：申请新char数组
	CHAR* res = (CHAR*)malloc(digit + 1);
	//置零
	memset(res, 0x0, digit + 1);
	//逐位转为字符，填入char数组
	for (int i = digit - 1; i >= 0; i--)
	{
		//十六进制的A~F需+0x37
		*(res + i) = srcHex % 16 + ((srcHex % 16) < 0xA ? 0x30 : 0x37);
		srcHex = srcHex / 16;
	}
	return res;
}
// <summary>
// 将十进制的数转为同样的字符串
// 1234->'1234'
// </summary>
// <param name="srcDec"></param>
CHAR* DecToStr(DWORD srcDec)
{
	//计算数字的位数
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
	//存在内存泄漏的问题：申请新char数组
	CHAR* res = (CHAR*)malloc(digit + 1);
	//置零
	memset(res, 0x0, digit + 1);
	//逐位转为字符，填入char数组
	for (int i = digit - 1; i >= 0; i--)
	{
		*(res + i) = srcDec % 10 + 48;
		srcDec = srcDec / 10;
	}
	return res;
}
// <summary>
// 打印十六进制数字hex和msg到OutputDebugString (四字节的hex数)
// </summary>
// <param name="msgStr"></param>
// <param name="hex"></param>
void ShowDbg(const char* msgStr, DWORD hex)
{
	//把常量字符串const char* 转为char*，数组需足够长  
	char res[100] = { 0 }; //观察反汇编调用了_memset函数，_memset实际上跳转至外部DLL(vcruntime140.dll)的memset函数,故在反射式注入时调用需先修复IAT表
	strcpy(res, msgStr);

	//把十六进制数转为字符串，然后拼接
	strcat(res, HexToStr(hex));

	//打印到debug
	OutputDebugString(res);
}

//提升权限(用管理员权限运行EXE)
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
	printf("【info】Up is Success ! \n");
	CloseHandle(hToken);
	return true;
}