// Shell.cpp: 定义控制台应用程序的入口点。
//
#include "stdafx.h"
#include "MyVariable_Copy.h" //拷贝PETools项目定义的结构体
#include <windows.h>
#include <locale.h>
#include <psapi.h>
#include <tlhelp32.h>

typedef int(*ReadPEFile)(char*, OUT unsigned char**);
typedef void(*AnalyzePE)(unsigned char* pFileBuffer, PEHeader* pPEHeader, PEBody* pPEBody);
typedef void(*FileBufferToImageBuffer)(unsigned char* pFileBuffer, OUT unsigned char** pImageBuffer_address, PEHeader PEHeader);
typedef void(*ChangeImageBase)(unsigned int destImageBase, unsigned char* pFileBuffer, PEHeader* pPEHeader, PEBody thePEBody, char* filePath);

/*
	壳程序（本程序）是shell.exe ，要执行的代码是src.exe
	壳程序负责解壳，创建shell新进程，将src贴入新进程内

	某些程序作为src时，贴入shell新进程后无法执行，原因未知。
*/
int main()
{
	
	//0.加载所需的函数(PETools的DLL)
	HMODULE hDLL = LoadLibrary(TEXT("PETOOL_DLL.dll"));
	ReadPEFile readPEFile = (ReadPEFile)GetProcAddress(hDLL, "readPEFile");
	AnalyzePE analyzePE = (AnalyzePE)GetProcAddress(hDLL, "analyzePE");
	FileBufferToImageBuffer fileBufferToImageBuffer = (FileBufferToImageBuffer)GetProcAddress(hDLL, "fileBufferToImageBuffer");
	ChangeImageBase changeImageBase = (ChangeImageBase)GetProcAddress(hDLL, "changeImageBase");
	
	//1.读取壳程序(自己)的路径
	TCHAR filePath_shell_W[MAX_PATH] = { 0 };
	if (GetModuleFileName(NULL, filePath_shell_W, MAX_PATH) == 0)
	{
		DWORD code = GetLastError();
		printf("获取当前程序路径失败,code=%d \n", code);
		return 0;
	}
	setlocale(LC_ALL, "");
	wprintf(L"获取当前程序路径=%s \n", filePath_shell_W);
	char filePath_shell[256] = { 0 };
	sprintf(filePath_shell, "%ws", filePath_shell_W);	//路径：宽字符转多字符

	//2.读取壳程序(自己)的fileBuffer
	BYTE* pFileBuffer_shell;
	readPEFile(filePath_shell, OUT &pFileBuffer_shell);
	PEHeader PEHeader_shell;
	PEBody PEBody_shell;

	//3.分析壳程序(自己)的PE头
	analyzePE(pFileBuffer_shell, &PEHeader_shell, &PEBody_shell);

	//4.读取壳程序的PE最后一节数据 (因为src文件存放于最后一节)
	BYTE* pFileBuffer_src;
	PEHeader PEHeader_src;
	PEBody PEBody_src;
	pFileBuffer_src = pFileBuffer_shell + PEHeader_shell.SectionHeader.pointer_to_raw_data[PEHeader_shell.COFFHeader.number_of_section - 1];

	//5.解密源程序数据（省略）
	if ((*(WORD*)pFileBuffer_src) != 0x5A4D)
	{//MZ判断
		printf("\n读到的src.exe没有MZ标识，不是PE文件 \n");
		getchar();
		return 0;
	}

	//6.分析源程序的PE结构
	analyzePE(pFileBuffer_src, &PEHeader_src, &PEBody_src);

	//7.以挂起的形式创建壳程序(自己)的新进程
	STARTUPINFO si = { 0 };
	si.cb = sizeof(STARTUPINFO);
	PROCESS_INFORMATION pi;
	TCHAR ssss[] = TEXT("D:\\Users\\voila\\Desktop\\demo.exe");
	if (CreateProcess(filePath_shell_W, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi) == 0)
	{
		DWORD code = GetLastError();
		printf("创建进程失败,code=%d \n", code);
	}
	////8.枚举所有线程的句柄
	//HMODULE moduleArray[500] = { 0 };
	//DWORD moduleArray_byteSize;
	//EnumProcessModulesEx(pi.hProcess, moduleArray, sizeof(moduleArray), OUT &moduleArray_byteSize, LIST_MODULES_ALL);

	//8.得到新进程的主线程CONTEXT
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(pi.hThread, &context))
	{
		printf("获取主线程CONTEXT失败 \n");
		getchar();
		return 0;
	}

	// 9.获取新进程的主模块基址(EBX+8中存储了地址值，这个地址值的内存单元存放了ImageBase的值)
	// EBX points to PEB, offset 8 is the pointer to the base address
	DWORD imageBase;
	if (ReadProcessMemory(pi.hProcess, (LPCVOID)(context.Ebx + 8), OUT &imageBase, sizeof(PVOID), NULL) == 0)
	{
		DWORD CODE = GetLastError();
		printf("读取进程内存失败,code=%d \n", CODE);
		TerminateProcess(pi.hProcess, 0);
		getchar();
		return 0;
	}
	//****如果卸载主模块，程序恢复时将出错*****//
	//10.卸载新进程的主模块(因为只拿得到主模块的地址，要是有其他模块的地址就全部卸载掉了)
	//typedef ULONG(WINAPI *PNtUnmapViewOfSection) (HANDLE ProcessHandle, PVOID BaseAddress);
	//HMODULE hNtModule = GetModuleHandle(_T("ntdll.dll"));
	//PNtUnmapViewOfSection pfNtUnmapViewOfSection = (PNtUnmapViewOfSection)GetProcAddress(hNtModule, "NtUnmapViewOfSection");
	//if (pfNtUnmapViewOfSection(pi.hProcess, (PVOID)imageBase))
	//{
	//	printf("卸载模块失败,STATUS_ACCESS_DENIED: The caller does not have access rights to the process object or to the base virtual address of the view.\n");
	//	TerminateProcess(pi.hProcess, 0);
	//	getchar();
	//	return 0;
	//}

	//11.尝试在源文件希望的基地址ImageBase申请源文件希望的SizeOfImage大小的内存，VirtualAllocEx函数跨进程申请指定地址内存
	DWORD VA = (DWORD)VirtualAllocEx(pi.hProcess, (LPVOID)PEHeader_src.OptionalHeader.image_base, PEHeader_src.OptionalHeader.size_of_image, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (VA == NULL)
	{//11.1 若申请内存失败，查看源程序是否有重定位表，
		printf("申请期望的基地址失败,希望的基址=%d \n", PEHeader_src.OptionalHeader.image_base);
		if (PEHeader_shell.OptionalHeader.relocation_directory_offset == 0x0)
		{//11.2 若没有重定位表则退出
			TerminateProcess(pi.hProcess, 0);
			getchar();
			return 0;
		}

		//11.3 若有重定位表则重新申请任意地址的内存，
		VA = (DWORD)VirtualAllocEx(pi.hProcess, NULL, PEHeader_src.OptionalHeader.size_of_image, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		printf("重新申请到的基址=%08X \n",VA );

		//11.4 重新申请随即内存后，根据重定位表修复数据
		changeImageBase(VA, pFileBuffer_src, &PEHeader_src, PEBody_src, NULL);
		
	}

	//12.申请内存成功后，将源程序数据拉伸至ImageBuffer
	BYTE* pImageBuffer_src;
	fileBufferToImageBuffer(pFileBuffer_src, &pImageBuffer_src, PEHeader_src);
	//13.将拉伸后的源程序贴入新进程的基址处
	if (WriteProcessMemory(pi.hProcess, (LPVOID)VA, (LPCVOID)pImageBuffer_src, PEHeader_src.OptionalHeader.size_of_image, OUT NULL) == 0)
	{
		DWORD CODE = GetLastError();
		printf("写入内存失败,CODE=%d \n", CODE);
		TerminateProcess(pi.hProcess, 0);
		getchar();
	}

	//14.修改新进程的主模块基地址
	// Replace the base address in the PEB
	if (WriteProcessMemory(pi.hProcess, (LPVOID)(context.Ebx + 0x8), (LPVOID)&VA, sizeof(DWORD), NULL) == 0)
	{
		DWORD CODE = GetLastError();
		printf("写入内存失败,CODE=%d \n", CODE);
		TerminateProcess(pi.hProcess, 0);
		getchar();
	}
	//15.修改新进程的入口点(程序的入口点放在EAX寄存器中)
	// Replace Entry Point Address
	//32位模式下的eax寄存器，保存的值为程序的入口点地址，即镜像加载基址+镜像内偏移。而在64为模式下，变为了Rcx寄存器。
	context.Eax =VA + PEHeader_src.OptionalHeader.address_of_entry_point;

	//16.存入线程上下文CONTEXT
	SetThreadContext(pi.hThread, &context);

	//17.恢复线程
	ResumeThread(pi.hThread);

	//18.脱壳结束，终止原外壳进程(自己)
	ExitProcess(NULL);

	return 0;
}

