#include "pch.h"
// -------------------------------------------------------------------
//反射式注入只能注入自己EXE当前模块，不能注入DLL
//	因为被注入的模块需要自己修复IAT表，而修复IAT表所需的参数较多，
//	如果事先将所需参数全部写入目标进程太麻烦了（参数是结构体，结构体中又包含指针数组，
//	所以只写入结构体是不够的，还需要把里面的指针数组所指向的所有数据一并写入，还要考虑写入后的地址偏移）。
//
// Copyright (c) LiSheDaChun. All rights reserved.
// -------------------------------------------------------------------

// <summary>
// Malware所需的全局变量参数
// </summary>
MALWARE_PARAM malware_Param;
//导出函数：获取全局变量的地址
LPVOID GetMalwareParam()
{
	return &malware_Param;
}
// <summary>
// 为malware全局参数赋值
// </summary>
// <param name="PEBody"></param>
// <param name="virtualAddr"></param>
VOID Malware_HandleParam(PEBODY PEBody, DWORD64 virtualAddr)
{
	//判断原定的数组大小是否足够
	if (PEBody.pri_sum_importDirectory > 100)
	{
		printf("错误:pri_sum_importDirectory大于100 \n");
		return;
	}
	for (int i = 0; i < PEBody.pri_sum_importDirectory; i++)
	{
		if (PEBody.INT_Table[i].pri_sum_item > 200)
		{
			printf("错误:pri_sum_item大于200 \n");
			return;
		}
	}
	//开始赋值
	malware_Param.virtualAddr = virtualAddr;
	malware_Param.numOfImportDirectory = PEBody.pri_sum_importDirectory;
	for (int i = 0; i < PEBody.pri_sum_importDirectory; i++)
	{
		malware_Param.ImportDirectory[i] = PEBody.ImportDirectory[i];
		malware_Param.INT_Malware[i].numOfItem_pri = PEBody.INT_Table[i].pri_sum_item;
		malware_Param.IAT_Malware[i].numOfItem_pri = PEBody.IAT_Table[i].pri_sum_item;
		for (int j = 0; j < PEBody.INT_Table[i].pri_sum_item; j++)
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
VOID Malware_RepairIAT()
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
//在目标进程中执行的恶意代码(要负责修复IAT表)
// </summary>
// <param name="NULL"></param>
DWORD WINAPI Malware_Core(LPVOID lpThreadParameter)
{
	//OutputDebugString("my-进入目标进程");

	//修复IAT表 (需在调用外部DLL函数之前修复)
	Malware_RepairIAT();

	//malware...
	//MessageBox(0, "已注入完毕...", 0, 0);

	//创建控制台窗口
	AllocConsole();
	freopen("conout$", "w", stdout);
	printf("Hello MalwareCore !\n");

	//d3d透视
	WallHack_Hook();

	return 0x6666;
}


// <summary>
// 反射式注入（注入当前EXE模块）
// </summary>
// <param name="destPID">目标进程ID</param>
VOID ReflectInject_EXE(const CHAR* processName)
{
#if _DEBUG
	printf("错误：需编译为release版本... \n");
	return;
#endif

	printf("\n开始执行反射式注入... \n");

	//1.打开目标进程：读/写权限、操作权限(用于申请虚拟内存)，如果目标进程是以管理员身法打开的，那么本进程也需要管理员身份。
	HANDLE hDestProcess = OpenProcessByName(processName, PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION);
	if (hDestProcess == 0x0)return;
	//1.1 当前进程与目标进程必须位数相等才能注入
	BOOL is32BitProcess;
	IsWow64Process(hDestProcess, &is32BitProcess);
#if _IS_X86
	if (is32BitProcess == FALSE)
	{
		printf("错误：当前进程是32位，目标进程是64位...\n");
		return;
	}
#elif _IS_X64
	if (is32BitProcess == TRUE)
	{
		printf("错误：当前进程是64位，目标进程是32位...\n");
		return;
	}
#endif
	//2.得到当前模块的镜像大小ImageSize、镜像基址ImageBase
	MODULEINFO moduleInfo;
	GetModuleInformation(GetCurrentProcess(), GetModuleHandle(NULL), OUT & moduleInfo, sizeof(MODULEINFO));

	//3.将当前模块复制到缓冲区ImageBuffer
	PBYTE imageBuffer = (PBYTE)malloc(moduleInfo.SizeOfImage);
	memcpy(imageBuffer, moduleInfo.lpBaseOfDll, moduleInfo.SizeOfImage);

	//4.分析当前模块的PE结构
	PEBODY PEBody;
	PEHEADER PEHeader;
	AnalyzePE_ByImageBuffer((PBYTE)imageBuffer, &PEHeader, &PEBody);

	//5.申请一块足够粘贴当前模块大小的虚拟内存VirtualMemory，指定内存页保护属性为"可执行、可读可写"
	DWORD64 virtualAddr = (DWORD64)VirtualAllocEx(hDestProcess, NULL, moduleInfo.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (virtualAddr == 0x0)
	{
		printf("申请内存失败，code=%d \n", GetLastError());
		return;
	}

	//6.根据申请到的基址，修复当前模块重定位表（编译成release版本才有重定位表）
	if (!Repair_ReLocDirectory(virtualAddr, (DWORD64)moduleInfo.lpBaseOfDll, imageBuffer, &PEHeader, &PEBody))
	{
		return;
	}

	//7.1 为恶意函数所需的参数赋值，参数必须是【全局变量】(传递的参数中如果存在写死的指针值，则需要手动重定位)
	Malware_HandleParam(PEBody, virtualAddr);

	//7.2 将参数更新至缓冲区ImageBuffer
	DWORD64 RVA_MalwareParam = (DWORD64)& malware_Param - (DWORD64)moduleInfo.lpBaseOfDll;
	memcpy(imageBuffer + RVA_MalwareParam, &malware_Param, sizeof(malware_Param));

	//8.将最终的imageBuffer贴入目标进程虚拟内存
	WriteProcessMemory(hDestProcess, (LPVOID)virtualAddr, imageBuffer, moduleInfo.SizeOfImage, NULL);

	//9.计算Malware函数在目标进程中的地址
	DWORD64 RVA = (DWORD64)Malware_Core - (DWORD64)moduleInfo.lpBaseOfDll;
	LPTHREAD_START_ROUTINE pMALWAREFUNC = (LPTHREAD_START_ROUTINE)(virtualAddr + RVA);
	printf("计算远程函数地址=%llX \n", pMALWAREFUNC);

	//10.调用远程线程执行Malware函数
	HANDLE hRemoteThread = CreateRemoteThread(hDestProcess, NULL, 0, pMALWAREFUNC, NULL, 0, OUT NULL);
	printf("开启远程线程,线程句柄=%llX \n", hRemoteThread);

	//11.等待远程线程结束
	WaitForSingleObject(hRemoteThread, INFINITE);
	DWORD exitCode = 0;
	GetExitCodeThread(hRemoteThread, OUT & exitCode);//线程退出码
	printf("远程线程退出码= %llX \n", exitCode);

	CloseHandle(hRemoteThread);
}



//反射式注入 (注入当前EXE模块，反检测)
/**
	<检测机制>(针对2019年6月6日)
		守望先锋对于CreateThread创建线程做了检测，一旦发现线程函数的地址并非位于正常的模块中时，就将线程函数的首句代码改为0x3C(ret)
			1.不论是远程线程注入DLL后调用CreateThread创建本地线程，还是反射式注入调用CreateRemoteThread创建远程线程，都会被修改代码。
			2.如果线程函数是正常模块中的函数（例如LoadLibrary函数），那么可以正常调用，不会被改代码。
			3.没有发现守望先锋对createThread做inline hook(机器码未变)
	<反检测思路>
		将shellcode正常映射，然后在守望先锋的正常模块中写入一条"far jmp"指令，然后调用远程线程执行这条指令，跳转至我们事先写入的shellcode即可。
*/
VOID ReflectInject_EXE_AntiDetect_20190606(const CHAR* processName)
{
#if _DEBUG
	printf("【error】需将当前exe编译为Release版本才有重定位表... \n");
	return;
#endif

	//0.提权（似乎不需要）
	//Up();

	//0.打开目标进程
	HANDLE hDestProcess = OpenProcessByName(processName, PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION);
	if (hDestProcess == 0x0) { printf("【error】打开目标进程失败..."); return; }
	//1. 当前进程与目标进程必须位数相等才能注入
	BOOL is32BitProcess;
	IsWow64Process(hDestProcess, &is32BitProcess);
#if _IS_X86
	if (is32BitProcess == FALSE)
	{
		printf("错误：当前进程是32位，目标进程是64位...\n");
		return;
}
#elif _IS_X64
	if (is32BitProcess == TRUE)
	{
		printf("错误：当前进程是64位，目标进程是32位...\n");
		return;
	}
#endif
	//2.将shellcode映射进入目标进程
	MODULEINFO moduleInfo;
	GetModuleInformation(GetCurrentProcess(), GetModuleHandle(NULL), OUT & moduleInfo, sizeof(MODULEINFO));
	PBYTE imageBuffer = (PBYTE)malloc(moduleInfo.SizeOfImage);
	memcpy(imageBuffer, moduleInfo.lpBaseOfDll, moduleInfo.SizeOfImage);
	PEBODY PEBody; PEHEADER PEHeader;
	AnalyzePE_ByImageBuffer((PBYTE)imageBuffer, &PEHeader, &PEBody);
	DWORD64 virtualAddr = (DWORD64)VirtualAllocEx(hDestProcess, NULL, moduleInfo.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (virtualAddr == 0x0) { printf("申请内存失败，code=%d \n", GetLastError()); return; }
	if (!Repair_ReLocDirectory(virtualAddr, (DWORD64)moduleInfo.lpBaseOfDll, imageBuffer, &PEHeader, &PEBody)) { return; }
	Malware_HandleParam(PEBody, virtualAddr);
	DWORD64 RVA_MalwareParam = (DWORD64)& malware_Param - (DWORD64)moduleInfo.lpBaseOfDll;
	memcpy(imageBuffer + RVA_MalwareParam, &malware_Param, sizeof(malware_Param));
	WriteProcessMemory(hDestProcess, (LPVOID)virtualAddr, imageBuffer, moduleInfo.SizeOfImage, NULL);
	DWORD64 RVA = (DWORD64)Malware_Core - (DWORD64)moduleInfo.lpBaseOfDll;
	LPTHREAD_START_ROUTINE pMALWAREFUNC = (LPTHREAD_START_ROUTINE)(virtualAddr + RVA); //Malware函数在目标进程中的地址

	//2.修改正常模块的页保护属性为"读、写、执行"
	HMODULE hNTDLL=GetModuleHandle("ntdll.dll");			//因为每次重启电脑后加载ntdll.dll的基址都会变化，所以要动态获取。
	LPVOID pasteAddr = (LPVOID)((DWORD64)hNTDLL + 0x03E7);	//通过CE查看，ntdll.dll+0x3E7处的连续0x10个内存都是0x0，可以作为粘贴FarJMP的位置
	DWORD oldProtect = 0;
	if (VirtualProtectEx(hDestProcess, pasteAddr, 0x10, PAGE_EXECUTE_READWRITE, &oldProtect) == FALSE) //修改保护性为"读、写、可执行"
	{
		printf("【error】修改ntdll.dll中的内存页保护属性失败，errorCode=%d \n", GetLastError()); return;
	}

	//3.构造 FAR JMP 远跳指令，并写入一个正常模块
	HardCode_FarJMP farJMP;
	farJMP.PUSH = 0x68;
	farJMP.Addr_Low32 = (DWORD64)pMALWAREFUNC & 0xFFFFFFFF;
	farJMP.MOV_DWORD_PTR_SS = 0x042444C7;
	farJMP.Addr_High32 = ((DWORD64)pMALWAREFUNC) >> 32;
	farJMP.RET = 0xC3;
	if (WriteProcessMemory(hDestProcess, pasteAddr, &farJMP, sizeof(farJMP), NULL) == FALSE) { printf("【error】远跳指令写入目标进程失败,errorCode=%d \n", GetLastError()); return; }


	//4.远程线程执行位于正常模块的远跳指令，从而执行shellcode（OW不会把首句代码改成0xC3）
	HANDLE hRemoteThread = CreateRemoteThread(hDestProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pasteAddr, NULL, 0, OUT NULL);
	printf("【info】启动远程线程,线程句柄=%llX \n", hRemoteThread);
	WaitForSingleObject(hRemoteThread, INFINITE);
	DWORD exitCode = 0;
	GetExitCodeThread(hRemoteThread, OUT & exitCode);
	printf("【info】远程线程结束，退出码 = %llX \n", exitCode);

}

// 为malware全局参数赋值
VOID Malware_HandleParam_DLL(PEBODY PEBody, DWORD64 virtualAddr, MALWARE_PARAM* malware_Param)
{
	//判断原定的数组大小是否足够
	if (PEBody.pri_sum_importDirectory > 100)
	{
		printf("错误:pri_sum_importDirectory大于100 \n");
		return;
	}
	for (int i = 0; i < PEBody.pri_sum_importDirectory; i++)
	{
		if (PEBody.INT_Table[i].pri_sum_item > 200)
		{
			printf("错误:pri_sum_item大于200 \n");
			return;
		}
	}
	//开始赋值
	malware_Param->virtualAddr = virtualAddr;
	malware_Param->numOfImportDirectory = PEBody.pri_sum_importDirectory;
	for (int i = 0; i < PEBody.pri_sum_importDirectory; i++)
	{
		malware_Param->ImportDirectory[i] = PEBody.ImportDirectory[i];
		malware_Param->INT_Malware[i].numOfItem_pri = PEBody.INT_Table[i].pri_sum_item;
		malware_Param->IAT_Malware[i].numOfItem_pri = PEBody.IAT_Table[i].pri_sum_item;
		for (int j = 0; j < PEBody.INT_Table[i].pri_sum_item; j++)
		{
			malware_Param->INT_Malware[i].IMAGE_THUNK_DATA[j] = (DWORD)PEBody.INT_Table[i].IMAGE_THUNK_DATA[j];
			malware_Param->IAT_Malware[i].funcAddr[j] = (DWORD)PEBody.IAT_Table[i].funcAddress[j];
		}
	}
}


// <summary>
// //反射式注入（外部DLL模块，外部DLL暂时只能为debug版本，因为ASM汇编函数存在待解决问题）
// </summary>
// <param name="processName">目标进程名</param>
VOID ReflectInject_DLL_AntiDetect_20190606(const CHAR* processName, const char* dllPath)
{
	printf("\n开始执行反射式注入... \n");

	//1.打开目标进程：读/写权限、操作权限(用于申请虚拟内存)，如果目标进程是以管理员身法打开的，那么本进程也需要管理员身份。
	HANDLE hDestProcess = OpenProcessByName(processName, PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION);
	if (hDestProcess == 0x0)return;
	//1.1 当前进程与目标进程必须位数相等才能注入
	BOOL is32BitProcess;
	IsWow64Process(hDestProcess, &is32BitProcess);
#if _IS_X86
	if (is32BitProcess == FALSE)
	{
		printf("错误：当前进程是32位，目标进程是64位...\n");
		return;
}
#elif _IS_X64
	if (is32BitProcess == TRUE)
	{
		printf("错误：当前进程是64位，目标进程是32位...\n");
		return;
	}
#endif

	//2.在本进程中先加载目标模块DLL
	HMODULE hModule = LoadLibrary(dllPath);
	if (hModule == 0x0) { printf("【error】加载目标DLL失败..."); return; }

	//3.获取DLL的镜像大小ImageSize、镜像基址ImageBase
	MODULEINFO moduleInfo;
	GetModuleInformation(GetCurrentProcess(), hModule, OUT & moduleInfo, sizeof(MODULEINFO));

	//4.获取DLL中我写好的2个导出函数地址
	LPVOID(*pGetMalwareParam)();
	pGetMalwareParam = (LPVOID(*)()) GetProcAddress(hModule, "GetMalwareParam");
	LPVOID pMalwareParam = pGetMalwareParam();							//函数1：用于获取全局变量参数的地址
	LPVOID pMalware_Core = GetProcAddress(hModule, "Malware_Core");		//函数2

	//5.将目标模块复制到缓冲区ImageBuffer
	PBYTE pImageBuffer = (PBYTE)malloc(moduleInfo.SizeOfImage);
	memcpy(pImageBuffer, moduleInfo.lpBaseOfDll, moduleInfo.SizeOfImage);

	//6.分析目标模块的PE结构
	PEBODY PEBody; PEHEADER PEHeader;
	AnalyzePE_ByImageBuffer((PBYTE)pImageBuffer, &PEHeader, &PEBody);

	//7.向目标进程申请一块足够粘贴当前模块大小的虚拟内存VirtualMemory，指定内存页保护属性为"可执行、可读可写"
	DWORD64 virtualAddr = (DWORD64)VirtualAllocEx(hDestProcess, NULL, moduleInfo.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (virtualAddr == 0x0)
	{
		printf("申请内存失败，code=%d \n", GetLastError());
		return;
	}

	//8.根据申请到的基址，修复当前模块重定位表（DLL一定会有重定位表，EXE则需要编译为release才有重定位表）
	if (!Repair_ReLocDirectory(virtualAddr, (DWORD64)moduleInfo.lpBaseOfDll, pImageBuffer, &PEHeader, &PEBody))
	{
		return;
	}

	//9.1 为恶意函数所需的参数赋值，参数必须是【全局变量】(传递的参数中如果存在写死的指针值，则需要手动重定位)
	Malware_HandleParam_DLL(PEBody, virtualAddr, (MALWARE_PARAM*)pMalwareParam);

	//9.2 将参数更新至缓冲区ImageBuffer
	DWORD64 RVA_MalwareParam = (DWORD64)pMalwareParam - (DWORD64)moduleInfo.lpBaseOfDll;
	memcpy(pImageBuffer + RVA_MalwareParam, pMalwareParam, sizeof(MALWARE_PARAM));

	//10.将最终的ImageBuffer贴入目标进程虚拟内存
	WriteProcessMemory(hDestProcess, (LPVOID)virtualAddr, pImageBuffer, moduleInfo.SizeOfImage, NULL);

	//11.计算Malware函数在目标进程中的地址
	DWORD64 RVA = (DWORD64)pMalware_Core - (DWORD64)moduleInfo.lpBaseOfDll;
	LPTHREAD_START_ROUTINE threadProc = (LPTHREAD_START_ROUTINE)(virtualAddr + RVA);
	printf("计算远程函数地址=%llX \n", threadProc);

	//【反检测机制】......(如果不需要反检测，那么直接调用目标进程中的MalwareCore函数即可)
	//12.修改正常模块的页保护属性为"读、写、执行"
	HMODULE hNTDLL = GetModuleHandle("ntdll.dll");			//因为每次重启电脑后加载ntdll.dll的基址都会变化，所以要动态获取。
	LPVOID pasteAddr = (LPVOID)((DWORD64)hNTDLL + 0x03E7);	//通过CE查看，ntdll.dll+0x3E7处的连续10个内存都是0x0，可以作为粘贴FarJMP的位置
	DWORD oldProtect = 0;
	if (VirtualProtectEx(hDestProcess, pasteAddr, 0x10, PAGE_EXECUTE_READWRITE, &oldProtect) == FALSE) //修改保护性为"读、写、可执行"
	{
		printf("【error】修改ntdll.dll中的内存页保护属性失败，errorCode=%d \n", GetLastError()); return;
	}

	//13.构造 FAR JMP 远跳指令，并写入一个正常模块
	HardCode_FarJMP farJMP;
	farJMP.PUSH = 0x68;
	farJMP.Addr_Low32 = (DWORD64)threadProc & 0xFFFFFFFF;
	farJMP.MOV_DWORD_PTR_SS = 0x042444C7;
	farJMP.Addr_High32 = ((DWORD64)threadProc) >> 32;
	farJMP.RET = 0xC3;
	if (WriteProcessMemory(hDestProcess, pasteAddr, &farJMP, sizeof(farJMP), NULL) == FALSE) { printf("【error】远跳指令写入目标进程失败,errorCode=%d \n", GetLastError()); return; }


	//14.远程线程执行位于正常模块的远跳指令，从而执行shellcode（OW不会把首句代码改成0xC3）
	HANDLE hRemoteThread = CreateRemoteThread(hDestProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pasteAddr, NULL, 0, OUT NULL);
	printf("【info】启动远程线程,线程句柄=%llX \n", hRemoteThread);
	WaitForSingleObject(hRemoteThread, INFINITE);
	DWORD exitCode = 0;
	GetExitCodeThread(hRemoteThread, OUT & exitCode);
	printf("【info】远程线程结束，退出码 = %llX \n", exitCode);


	CloseHandle(hRemoteThread);
}

