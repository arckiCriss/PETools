//定义控制台应用程序的入口点。

#include "stdafx.h"
#define TOUPPER(c) ('a'<=(c)&&(c)<='z'?(c)-'a'+'A':(c))


char* filePath_read;
char* filePath_write;
#define IS_HOME 1
PEHeader thePEHeader;
PEBody thePEBody;
PBYTE pFileBuffer = NULL;

//打印PE头
void printPEHeader()
{
	printf("\n可选PE头：数据目录--------------------- \n");
	printf("export_directory_offset=%08X \n", thePEHeader.OptionalHeader.export_directory_offset);
	printf("relocation_directory_offset=%08X \n", thePEHeader.OptionalHeader.relocation_directory_offset);
	printf("import_directory_offset=%08X \n", thePEHeader.OptionalHeader.import_directory_offset);
}
//打印导出目录
void printExportDirectory()
{
	//打印导出目录
	printf("\n导出目录----------------------- \n");
	printf("Address_Of_Functions=%08X \n", thePEBody.ExportDirectory.Address_Of_Functions);
	printf("Address_Of_NameOrdinals=%08X \n", thePEBody.ExportDirectory.Address_Of_NameOrdinals);
	printf("Address_Of_Names=%08X \n", thePEBody.ExportDirectory.Address_Of_Names);
	printf("Base=%08X \n", thePEBody.ExportDirectory.Base);
	printf("Number_Of_Functions=%08X \n", thePEBody.ExportDirectory.Number_Of_Functions);
	printf("Number_Of_Names=%08X \n", thePEBody.ExportDirectory.Number_Of_Names);

	//打印函数名称
	printf("\n函数名称表----------------------- \n");
	for (int i = 0; i < thePEBody.ExportDirectory.Number_Of_Names; i++)
	{
		printf("%s \n", (char*)(pFileBuffer + convertRVAtoFOA(thePEBody.Functions_Names[i], thePEHeader)));
	}

	//打印函数名称序号
	printf("\n函数名称序号表----------------------- \n");
	for (int i = 0; i < thePEBody.ExportDirectory.Number_Of_Names; i++)
	{
		printf("%04X \n", thePEBody.Functions_NameOrdinals[i]);
	}

	//打印函数地址
	printf("\n函数地址表----------------------- \n");
	for (unsigned int i = 0; i < thePEBody.ExportDirectory.Number_Of_Functions; i++)
	{
		printf("%08X \n", thePEBody.Functions_Address[i]);
	}
}
//打印重定位目录及其映射表
void printRelocationDirectory()
{
	printf("\n重定位目录----------------------- \n");
	for (int i = 0; i < thePEBody.ReloactionDirectory.NumberOfBlock; i++)
	{
		printf("重定位块%2d： ", i);
		printf("Virtual_Address=%08X  ", thePEBody.ReloactionDirectory.Block[i].Virtual_Address);
		printf("Size_Of_Block=%08X \n", thePEBody.ReloactionDirectory.Block[i].Size_Of_Block);
		for (int j = 0; j < (thePEBody.ReloactionDirectory.Block[i].Size_Of_Block - 0x8) / 0x2; j++)
		{
			printf("重定位项offset=%X ", thePEBody.ReloactionDirectory.Block[i].Item[j].Offset);
			printf("重定位项type=%X \n", thePEBody.ReloactionDirectory.Block[i].Item[j].Type);
		}
	}
}
void printBoundImportDirectory()
{
	printf("\n绑定导出目录----------------------- \n");
	for (unsigned int i = 0; i < thePEBody.NumberOfBoundImportDirectory; i++)
	{
		printf("第 %d 个绑定导出目录: ", i);
		printf("时间戳=%08X   ", thePEBody.BoundImportDirectory[i].TimeDateStamp);
		//DLL名字的RVA = 绑定导入目录首地址RVA值 + OffsetModuleName
		unsigned int nameStr_RVA = thePEBody.BoundImportDirectory[i].OffsetModuleName + thePEHeader.OptionalHeader.bound_import_directory_offset;
		unsigned int nameStr_FOA = convertRVAtoFOA(nameStr_RVA, thePEHeader);
		char* nameStr = (char*)(pFileBuffer + nameStr_FOA);
		printf("DLL名称字符串=%s    ", nameStr);

		printf("NumberOfModuleForwarderRefs依赖DLL个数=%04X \n", thePEBody.BoundImportDirectory[i].NumberOfModuleForwarderRefs);
	}
}

void printPEBody()
{
	//打印导出目录及其映射表
	printExportDirectory();

	//打印重定位目录
	//printRelocationDirectory();	

	//打印导入目录及其映射表
	PrintImportDirectory(thePEHeader, thePEBody, pFileBuffer);

	//打印绑定导出目录
	printBoundImportDirectory();
}


//EXE的入口函数
int main(int argc, char* argv[])
{
	filePath_read = "C:\\Users\\41388\\Desktop\\src.exe";
	filePath_write = "C:\\Users\\41388\\Desktop\\dest.exe";

	//读文件到fileBuffer
	//int fileLength = readPEFile(filePath_read, OUT &pFileBuffer);

	//打印fileBuffer
	//printFileBuffer(pFileBuffer, fileLength);

	//分析PE参数
	//AnalyzePE_FileBuffer_x86(pFileBuffer, &thePEHeader, &thePEBody);

	//将FileBuffer拉伸到ImageBuffer
	//PBYTE pImageBuffer = NULL;
	//FileBufferToImageBuffer(pFileBuffer, OUT &pImageBuffer, thePEHeader);

	//向ImageBuffer插入代码(插入MessageBoxA函数)
	//insertCode(pImageBuffer);

	//新增一节
	//addSection(&thePEHeader, &thePEBody, filePath_read, pFileBuffer, "newnew", 0x1000);

	//通过函数名查找函数地址 D3D10Hook_SwapChain_Present_imp
	//unsigned int funcAddress= getFuncAddressByName("D3D10Hook_DrawIndexed_imp", pFileBuffer, thePEHeader, thePEBody);
	//printf("根据函数名查找函数地址：%08X \n", funcAddress);

	//通过逻辑序号查函数地址
	//printf("根据逻辑序号查函数地址: %08X \n",getFuncAddressByLogicalOrdinal(3,thePEBody));


	//将ImagaBuffer转换至NewBuffer
	//PBYTE pNewBuffer = NULL;
	//int length_NewBuffer = thePEHeader.SectionHeader.pointer_to_raw_data[thePEHeader.COFFHeader.number_of_section - 1] + thePEHeader.SectionHeader.size_Of_raw_data[thePEHeader.COFFHeader.number_of_section - 1];
	//imageBufferToNewBuffer(pImageBuffer, &pNewBuffer, length_NewBuffer, thePEHeader);
	//newBuffer写入文件
	//writePEFile(filePath_write, length_NewBuffer, pNewBuffer);

	//移动导出目录
	//moveExportDirectory(&thePEHeader, &thePEBody,filePath_read, pFileBuffer);

	//移动重定位目录
	//moveRelocationDirectory(&thePEHeader, &thePEBody, filePath_read, pFileBuffer);

	//打印PE头
	//printPEHeader();

	//打印PEBody
	//printPEBody();

	//遍历进程
	//traversalProcess();

	//加壳
	//addShell("D:\\Users\\voila\\Desktop\\src.exe", "D:\\Users\\voila\\Desktop\\项目\\PETOOLS\\Debug\\shell.exe");

	//远程线程DLL注入目标进程(编译成64位后有一些进程仍无法注入如Win10计算器)
	RemoteThreadInject_X64("Overwatch.exe", TEXT("C:\\Users\\41388\\source\\repos\\D3D11-Wallhack\\x64\\Debug\\d3d11hook.dll"));
	//RemoteThreadInject_X86(TEXT("cstrike.exe"), TEXT("C:\\Users\\41388\\source\\repos\\D3D11-Wallhack\\Debug\\d3d11hook.dll"));
	//RemoteThreadInject_X64(TEXT("Overwatch.exe"), TEXT("C:\\Users\\41388\\Desktop\\MalwareDllX64.dll"));

	//加载目标EXE,经测试可执行战网exe(需放同目录下)
	//LoadExe_x86("dest.exe");

	//反射式注入（编译成Release）
	//ReflectInject_X86("cstrike.exe");
	ReflectInject_X86("cloudmusic.exe");

	//设置全局键盘钩子
	//Hook_MessageHook();

	//IAT Hook
	//Hook_IATHook_x86("USER32.dll","MessageBoxA",(DWORD)Hook_MyMessageBox);

	//Inline Hook
	//InlineHook_X86(TEXT("USER32.dll"), TEXT("MessageBoxA"),(DWORD)InlineHook_MyMessageBoxA_X86,5);

	
	getchar();
}

// <summary>
//	定义一个DLL初始化函数
// </summary>
// <param name="lpThreadParameter"></param>
DWORD WINAPI initDLL(LPVOID lpThreadParameter)
{
	//创建控制台
	AllocConsole();
	freopen("conout$", "w", stdout);
	while (true)
	{
		printf("hello wolrd!\n");
		Sleep(2222);
	}
	return 0;
}
//DLL的入口函数
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	HANDLE hThread = 0;
	switch (ul_reason_for_call)
	{

	case DLL_PROCESS_ATTACH://当DLL被加载时
		//在目标进程中开启一个线程做一些事
		MessageBox(0, TEXT("加载DLL..."), TEXT("标题~"), MB_OK);
		hThread = CreateThread(NULL, 0, initDLL, NULL, 0, NULL);
		break;
	case DLL_PROCESS_DETACH: //当DLL被卸载时
	{
		MessageBox(0, TEXT("DLL被卸载..."), TEXT("标题~"), MB_OK);
	}
	break;
	default:
		break;
	}
	return TRUE;
}



