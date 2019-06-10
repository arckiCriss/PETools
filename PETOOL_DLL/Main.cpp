//�������̨Ӧ�ó������ڵ㡣

#include "stdafx.h"
#define TOUPPER(c) ('a'<=(c)&&(c)<='z'?(c)-'a'+'A':(c))


char* filePath_read;
char* filePath_write;
#define IS_HOME 1
PEHeader thePEHeader;
PEBody thePEBody;
PBYTE pFileBuffer = NULL;

//��ӡPEͷ
void printPEHeader()
{
	printf("\n��ѡPEͷ������Ŀ¼--------------------- \n");
	printf("export_directory_offset=%08X \n", thePEHeader.OptionalHeader.export_directory_offset);
	printf("relocation_directory_offset=%08X \n", thePEHeader.OptionalHeader.relocation_directory_offset);
	printf("import_directory_offset=%08X \n", thePEHeader.OptionalHeader.import_directory_offset);
}
//��ӡ����Ŀ¼
void printExportDirectory()
{
	//��ӡ����Ŀ¼
	printf("\n����Ŀ¼----------------------- \n");
	printf("Address_Of_Functions=%08X \n", thePEBody.ExportDirectory.Address_Of_Functions);
	printf("Address_Of_NameOrdinals=%08X \n", thePEBody.ExportDirectory.Address_Of_NameOrdinals);
	printf("Address_Of_Names=%08X \n", thePEBody.ExportDirectory.Address_Of_Names);
	printf("Base=%08X \n", thePEBody.ExportDirectory.Base);
	printf("Number_Of_Functions=%08X \n", thePEBody.ExportDirectory.Number_Of_Functions);
	printf("Number_Of_Names=%08X \n", thePEBody.ExportDirectory.Number_Of_Names);

	//��ӡ��������
	printf("\n�������Ʊ�----------------------- \n");
	for (int i = 0; i < thePEBody.ExportDirectory.Number_Of_Names; i++)
	{
		printf("%s \n", (char*)(pFileBuffer + convertRVAtoFOA(thePEBody.Functions_Names[i], thePEHeader)));
	}

	//��ӡ�����������
	printf("\n����������ű�----------------------- \n");
	for (int i = 0; i < thePEBody.ExportDirectory.Number_Of_Names; i++)
	{
		printf("%04X \n", thePEBody.Functions_NameOrdinals[i]);
	}

	//��ӡ������ַ
	printf("\n������ַ��----------------------- \n");
	for (unsigned int i = 0; i < thePEBody.ExportDirectory.Number_Of_Functions; i++)
	{
		printf("%08X \n", thePEBody.Functions_Address[i]);
	}
}
//��ӡ�ض�λĿ¼����ӳ���
void printRelocationDirectory()
{
	printf("\n�ض�λĿ¼----------------------- \n");
	for (int i = 0; i < thePEBody.ReloactionDirectory.NumberOfBlock; i++)
	{
		printf("�ض�λ��%2d�� ", i);
		printf("Virtual_Address=%08X  ", thePEBody.ReloactionDirectory.Block[i].Virtual_Address);
		printf("Size_Of_Block=%08X \n", thePEBody.ReloactionDirectory.Block[i].Size_Of_Block);
		for (int j = 0; j < (thePEBody.ReloactionDirectory.Block[i].Size_Of_Block - 0x8) / 0x2; j++)
		{
			printf("�ض�λ��offset=%X ", thePEBody.ReloactionDirectory.Block[i].Item[j].Offset);
			printf("�ض�λ��type=%X \n", thePEBody.ReloactionDirectory.Block[i].Item[j].Type);
		}
	}
}
void printBoundImportDirectory()
{
	printf("\n�󶨵���Ŀ¼----------------------- \n");
	for (unsigned int i = 0; i < thePEBody.NumberOfBoundImportDirectory; i++)
	{
		printf("�� %d ���󶨵���Ŀ¼: ", i);
		printf("ʱ���=%08X   ", thePEBody.BoundImportDirectory[i].TimeDateStamp);
		//DLL���ֵ�RVA = �󶨵���Ŀ¼�׵�ַRVAֵ + OffsetModuleName
		unsigned int nameStr_RVA = thePEBody.BoundImportDirectory[i].OffsetModuleName + thePEHeader.OptionalHeader.bound_import_directory_offset;
		unsigned int nameStr_FOA = convertRVAtoFOA(nameStr_RVA, thePEHeader);
		char* nameStr = (char*)(pFileBuffer + nameStr_FOA);
		printf("DLL�����ַ���=%s    ", nameStr);

		printf("NumberOfModuleForwarderRefs����DLL����=%04X \n", thePEBody.BoundImportDirectory[i].NumberOfModuleForwarderRefs);
	}
}

void printPEBody()
{
	//��ӡ����Ŀ¼����ӳ���
	printExportDirectory();

	//��ӡ�ض�λĿ¼
	//printRelocationDirectory();	

	//��ӡ����Ŀ¼����ӳ���
	PrintImportDirectory(thePEHeader, thePEBody, pFileBuffer);

	//��ӡ�󶨵���Ŀ¼
	printBoundImportDirectory();
}


//EXE����ں���
int main(int argc, char* argv[])
{
	filePath_read = "C:\\Users\\41388\\Desktop\\src.exe";
	filePath_write = "C:\\Users\\41388\\Desktop\\dest.exe";

	//���ļ���fileBuffer
	//int fileLength = readPEFile(filePath_read, OUT &pFileBuffer);

	//��ӡfileBuffer
	//printFileBuffer(pFileBuffer, fileLength);

	//����PE����
	//AnalyzePE_FileBuffer_x86(pFileBuffer, &thePEHeader, &thePEBody);

	//��FileBuffer���쵽ImageBuffer
	//PBYTE pImageBuffer = NULL;
	//FileBufferToImageBuffer(pFileBuffer, OUT &pImageBuffer, thePEHeader);

	//��ImageBuffer�������(����MessageBoxA����)
	//insertCode(pImageBuffer);

	//����һ��
	//addSection(&thePEHeader, &thePEBody, filePath_read, pFileBuffer, "newnew", 0x1000);

	//ͨ�����������Һ�����ַ D3D10Hook_SwapChain_Present_imp
	//unsigned int funcAddress= getFuncAddressByName("D3D10Hook_DrawIndexed_imp", pFileBuffer, thePEHeader, thePEBody);
	//printf("���ݺ��������Һ�����ַ��%08X \n", funcAddress);

	//ͨ���߼���Ų麯����ַ
	//printf("�����߼���Ų麯����ַ: %08X \n",getFuncAddressByLogicalOrdinal(3,thePEBody));


	//��ImagaBufferת����NewBuffer
	//PBYTE pNewBuffer = NULL;
	//int length_NewBuffer = thePEHeader.SectionHeader.pointer_to_raw_data[thePEHeader.COFFHeader.number_of_section - 1] + thePEHeader.SectionHeader.size_Of_raw_data[thePEHeader.COFFHeader.number_of_section - 1];
	//imageBufferToNewBuffer(pImageBuffer, &pNewBuffer, length_NewBuffer, thePEHeader);
	//newBufferд���ļ�
	//writePEFile(filePath_write, length_NewBuffer, pNewBuffer);

	//�ƶ�����Ŀ¼
	//moveExportDirectory(&thePEHeader, &thePEBody,filePath_read, pFileBuffer);

	//�ƶ��ض�λĿ¼
	//moveRelocationDirectory(&thePEHeader, &thePEBody, filePath_read, pFileBuffer);

	//��ӡPEͷ
	//printPEHeader();

	//��ӡPEBody
	//printPEBody();

	//��������
	//traversalProcess();

	//�ӿ�
	//addShell("D:\\Users\\voila\\Desktop\\src.exe", "D:\\Users\\voila\\Desktop\\��Ŀ\\PETOOLS\\Debug\\shell.exe");

	//Զ���߳�DLLע��Ŀ�����(�����64λ����һЩ�������޷�ע����Win10������)
	RemoteThreadInject_X64("Overwatch.exe", TEXT("C:\\Users\\41388\\source\\repos\\D3D11-Wallhack\\x64\\Debug\\d3d11hook.dll"));
	//RemoteThreadInject_X86(TEXT("cstrike.exe"), TEXT("C:\\Users\\41388\\source\\repos\\D3D11-Wallhack\\Debug\\d3d11hook.dll"));
	//RemoteThreadInject_X64(TEXT("Overwatch.exe"), TEXT("C:\\Users\\41388\\Desktop\\MalwareDllX64.dll"));

	//����Ŀ��EXE,�����Կ�ִ��ս��exe(���ͬĿ¼��)
	//LoadExe_x86("dest.exe");

	//����ʽע�루�����Release��
	//ReflectInject_X86("cstrike.exe");
	ReflectInject_X86("cloudmusic.exe");

	//����ȫ�ּ��̹���
	//Hook_MessageHook();

	//IAT Hook
	//Hook_IATHook_x86("USER32.dll","MessageBoxA",(DWORD)Hook_MyMessageBox);

	//Inline Hook
	//InlineHook_X86(TEXT("USER32.dll"), TEXT("MessageBoxA"),(DWORD)InlineHook_MyMessageBoxA_X86,5);

	
	getchar();
}

// <summary>
//	����һ��DLL��ʼ������
// </summary>
// <param name="lpThreadParameter"></param>
DWORD WINAPI initDLL(LPVOID lpThreadParameter)
{
	//��������̨
	AllocConsole();
	freopen("conout$", "w", stdout);
	while (true)
	{
		printf("hello wolrd!\n");
		Sleep(2222);
	}
	return 0;
}
//DLL����ں���
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	HANDLE hThread = 0;
	switch (ul_reason_for_call)
	{

	case DLL_PROCESS_ATTACH://��DLL������ʱ
		//��Ŀ������п���һ���߳���һЩ��
		MessageBox(0, TEXT("����DLL..."), TEXT("����~"), MB_OK);
		hThread = CreateThread(NULL, 0, initDLL, NULL, 0, NULL);
		break;
	case DLL_PROCESS_DETACH: //��DLL��ж��ʱ
	{
		MessageBox(0, TEXT("DLL��ж��..."), TEXT("����~"), MB_OK);
	}
	break;
	default:
		break;
	}
	return TRUE;
}



