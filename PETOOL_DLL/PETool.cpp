#include "stdafx.h"

// <summary>
// 分析PE参数(根据FileBuffer)(x86)
// </summary>
// <param name="pFileBuffer"></param>
// <param name="pPEHeader"></param>
// <param name="pPEBody"></param>
void AnalyzePE_FileBuffer_x86(PBYTE pFileBuffer, OUT PEHeader* pPEHeader, OUT PEBody* pPEBody)
{
	//先初始化为0
	memset(pPEHeader, 0x0, sizeof(PEHeader));
	memset(pPEBody, 0x0, sizeof(PEBody));

	//-----------------分析PEHeader---------
	//分析【DOS头】
	pPEHeader->DOSHeader.MZ = *((unsigned short*)pFileBuffer);
	pPEHeader->DOSHeader.offset_to_PE_signature = *((DWORD*)(pFileBuffer + 0x3C));
	//分析【标准PE头】
	pPEHeader->COFFHeader.number_of_section = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x6));
	pPEHeader->COFFHeader.size_of_optional_Headers = *((unsigned short*)(pFileBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x14));
	//分析【可选PE头】
	pPEHeader->OptionalHeader.size_of_image = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x50));
	pPEHeader->OptionalHeader.size_of_headers = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x54));
	pPEHeader->OptionalHeader.address_of_entry_point = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x18 + 0x10));
	pPEHeader->OptionalHeader.image_base = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x18 + 0x1C));
	//分析【可选PE头】的数据目录
	pPEHeader->OptionalHeader.export_directory_offset = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x18 + 0x60 + 0x8 * 0)); //导出目录的RVA：数据目录第1个
	pPEHeader->OptionalHeader.relocation_directory_offset = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x18 + 0x60 + 0x8 * 5));//重定位目录的RVA：数据目录第6个
	pPEHeader->OptionalHeader.import_directory_offset = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x18 + 0x60 + 0x8 * 1)); //导入目录的RVA：数据目录第2个
	pPEHeader->OptionalHeader.bound_import_directory_offset = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x18 + 0x60 + 0x8 * 11)); //绑定导入目录的RVA：数据目录第12个

																																								  //根据"节数量"，申请内存，类似数组
	pPEHeader->SectionHeader.section_name = (unsigned long long*) malloc(sizeof(unsigned long long)*pPEHeader->COFFHeader.number_of_section);
	pPEHeader->SectionHeader.virtual_size = (DWORD*)malloc(sizeof(DWORD)*pPEHeader->COFFHeader.number_of_section);
	pPEHeader->SectionHeader.virtual_address = (DWORD*)malloc(sizeof(DWORD)*pPEHeader->COFFHeader.number_of_section);
	pPEHeader->SectionHeader.size_Of_raw_data = (DWORD*)malloc(sizeof(DWORD)*pPEHeader->COFFHeader.number_of_section);
	pPEHeader->SectionHeader.pointer_to_raw_data = (DWORD*)malloc(sizeof(DWORD)*pPEHeader->COFFHeader.number_of_section);
	for (int i = 0; i < pPEHeader->COFFHeader.number_of_section; i++)
	{
		pPEHeader->SectionHeader.section_name[i] = *((unsigned long long*)(pFileBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x18 + pPEHeader->COFFHeader.size_of_optional_Headers + i * 40 + 0x0));
		pPEHeader->SectionHeader.virtual_size[i] = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x18 + pPEHeader->COFFHeader.size_of_optional_Headers + i * 40 + 0x8));
		pPEHeader->SectionHeader.virtual_address[i] = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x18 + pPEHeader->COFFHeader.size_of_optional_Headers + i * 40 + 0xC));
		pPEHeader->SectionHeader.size_Of_raw_data[i] = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x18 + pPEHeader->COFFHeader.size_of_optional_Headers + i * 40 + 0x10));
		pPEHeader->SectionHeader.pointer_to_raw_data[i] = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x18 + pPEHeader->COFFHeader.size_of_optional_Headers + i * 40 + 0x14));
	}
	//-----------------分析PEBody---------
	//判断导出目录是否存在
	if (pPEHeader->OptionalHeader.export_directory_offset != 0x0)
	{
		//分析【导出目录】
		DWORD exportDirectory_FOA = convertRVAtoFOA(pPEHeader->OptionalHeader.export_directory_offset, *pPEHeader);
		pPEBody->ExportDirectory.Base = *(DWORD*)(pFileBuffer + exportDirectory_FOA + 0x4 * 0x4);
		pPEBody->ExportDirectory.Number_Of_Functions = *(DWORD*)(pFileBuffer + exportDirectory_FOA + 0x5 * 0x4);
		pPEBody->ExportDirectory.Number_Of_Names = *(DWORD*)(pFileBuffer + exportDirectory_FOA + 0x6 * 0x4);
		pPEBody->ExportDirectory.Address_Of_Functions = *(DWORD*)(pFileBuffer + exportDirectory_FOA + 0x7 * 0x4);
		pPEBody->ExportDirectory.Address_Of_Names = *(DWORD*)(pFileBuffer + exportDirectory_FOA + 0x8 * 0x4);
		pPEBody->ExportDirectory.Address_Of_NameOrdinals = *(DWORD*)(pFileBuffer + exportDirectory_FOA + 0x9 * 0x4);

		//分析由【导出目录】映射的【函数名称表】【函数名称序号表】
		pPEBody->Functions_Address = (DWORD *)malloc(sizeof(DWORD)*pPEBody->ExportDirectory.Number_Of_Functions);
		pPEBody->Functions_Names = (DWORD *)malloc(sizeof(DWORD)*pPEBody->ExportDirectory.Number_Of_Names);
		pPEBody->Functions_NameOrdinals = (unsigned short *)malloc(sizeof(DWORD)*pPEBody->ExportDirectory.Number_Of_Names);
		for (DWORD i = 0; i < pPEBody->ExportDirectory.Number_Of_Names; i++)
		{
			pPEBody->Functions_Names[i] = *(DWORD*)(pFileBuffer + convertRVAtoFOA(pPEBody->ExportDirectory.Address_Of_Names, *pPEHeader) + 0x4 * i);
			pPEBody->Functions_NameOrdinals[i] = *(unsigned short*)(pFileBuffer + convertRVAtoFOA(pPEBody->ExportDirectory.Address_Of_NameOrdinals, *pPEHeader) + 0x2 * i);
		}
		//分析由【导出目录】映射的【函数地址表】
		for (DWORD i = 0; i < pPEBody->ExportDirectory.Number_Of_Functions; i++)
		{
			pPEBody->Functions_Address[i] = *(DWORD*)(pFileBuffer + convertRVAtoFOA(pPEBody->ExportDirectory.Address_Of_Functions, *pPEHeader) + 0x4 * i);
		}
	}
	//分析【重定位目录】
	//先判断重定位目录是否存在
	if (pPEHeader->OptionalHeader.relocation_directory_offset != 0x0)
	{
		DWORD BlockStart_FOA = convertRVAtoFOA(pPEHeader->OptionalHeader.relocation_directory_offset, *pPEHeader);
		//计算重定位块的块数，申请堆空间
		pPEBody->ReloactionDirectory.NumberOfBlock = calcNumberOfBlock(BlockStart_FOA, *pPEHeader, pFileBuffer);
		pPEBody->ReloactionDirectory.Block = (Block*)malloc(sizeof(Block)*pPEBody->ReloactionDirectory.NumberOfBlock);
		for (int i = 0; i < pPEBody->ReloactionDirectory.NumberOfBlock; i++)
		{

			pPEBody->ReloactionDirectory.Block[i].Virtual_Address = *(DWORD*)(pFileBuffer + BlockStart_FOA + 0x0);
			pPEBody->ReloactionDirectory.Block[i].Size_Of_Block = *(DWORD*)(pFileBuffer + BlockStart_FOA + 0x4);
			int numberOfItem = (pPEBody->ReloactionDirectory.Block[i].Size_Of_Block - 0x8) / 0x2;
			pPEBody->ReloactionDirectory.Block[i].Item = (Item*)malloc(sizeof(Item)*numberOfItem);
			for (int index = 0; index < numberOfItem; index++)
			{
				pPEBody->ReloactionDirectory.Block[i].Item[index].Offset = *(unsigned short *)(pFileBuffer + BlockStart_FOA + 0x8 + 0x2 * index) & 0x0FFF;
				pPEBody->ReloactionDirectory.Block[i].Item[index].Type = *(unsigned short *)(pFileBuffer + BlockStart_FOA + 0x8 + 0x2 * index) >> 12;
			}
			BlockStart_FOA += pPEBody->ReloactionDirectory.Block[i].Size_Of_Block;
		}
	}

	//分析【导入目录】
	//先判断导入目录是否存在
	if (pPEHeader->OptionalHeader.import_directory_offset != 0x0)
	{
		//计算导入目录的个数
		DWORD FirstImportDir_FOA = convertRVAtoFOA(pPEHeader->OptionalHeader.import_directory_offset, *pPEHeader);
		DWORD DirSize = sizeof(ImportDirectory);//单个导入目录Size
		while (true)
		{
			ImportDirectory temp = *(ImportDirectory*)(pFileBuffer + FirstImportDir_FOA + pPEBody->NumberOfImportDirectory * DirSize);
			if (temp.FirstThunk == 0x0 && temp.ForwarderChain == 0x0 && temp.Name == 0x0 && temp.OriginalFirstThunk == 0x0 && temp.TimeDateStamp == 0x0)//判断结构体全为0x0
			{
				break;
			}
			pPEBody->NumberOfImportDirectory++;
		}

		//根据导入目录个数，申请堆空间
		pPEBody->ImportDirectory = (ImportDirectory*)malloc(sizeof(ImportDirectory)*pPEBody->NumberOfImportDirectory);
		pPEBody->INT_Table = (INT_Table*)malloc(sizeof(INT_Table)* pPEBody->NumberOfImportDirectory);
		pPEBody->IAT_Table = (IAT_Table*)malloc(sizeof(IAT_Table)* pPEBody->NumberOfImportDirectory);
		memset(pPEBody->INT_Table, 0x0, sizeof(INT_Table)* pPEBody->NumberOfImportDirectory);
		memset(pPEBody->IAT_Table, 0x0, sizeof(IAT_Table)* pPEBody->NumberOfImportDirectory);
		memset(pPEBody->ImportDirectory, 0x0, sizeof(ImportDirectory)*pPEBody->NumberOfImportDirectory);

		//逐个分析
		for (DWORD i = 0; i < pPEBody->NumberOfImportDirectory; i++)
		{
			//分析导入目录
			pPEBody->ImportDirectory[i].OriginalFirstThunk = *(DWORD*)(pFileBuffer + FirstImportDir_FOA + i * DirSize + 0x0 * 0x4);
			pPEBody->ImportDirectory[i].TimeDateStamp = *(DWORD*)(pFileBuffer + FirstImportDir_FOA + i * DirSize + 0x1 * 0x4);
			pPEBody->ImportDirectory[i].ForwarderChain = *(DWORD*)(pFileBuffer + FirstImportDir_FOA + i * DirSize + 0x2 * 0x4);
			pPEBody->ImportDirectory[i].Name = *(DWORD*)(pFileBuffer + FirstImportDir_FOA + i * DirSize + 0x3 * 0x4);
			pPEBody->ImportDirectory[i].FirstThunk = *(DWORD*)(pFileBuffer + FirstImportDir_FOA + i * DirSize + 0x4 * 0x4);

			//分析INT表的项个数
			if (pPEBody->ImportDirectory[i].OriginalFirstThunk == 0)
			{//如果OriginalFirstThunk=0则表示INT表为空，我用未拉伸前的IAT表作为INT表 (因为未拉伸前的IAT和INT相同)
				printf("注意：此fileBuffer将INT表设为空，故将未拉伸前的IAT表作为INT表... \n");
				pPEBody->ImportDirectory[i].OriginalFirstThunk = pPEBody->ImportDirectory[i].FirstThunk;
			}
			DWORD OriginalFirstThunk_FOA = convertRVAtoFOA(pPEBody->ImportDirectory[i].OriginalFirstThunk, *pPEHeader);
			while (true)
			{
				if (*(DWORD*)(pFileBuffer + OriginalFirstThunk_FOA + pPEBody->INT_Table[i].NumberOfItem * 0x4) == 0x0)
				{
					break;
				}
				pPEBody->INT_Table[i].NumberOfItem++;
			}
			//分析IAT表的项个数
			DWORD FirstThunk_FOA = convertRVAtoFOA(pPEBody->ImportDirectory[i].FirstThunk, *pPEHeader);
			while (true)
			{
				if (*(DWORD*)(pFileBuffer + FirstThunk_FOA + pPEBody->IAT_Table[i].NumberOfItem * 0x4) == 0x0)
				{
					break;
				}
				pPEBody->IAT_Table[i].NumberOfItem++;
			}

			//根据INT表的项个数，申请堆内存
			pPEBody->INT_Table[i].IMAGE_THUNK_DATA = (DWORD *)malloc(pPEBody->INT_Table[i].NumberOfItem * 0x4);

			//根据IAT表的项个数，申请堆内存
			pPEBody->IAT_Table[i].funcAddress = (DWORD *)malloc(pPEBody->IAT_Table[i].NumberOfItem * 0x4);

			//为INT表的每个项赋值
			for (DWORD j = 0; j < pPEBody->INT_Table[i].NumberOfItem; j++)
			{
				pPEBody->INT_Table[i].IMAGE_THUNK_DATA[j] = *(DWORD *)(pFileBuffer + OriginalFirstThunk_FOA + j * 0x4);
			}

			//为IAT表的每个项赋值
			for (DWORD j = 0; j < pPEBody->IAT_Table[i].NumberOfItem; j++)
			{
				pPEBody->IAT_Table[i].funcAddress[j] = *(DWORD *)(pFileBuffer + FirstThunk_FOA + j * 0x4);
			}

		}
	}

	//分析【绑定导入目录】：使用动态数组的思路申请内存(循环申请和释放)
	//先判断存在
	if (pPEHeader->OptionalHeader.bound_import_directory_offset != 0x0)
	{
		//计算【绑定导入目录】的首地址的FOA，注意实际上因为这个FOA、RVA处于节表中，故不需要转换
		DWORD Dir_FOA = convertRVAtoFOA(pPEHeader->OptionalHeader.bound_import_directory_offset, *pPEHeader);
		//当前游标
		DWORD cursor_FOA = Dir_FOA;

		while (true)
		{
			//判断一个全0的8字节结构，即为结束标识
			BoundImportDirectory temp = *(BoundImportDirectory*)(pFileBuffer + cursor_FOA);
			if (temp.NumberOfModuleForwarderRefs == 0x0 && temp.OffsetModuleName == 0x0 && temp.TimeDateStamp == 0x0)
			{
				break;
			}

			//【绑定导入目录】的个数+1
			pPEBody->NumberOfBoundImportDirectory++;

			//保存上一轮循环所申请的堆内存指针
			BoundImportDirectory* lastPoint = pPEBody->BoundImportDirectory;

			//申请当前循环的【绑定导入目录】的堆内存
			pPEBody->BoundImportDirectory = (BoundImportDirectory*)malloc(sizeof(BoundImportDirectory)*pPEBody->NumberOfBoundImportDirectory);
			memset(pPEBody->BoundImportDirectory, 0x0, sizeof(BoundImportDirectory)*pPEBody->NumberOfBoundImportDirectory);

			//分配当前循环的【绑定导入目录】的参数
			pPEBody->BoundImportDirectory[pPEBody->NumberOfBoundImportDirectory - 1].TimeDateStamp = *(DWORD*)(pFileBuffer + cursor_FOA);
			pPEBody->BoundImportDirectory[pPEBody->NumberOfBoundImportDirectory - 1].OffsetModuleName = *(unsigned short*)(pFileBuffer + cursor_FOA + 0x4);
			pPEBody->BoundImportDirectory[pPEBody->NumberOfBoundImportDirectory - 1].NumberOfModuleForwarderRefs = *(unsigned short*)(pFileBuffer + cursor_FOA + 0x4 + 0x2);

			//当前循环的【绑定导入目录】的BoundForwarderRef结构的参数
			pPEBody->BoundImportDirectory[pPEBody->NumberOfBoundImportDirectory - 1].BoundForwarderRef = (BoundForwarderRef*)malloc(sizeof(BoundForwarderRef)*pPEBody->BoundImportDirectory[pPEBody->NumberOfBoundImportDirectory - 1].NumberOfModuleForwarderRefs);
			memset(pPEBody->BoundImportDirectory[pPEBody->NumberOfBoundImportDirectory - 1].BoundForwarderRef, 0x0, sizeof(BoundForwarderRef)*pPEBody->BoundImportDirectory[pPEBody->NumberOfBoundImportDirectory - 1].NumberOfModuleForwarderRefs);
			for (DWORD i = 0; i < pPEBody->BoundImportDirectory[pPEBody->NumberOfBoundImportDirectory - 1].NumberOfModuleForwarderRefs; i++)
			{
				pPEBody->BoundImportDirectory[pPEBody->NumberOfBoundImportDirectory - 1].BoundForwarderRef[i].TimeDateStamp = *(DWORD*)(pFileBuffer + cursor_FOA + 0x8 + i * 0x8);
				pPEBody->BoundImportDirectory[pPEBody->NumberOfBoundImportDirectory - 1].BoundForwarderRef[i].OffsetModuleName = *(DWORD*)(pFileBuffer + cursor_FOA + 0x8 + i * 0x8 + 0x4);
				pPEBody->BoundImportDirectory[pPEBody->NumberOfBoundImportDirectory - 1].BoundForwarderRef[i].Reserved = *(DWORD*)(pFileBuffer + cursor_FOA + 0x8 + i * 0x8 + 0x4 + 0x2);
			}

			//从第2轮循环开始
			if (pPEBody->NumberOfBoundImportDirectory >= 2)
			{
				//将上一次循环申请的堆内存 复制到 新的堆内存
				memcpy(pPEBody->BoundImportDirectory, lastPoint, sizeof(BoundImportDirectory)*(pPEBody->NumberOfBoundImportDirectory - 1));

				//将上一次循环申请的堆内存释放
				free(lastPoint);
			}


			//游标移至下一个绑定导入目录
			cursor_FOA += (pPEBody->BoundImportDirectory[pPEBody->NumberOfBoundImportDirectory - 1].NumberOfModuleForwarderRefs * 0x8 + 0x8);

		}

	}

}

// <summary>
// 分析PE参数(根据ImageBuffer)(x86)
// </summary>
// <param name="pImageBuffer"></param>
// <param name="pPEHeader"></param>
// <param name="pPEBody"></param>
VOID AnalyzePE_ImageBuffer_x86(PBYTE pImageBuffer, OUT PEHeader* pPEHeader, OUT PEBody* pPEBody)
{
	//先初始化为0
	memset(pPEHeader, 0x0, sizeof(PEHeader));
	memset(pPEBody, 0x0, sizeof(PEBody));

	//分析PEHeader(与FileBuffer的分析相同)
	//【DOS头】
	pPEHeader->DOSHeader.MZ = *((unsigned short*)pImageBuffer);
	pPEHeader->DOSHeader.offset_to_PE_signature = *((DWORD*)(pImageBuffer + 0x3C));
	//【标准PE头】
	pPEHeader->COFFHeader.number_of_section = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x6));
	pPEHeader->COFFHeader.size_of_optional_Headers = *((unsigned short*)(pImageBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x14));
	//【可选PE头】
	pPEHeader->OptionalHeader.size_of_image = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x50));
	pPEHeader->OptionalHeader.size_of_headers = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x54));
	pPEHeader->OptionalHeader.address_of_entry_point = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x18 + 0x10));
	pPEHeader->OptionalHeader.image_base = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x18 + 0x1C));
	//【可选PE头之数据目录】
	pPEHeader->OptionalHeader.export_directory_offset = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x18 + 0x60 + 0x8 * 0)); //导出目录的RVA：数据目录第1个
	pPEHeader->OptionalHeader.relocation_directory_offset = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x18 + 0x60 + 0x8 * 5));//重定位目录的RVA：数据目录第6个
	pPEHeader->OptionalHeader.import_directory_offset = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x18 + 0x60 + 0x8 * 1)); //导入目录的RVA：数据目录第2个
	pPEHeader->OptionalHeader.bound_import_directory_offset = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x18 + 0x60 + 0x8 * 11)); //绑定导入目录的RVA：数据目录第12个
	//【可选PE头之节表】																																								  //根据"节数量"，申请内存，类似数组
	pPEHeader->SectionHeader.section_name = (unsigned long long*) malloc(sizeof(unsigned long long)*pPEHeader->COFFHeader.number_of_section);
	pPEHeader->SectionHeader.virtual_size = (DWORD*)malloc(sizeof(DWORD)*pPEHeader->COFFHeader.number_of_section);
	pPEHeader->SectionHeader.virtual_address = (DWORD*)malloc(sizeof(DWORD)*pPEHeader->COFFHeader.number_of_section);
	pPEHeader->SectionHeader.size_Of_raw_data = (DWORD*)malloc(sizeof(DWORD)*pPEHeader->COFFHeader.number_of_section);
	pPEHeader->SectionHeader.pointer_to_raw_data = (DWORD*)malloc(sizeof(DWORD)*pPEHeader->COFFHeader.number_of_section);
	for (int i = 0; i < pPEHeader->COFFHeader.number_of_section; i++)
	{
		pPEHeader->SectionHeader.section_name[i] = *((unsigned long long*)(pImageBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x18 + pPEHeader->COFFHeader.size_of_optional_Headers + i * 40 + 0x0));
		pPEHeader->SectionHeader.virtual_size[i] = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x18 + pPEHeader->COFFHeader.size_of_optional_Headers + i * 40 + 0x8));
		pPEHeader->SectionHeader.virtual_address[i] = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x18 + pPEHeader->COFFHeader.size_of_optional_Headers + i * 40 + 0xC));
		pPEHeader->SectionHeader.size_Of_raw_data[i] = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x18 + pPEHeader->COFFHeader.size_of_optional_Headers + i * 40 + 0x10));
		pPEHeader->SectionHeader.pointer_to_raw_data[i] = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x18 + pPEHeader->COFFHeader.size_of_optional_Headers + i * 40 + 0x14));
	}
	//-------分析PEBody---------
	//分析【导出目录】
	if (pPEHeader->OptionalHeader.export_directory_offset != 0x0)
	{//判断【导出目录】是否存在
		DWORD RVA = pPEHeader->OptionalHeader.export_directory_offset;
		pPEBody->ExportDirectory.Base = *(DWORD*)(pImageBuffer + RVA + 0x4 * 0x4);
		pPEBody->ExportDirectory.Number_Of_Functions = *(DWORD*)(pImageBuffer + RVA + 0x5 * 0x4);
		pPEBody->ExportDirectory.Number_Of_Names = *(DWORD*)(pImageBuffer + RVA + 0x6 * 0x4);
		pPEBody->ExportDirectory.Address_Of_Functions = *(DWORD*)(pImageBuffer + RVA + 0x7 * 0x4);
		pPEBody->ExportDirectory.Address_Of_Names = *(DWORD*)(pImageBuffer + RVA + 0x8 * 0x4);
		pPEBody->ExportDirectory.Address_Of_NameOrdinals = *(DWORD*)(pImageBuffer + RVA + 0x9 * 0x4);

		//分析由【导出目录】映射的【函数名称表】【函数名称序号表】
		pPEBody->Functions_Address = (DWORD *)malloc(sizeof(DWORD)*pPEBody->ExportDirectory.Number_Of_Functions);
		pPEBody->Functions_Names = (DWORD *)malloc(sizeof(DWORD)*pPEBody->ExportDirectory.Number_Of_Names);
		pPEBody->Functions_NameOrdinals = (unsigned short *)malloc(sizeof(DWORD)*pPEBody->ExportDirectory.Number_Of_Names);
		for (DWORD i = 0; i < pPEBody->ExportDirectory.Number_Of_Names; i++)
		{
			pPEBody->Functions_Names[i] = *(DWORD*)(pImageBuffer + pPEBody->ExportDirectory.Address_Of_Names + 0x4 * i);
			pPEBody->Functions_NameOrdinals[i] = *(unsigned short*)(pImageBuffer + pPEBody->ExportDirectory.Address_Of_NameOrdinals + 0x2 * i);
		}
		//分析由【导出目录】映射的【函数地址表】
		for (DWORD i = 0; i < pPEBody->ExportDirectory.Number_Of_Functions; i++)
		{
			pPEBody->Functions_Address[i] = *(DWORD*)(pImageBuffer + pPEBody->ExportDirectory.Address_Of_Functions + 0x4 * i);
		}
	}
	//分析【重定位目录】
	if (pPEHeader->OptionalHeader.relocation_directory_offset != 0x0)
	{//先判断重定位目录是否存在

		DWORD RVA = pPEHeader->OptionalHeader.relocation_directory_offset;
		//计算重定位块的块数，申请堆空间
		pPEBody->ReloactionDirectory.NumberOfBlock = calcNumberOfBlock(RVA, *pPEHeader, pImageBuffer);
		pPEBody->ReloactionDirectory.Block = (Block*)malloc(sizeof(Block)*pPEBody->ReloactionDirectory.NumberOfBlock);
		for (int i = 0; i < pPEBody->ReloactionDirectory.NumberOfBlock; i++)
		{
			pPEBody->ReloactionDirectory.Block[i].Virtual_Address = *(DWORD*)(pImageBuffer + RVA + 0x0);
			pPEBody->ReloactionDirectory.Block[i].Size_Of_Block = *(DWORD*)(pImageBuffer + RVA + 0x4);
			int numberOfItem = (pPEBody->ReloactionDirectory.Block[i].Size_Of_Block - 0x8) / 0x2;
			pPEBody->ReloactionDirectory.Block[i].Item = (Item*)malloc(sizeof(Item)*numberOfItem);
			for (int index = 0; index < numberOfItem; index++)
			{
				pPEBody->ReloactionDirectory.Block[i].Item[index].Offset = *(unsigned short *)(pImageBuffer + RVA + 0x8 + 0x2 * index) & 0x0FFF;
				pPEBody->ReloactionDirectory.Block[i].Item[index].Type = *(unsigned short *)(pImageBuffer + RVA + 0x8 + 0x2 * index) >> 12;
			}
			RVA += pPEBody->ReloactionDirectory.Block[i].Size_Of_Block;
		}
	}

	//分析【导入目录】
	if (pPEHeader->OptionalHeader.import_directory_offset != 0x0)
	{//先判断导入目录是否存在

		//计算导入目录的个数
		DWORD RVA = pPEHeader->OptionalHeader.import_directory_offset;
		DWORD DirSize = sizeof(ImportDirectory);//单个导入目录Size
		while (true)
		{
			ImportDirectory temp = *(ImportDirectory*)(pImageBuffer + RVA + pPEBody->NumberOfImportDirectory * DirSize);
			if (temp.FirstThunk == 0x0 && temp.ForwarderChain == 0x0 && temp.Name == 0x0 && temp.OriginalFirstThunk == 0x0 && temp.TimeDateStamp == 0x0)//判断结构体全为0x0
			{
				break;
			}
			pPEBody->NumberOfImportDirectory++;
		}

		//根据导入目录个数，申请堆空间
		pPEBody->ImportDirectory = (ImportDirectory*)malloc(sizeof(ImportDirectory)*pPEBody->NumberOfImportDirectory);
		pPEBody->INT_Table = (INT_Table*)malloc(sizeof(INT_Table)* pPEBody->NumberOfImportDirectory);
		pPEBody->IAT_Table = (IAT_Table*)malloc(sizeof(IAT_Table)* pPEBody->NumberOfImportDirectory);
		memset(pPEBody->INT_Table, 0x0, sizeof(INT_Table)* pPEBody->NumberOfImportDirectory);
		memset(pPEBody->IAT_Table, 0x0, sizeof(IAT_Table)* pPEBody->NumberOfImportDirectory);
		memset(pPEBody->ImportDirectory, 0x0, sizeof(ImportDirectory)*pPEBody->NumberOfImportDirectory);

		//逐个分析
		for (DWORD i = 0; i < pPEBody->NumberOfImportDirectory; i++)
		{
			//分析导入目录
			pPEBody->ImportDirectory[i].OriginalFirstThunk = *(DWORD*)(pImageBuffer + RVA + i * DirSize + 0x0 * 0x4);
			pPEBody->ImportDirectory[i].TimeDateStamp = *(DWORD*)(pImageBuffer + RVA + i * DirSize + 0x1 * 0x4);
			pPEBody->ImportDirectory[i].ForwarderChain = *(DWORD*)(pImageBuffer + RVA + i * DirSize + 0x2 * 0x4);
			pPEBody->ImportDirectory[i].Name = *(DWORD*)(pImageBuffer + RVA + i * DirSize + 0x3 * 0x4);
			pPEBody->ImportDirectory[i].FirstThunk = *(DWORD*)(pImageBuffer + RVA + i * DirSize + 0x4 * 0x4);

			//分析INT表的项个数
			DWORD RVA_OriginalFirstThunk = pPEBody->ImportDirectory[i].OriginalFirstThunk;
			while (true)
			{
				if (*(DWORD*)(pImageBuffer + RVA_OriginalFirstThunk + pPEBody->INT_Table[i].NumberOfItem * 0x4) == 0x0)
				{
					break;
				}
				pPEBody->INT_Table[i].NumberOfItem++;
			}
			if (pPEBody->ImportDirectory[i].OriginalFirstThunk == 0x0)
			{
				printf("错误：imageBuffer中的INT表为空，考虑用其他方法获取导入函数的名称... \n");
				pPEBody->INT_Table[i].NumberOfItem = 0;
			}
			//分析IAT表的项个数
			DWORD RVA_FirstThunk = pPEBody->ImportDirectory[i].FirstThunk;
			while (true)
			{
				if (*(DWORD*)(pImageBuffer + RVA_FirstThunk + pPEBody->IAT_Table[i].NumberOfItem * 0x4) == 0x0)
				{
					break;
				}
				pPEBody->IAT_Table[i].NumberOfItem++;
			}
			//根据INT表的项个数，申请堆内存
			pPEBody->INT_Table[i].IMAGE_THUNK_DATA = (DWORD *)malloc(pPEBody->INT_Table[i].NumberOfItem * 0x4);

			//根据IAT表的项个数，申请堆内存
			pPEBody->IAT_Table[i].funcAddress = (DWORD *)malloc(pPEBody->IAT_Table[i].NumberOfItem * 0x4);

			//为INT表的每个项赋值
			for (DWORD j = 0; j < pPEBody->INT_Table[i].NumberOfItem; j++)
			{
				pPEBody->INT_Table[i].IMAGE_THUNK_DATA[j] = *(DWORD *)(pImageBuffer + RVA_OriginalFirstThunk + j * 0x4);
			}
			//为IAT表的每个项赋值
			for (DWORD j = 0; j < pPEBody->IAT_Table[i].NumberOfItem; j++)
			{
				pPEBody->IAT_Table[i].funcAddress[j] = *(DWORD *)(pImageBuffer + RVA_FirstThunk + j * 0x4);
			}
		}
	}

	//分析【绑定导入目录】：使用动态数组的思路申请内存(循环申请和释放)
	//先判断存在
	if (pPEHeader->OptionalHeader.bound_import_directory_offset != 0x0)
	{
		//计算【绑定导入目录】的首地址的FOA，注意实际上因为这个FOA、RVA处于节表中，故不需要转换
		DWORD RVA_Dir = pPEHeader->OptionalHeader.bound_import_directory_offset;
		//当前游标
		DWORD RVA_cursor = RVA_Dir;

		while (true)
		{
			//判断一个全0的8字节结构，即为结束标识
			BoundImportDirectory temp = *(BoundImportDirectory*)(pImageBuffer + RVA_cursor);
			if (temp.NumberOfModuleForwarderRefs == 0x0 && temp.OffsetModuleName == 0x0 && temp.TimeDateStamp == 0x0)
			{
				break;
			}

			//【绑定导入目录】的个数+1
			pPEBody->NumberOfBoundImportDirectory++;

			//保存上一轮循环所申请的堆内存指针
			BoundImportDirectory* lastPoint = pPEBody->BoundImportDirectory;

			//申请当前循环的【绑定导入目录】的堆内存
			pPEBody->BoundImportDirectory = (BoundImportDirectory*)malloc(sizeof(BoundImportDirectory)*pPEBody->NumberOfBoundImportDirectory);
			memset(pPEBody->BoundImportDirectory, 0x0, sizeof(BoundImportDirectory)*pPEBody->NumberOfBoundImportDirectory);

			//分配当前循环的【绑定导入目录】的参数
			pPEBody->BoundImportDirectory[pPEBody->NumberOfBoundImportDirectory - 1].TimeDateStamp = *(DWORD*)(pImageBuffer + RVA_cursor);
			pPEBody->BoundImportDirectory[pPEBody->NumberOfBoundImportDirectory - 1].OffsetModuleName = *(unsigned short*)(pImageBuffer + RVA_cursor + 0x4);
			pPEBody->BoundImportDirectory[pPEBody->NumberOfBoundImportDirectory - 1].NumberOfModuleForwarderRefs = *(unsigned short*)(pImageBuffer + RVA_cursor + 0x4 + 0x2);

			//当前循环的【绑定导入目录】的BoundForwarderRef结构的参数
			pPEBody->BoundImportDirectory[pPEBody->NumberOfBoundImportDirectory - 1].BoundForwarderRef = (BoundForwarderRef*)malloc(sizeof(BoundForwarderRef)*pPEBody->BoundImportDirectory[pPEBody->NumberOfBoundImportDirectory - 1].NumberOfModuleForwarderRefs);
			memset(pPEBody->BoundImportDirectory[pPEBody->NumberOfBoundImportDirectory - 1].BoundForwarderRef, 0x0, sizeof(BoundForwarderRef)*pPEBody->BoundImportDirectory[pPEBody->NumberOfBoundImportDirectory - 1].NumberOfModuleForwarderRefs);
			for (DWORD i = 0; i < pPEBody->BoundImportDirectory[pPEBody->NumberOfBoundImportDirectory - 1].NumberOfModuleForwarderRefs; i++)
			{
				pPEBody->BoundImportDirectory[pPEBody->NumberOfBoundImportDirectory - 1].BoundForwarderRef[i].TimeDateStamp = *(DWORD*)(pImageBuffer + RVA_cursor + 0x8 + i * 0x8);
				pPEBody->BoundImportDirectory[pPEBody->NumberOfBoundImportDirectory - 1].BoundForwarderRef[i].OffsetModuleName = *(DWORD*)(pImageBuffer + RVA_cursor + 0x8 + i * 0x8 + 0x4);
				pPEBody->BoundImportDirectory[pPEBody->NumberOfBoundImportDirectory - 1].BoundForwarderRef[i].Reserved = *(DWORD*)(pImageBuffer + RVA_cursor + 0x8 + i * 0x8 + 0x4 + 0x2);
			}

			//从第2轮循环开始
			if (pPEBody->NumberOfBoundImportDirectory >= 2)
			{
				//将上一次循环申请的堆内存 复制到 新的堆内存
				memcpy(pPEBody->BoundImportDirectory, lastPoint, sizeof(BoundImportDirectory)*(pPEBody->NumberOfBoundImportDirectory - 1));

				//将上一次循环申请的堆内存释放
				free(lastPoint);
			}
			//游标移至下一个绑定导入目录
			RVA_cursor += (pPEBody->BoundImportDirectory[pPEBody->NumberOfBoundImportDirectory - 1].NumberOfModuleForwarderRefs * 0x8 + 0x8);
		}

	}
}

//计算重定位块的块数
int calcNumberOfBlock(DWORD Block_FOA, PEHeader thePEHeader, PBYTE pFileBuffer, int count)
{
	DWORD BlockSize = *(DWORD*)(pFileBuffer + Block_FOA + 0x4);
	//判断结束标识(连续8字节都为0x0）
	if (*(unsigned long long*)(pFileBuffer + Block_FOA + BlockSize) == 0x0)
	{
		return ++count;
	}
	return calcNumberOfBlock(Block_FOA + BlockSize, thePEHeader, pFileBuffer, ++count);
}

//读PE文件至内存，返回文件长度
int readPEFile(char* filePath, OUT PBYTE* pFileBuffer_addr)
{
	printf("\n开始读文件...FilePath = %s\n", filePath);
	FILE* pFile = NULL;

	//打开一个二进制文件，允许读写
	int result = fopen_s(&pFile, filePath, "rb");

	if (result != 0)
	{
		printf("打开文件失败,code=%d \n", result);
		getchar();
		return 0;
	}

	//移动文件位置指针移到文件末尾并偏移0字节
	fseek(pFile, 0, SEEK_END);

	//获取文件指针的当前位置下标(得到文件长度)
	int length = ftell(pFile);
	printf("FileSize = %d \n", length);

	//文件指针恢复到文件开头
	fseek(pFile, 0, SEEK_SET);
	//申请内存
	*pFileBuffer_addr = (PBYTE)malloc(length);
	if (*pFileBuffer_addr == NULL)
	{
		printf("malloc失败！ \n");
		return 0;
	}
	memset(*pFileBuffer_addr, 0x0, length);
	//保存现场
	PBYTE save = *pFileBuffer_addr;

	//将文件放入内存的"堆空间"
	for (int i = 0; i < length; i++)
	{
		//fgetc返回字符的int值(自动拓展至32位)
		*(*pFileBuffer_addr + i) = (unsigned char)fgetc(pFile);
	}
	//恢复现场
	*pFileBuffer_addr = save;

	//关闭文件
	fclose(pFile);

	//返回文件长度
	return length;
}

void printFileBuffer(PBYTE entry, int length)
{
	for (int i = 0x0; i < 0x10; i++)
	{
		printf(" %x ", i);
	}
	printf("\n-------------------------------------------\n");
	for (int count = 0; count < length;)
	{
		for (int i = 0x0; i < 0x10; i++)
		{
			if (count == length)
			{
				break;
			}
			printf("%02x ", *entry++);
			count++;
		}
		printf("\n");
	}
}

//从FileBuffer拉伸至ImageBuffer
void FileBufferToImageBuffer(PBYTE pFileBuffer, OUT PBYTE* pImageBuffer_address, PEHeader PEHeader)
{
	//申请imageBuffer
	PBYTE pImageBuffer = (PBYTE)malloc(PEHeader.OptionalHeader.size_of_image);
	if (pImageBuffer == NULL)
	{
		printf("pointer is NULL \n");
		getchar();
		return;
	}
	//清理imageBuffer
	memset(pImageBuffer, 0x0, PEHeader.OptionalHeader.size_of_image);

	//根据【size of headers】将fileBuffer内的"头信息"原封不动地拷贝至imageBuffer
	for (DWORD i = 0; i < PEHeader.OptionalHeader.size_of_headers; i++)
	{

		*(pImageBuffer + i) = *(pFileBuffer + i);

	}
	//将"节信息"拉伸并拷贝至imageBuffer
	for (DWORD i = 0; i < PEHeader.COFFHeader.number_of_section; i++)
	{
		for (DWORD j = 0; j < PEHeader.SectionHeader.size_Of_raw_data[i]; j++)
		{
			*(pImageBuffer + PEHeader.SectionHeader.virtual_address[i] + j) = *(pFileBuffer + PEHeader.SectionHeader.pointer_to_raw_data[i] + j);
		}
	}
	//返回
	*pImageBuffer_address = pImageBuffer;
}
/*
从ImageBuffer还原至NewBuffer

【所需PE参数】
标准PE头：(1)Number of Section
可选PE头：(2)Size of Headers
节表	：(3)Size of Raw Data、(4)Virtual Address、(5)Pointer to Raw Data
*/
void imageBufferToNewBuffer(PBYTE pImageBuffer, PBYTE* pNewBuffer_address, int fileLength, PEHeader PEHeader)
{
	PBYTE pNewBuffer = (PBYTE)malloc(fileLength);
	if (pNewBuffer == NULL)
	{
		printf("malloc() is fail \n");
		getchar();
		return;
	}
	memset(pNewBuffer, 0x0, fileLength);
	for (DWORD i = 0; i < PEHeader.OptionalHeader.size_of_headers; i++)
	{
		*(pNewBuffer + i) = *(pImageBuffer + i);
	}
	for (DWORD i = 0; i < PEHeader.COFFHeader.number_of_section; i++)
	{
		for (DWORD j = 0; j < PEHeader.SectionHeader.size_Of_raw_data[i]; j++)
		{
			*(pNewBuffer + PEHeader.SectionHeader.pointer_to_raw_data[i] + j) = *(pImageBuffer + PEHeader.SectionHeader.virtual_address[i] + j);
		}
	}
	//返回
	*pNewBuffer_address = pNewBuffer;
}

//向ImageBuffer的代码节空白区插入代码
void insertCode(PBYTE pImageBuffer)
{
	//	//向ImageBuffer插入MessageBoxA(0,0,0,0)代码
	//	DWORD MessageBox_Code = 0x76707E90;//我这台电脑的MessageBoxA地址
	//	int index = 0;						//向第0节的空白区插入代码
	//	DWORD imageBase = 0x400000; //传入动态基地址,【War3.exe】的基地址是0x400000
	//	//待修改的硬编码
	//	unsigned char shellCode[] =
	//	{
	//		0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00,	//入参
	//		0xE8, 0x00, 0x00, 0x00, 0x00,					//调用MessageBoxA
	//		0xE9, 0x00, 0x00, 0x00, 0x00,					//跳转原入口
	//	};
	//	//向第index节的空白区插入初始代码
	//	for (int i = 0; i < sizeof(shellCode); i++)
	//	{
	//		*(pImageBuffer + (virtual_address[index] + virtual_size[index]) + i) = shellCode[i];
	//	}
	//	//修改程序入口至ShellCode
	//	*((DWORD*)(pImageBuffer + offset_to_PE_signature + 0x28)) = virtual_address[index] + virtual_size[index];
	//	//找到E8下一条指令的虚拟地址(VA)
	//	DWORD E8_nextAddr = imageBase + (virtual_address[index] + virtual_size[index]) + 0x8 + 0x5;
	//	//计算E8的X值
	//	DWORD E8_X = MessageBox_Code - E8_nextAddr;
	//	//调整E8硬编码,修改为E8_X
	//	*((DWORD*)(pImageBuffer + (virtual_address[index] + virtual_size[index]) + 0x9)) = E8_X;
	//	//找到E9下一条指令的虚拟地址(VA)
	//	DWORD E9_nextAddr = imageBase + (virtual_address[index] + virtual_size[index]) + 0x8 + 0x5 + 0x5;
	//	//计算E9的X值(跳转至原函数入口)
	//	DWORD E9_X = (imageBase + address_of_entry_point) - E9_nextAddr;
	//	//调整E9硬编码,修改为E9_X
	//	*((DWORD*)(pImageBuffer + (virtual_address[index] + virtual_size[index]) + 0x9 + 0x5)) = E9_X;
}


//将NewBuffer写到文件
void writePEFile(char* filePath, int fileLength, PBYTE pNewBuffer)
{
	printf("\n 开始写文件...\n");
	printf("File Path = %s \n", filePath);
	FILE* pNewFile = NULL;
	int errorCode = fopen_s(&pNewFile, filePath, "wb+");
	if (errorCode == 0)
	{
		for (DWORD i = 0; i < fileLength; i++)
		{
			fputc(*(pNewBuffer + i), pNewFile);
		}
	}
	else
	{
		printf("打开文件失败，错误代码=%d \n", errorCode);
		return;
	}
	fclose(pNewFile);
}


//新增一节 ,返回新节FOA, 若返回-1表示失败
DWORD addSection(PEHeader* pPEHeader, PEBody* pPEBody, char* filePath, PBYTE* pFileBuffer_addr, char* sectionName, DWORD addSize)
{
	printf("\n开始新增节... \n");
	//计算，内存对齐后的新节的size， 设内存以1000字节对齐
	DWORD addSize_MemoryAlign = addSize % 0x1000 == 0x0 ? addSize : (addSize / 0x1000 * 0x1000 + 0x1000);

	//计算，文件对齐后的新节的size， 设文件以400字节对齐
	DWORD addSize_FileAlign = addSize % 0x400 == 0x0 ? addSize : (addSize / 0x400 * 0x400 + 0x400);

	//计算，节表末尾(不包括"未知数据")的地址偏移量
	DWORD offset_EndofSectionHeader = pPEHeader->DOSHeader.offset_to_PE_signature + 0x18 + pPEHeader->COFFHeader.size_of_optional_Headers + (pPEHeader->COFFHeader.number_of_section * 0x28);

	//计算，节表末尾(不包括"未知数据")距"size_of_headers"有多远
	DWORD distance = pPEHeader->OptionalHeader.size_of_headers - offset_EndofSectionHeader;

	//判断节表末尾是否存在"未知数据"
	bool haveUnknowData = false;
	for (DWORD i = 0; i < distance; i++)
	{
		if (*(*pFileBuffer_addr + offset_EndofSectionHeader + i) != 0x00)
		{
			printf("从节表末尾+[0x%x]处，存在未知数据 \n", i);
			haveUnknowData = true;
			break;
		}
	}
	//当存在未知数据时,需前移操作
	if (haveUnknowData)
	{
		//计算DOS头垃圾信息的size
		DWORD size_DOSTrash = pPEHeader->DOSHeader.offset_to_PE_signature - 0x40;
		printf("DOS头垃圾信息所占空间 = %x \n", size_DOSTrash);
		//判断DOS头垃圾信息的大小是否 >= 新增节表所需空间(0x28*2)
		if (size_DOSTrash < 0x28 * 2)
		{
			printf("新增节失败:DOS头垃圾信息的所占空间小于所需空间 \n");
			return -1;
		}
		printf("开始前移操作... \n");
		//【前置】fileBuffer】：修改number of section 加一
		(*(unsigned short*)(*pFileBuffer_addr + pPEHeader->DOSHeader.offset_to_PE_signature + 0x6)) += 0x1;

		//【前置】【fileBuffer】：修改Size of Image 
		*(DWORD *)(*pFileBuffer_addr + pPEHeader->DOSHeader.offset_to_PE_signature + 0x18 + 0x38) += addSize_MemoryAlign;

		//【前移操作】【fileBuffer】：将标准PE头、可选PE头、节表都前移，使其覆盖DOS头垃圾信息
		DWORD MoveCount = 0x18 + pPEHeader->COFFHeader.size_of_optional_Headers + pPEHeader->COFFHeader.number_of_section * 0x28;
		for (DWORD i = 0; i < MoveCount; i++)
		{
			*(*pFileBuffer_addr + 0x40 + i) = *(*pFileBuffer_addr + pPEHeader->DOSHeader.offset_to_PE_signature + i);
		}
		//【前移操作】【fileBuffer】：修改offset_to_PE_signature至DOS头垃圾信息处
		*(DWORD*)(*pFileBuffer_addr + 0x3C) = 0x40;

		//【前移操作】:重新计算节表末尾(不包括"未知数据")的地址偏移量
		offset_EndofSectionHeader = offset_EndofSectionHeader - size_DOSTrash;

		//【前移操作】【fileBuffer】：将前移后遗留的数据置为0 (为新节表清理空间)
		for (DWORD i = offset_EndofSectionHeader; i < offset_EndofSectionHeader + size_DOSTrash; i++)
		{
			*(*pFileBuffer_addr + i) = 0x0;
		}
	}
	//当不存在未知数据时，判断节表末尾至PE头尾部是否 >= 新增节表所需空间(0x28*2)
	if (!haveUnknowData)
	{
		if (distance < 0x28 * 2)
		{
			printf("新增节失败:节表末尾至PE头尾部空间小于所需空间 \n");
			return -1;
		}
		//【前置】【fileBuffer】：修改number of section 加一
		(*(unsigned short*)(*pFileBuffer_addr + pPEHeader->DOSHeader.offset_to_PE_signature + 0x6)) += 0x1;

		//【前置】：修改Size of Image 
		*(DWORD *)(*pFileBuffer_addr + pPEHeader->DOSHeader.offset_to_PE_signature + 0x18 + 0x38) += addSize_MemoryAlign;
	}
	printf("开始新增节操作... \n");

	//【新增节表】【fileBuffer】：修改新节表的各属性

	//Section Name
	*(unsigned long long*)(*pFileBuffer_addr + offset_EndofSectionHeader) = *(unsigned long long*)sectionName;

	//Virtual Size
	*(DWORD*)(*pFileBuffer_addr + offset_EndofSectionHeader + 0x8) = addSize_MemoryAlign;

	//Virtual Address改为内存对齐的整数倍, 设内存对齐 = 1000字节 
	DWORD sectionIndex = pPEHeader->COFFHeader.number_of_section - 1;
	DWORD lastSectionEndOffest_VA = pPEHeader->SectionHeader.virtual_address[sectionIndex] + pPEHeader->SectionHeader.virtual_size[sectionIndex];//计算上一个节表末尾的地址偏移量
	*(DWORD*)(*pFileBuffer_addr + offset_EndofSectionHeader + 0x8 + 0x4) = lastSectionEndOffest_VA % 0x1000 == 0x0 ? lastSectionEndOffest_VA : (lastSectionEndOffest_VA / 0x1000 * 0x1000 + 0x1000);

	//Size of Raw Data
	*(DWORD*)(*pFileBuffer_addr + offset_EndofSectionHeader + 0x8 + 0x4 + 0x4) = addSize;

	//Pointer to Raw Data 改为文件对齐的整数倍,设文件对齐 = 400字节
	DWORD lastSectionEndOffest_FOA = pPEHeader->SectionHeader.pointer_to_raw_data[sectionIndex] + pPEHeader->SectionHeader.size_Of_raw_data[sectionIndex];
	*(DWORD*)(*pFileBuffer_addr + offset_EndofSectionHeader + 0x8 + 0x4 + 0x4 + 0x4) = lastSectionEndOffest_FOA % 0x400 == 0x0 ? lastSectionEndOffest_FOA : (lastSectionEndOffest_FOA / 0x400 * 0x400 + 0x400);

	//计算新文件的长度(新节表的Pointer to Raw Data + 文件对齐后的节大小 )
	DWORD fileLen_new = *(DWORD*)(*pFileBuffer_addr + offset_EndofSectionHeader + 0x8 + 0x4 + 0x4 + 0x4) + addSize_FileAlign;

	//申请新pFileBuffer空间，复制原pFileBuffer至新空间，释放原pFileBuffer
	BYTE* newFileBuffer = (BYTE*)malloc(fileLen_new);
	memset(newFileBuffer, 0x0, fileLen_new);
	memcpy(newFileBuffer, *pFileBuffer_addr, fileLen_new - addSize_FileAlign);
	free(*pFileBuffer_addr);
	*pFileBuffer_addr = newFileBuffer;

	//将【fileBuffer】写入文件(覆盖)
	writePEFile(filePath, fileLen_new, *pFileBuffer_addr);

	//更新 PE各参数
	AnalyzePE_FileBuffer_x86(*pFileBuffer_addr, pPEHeader, pPEBody);

	printf("新增节成功! \n");

	//返回新节的FOA
	return pPEHeader->SectionHeader.pointer_to_raw_data[pPEHeader->COFFHeader.number_of_section - 1];
}
//FOA到RVA
DWORD convertFOAtoRVA(DWORD FOA, PEHeader thePEHeader)
{
	//查找RVA所在的节（二分法查找）
	int highIndex = thePEHeader.COFFHeader.number_of_section - 1;
	int lowIndex = 0;
	int midIndex = (highIndex + lowIndex) / 2;
	while (highIndex >= lowIndex)
	{
		if (FOA >= thePEHeader.SectionHeader.pointer_to_raw_data[midIndex] && FOA < thePEHeader.SectionHeader.pointer_to_raw_data[midIndex] + thePEHeader.SectionHeader.size_Of_raw_data[midIndex])
			break;//找到

		if (FOA < thePEHeader.SectionHeader.pointer_to_raw_data[midIndex])
		{
			highIndex = midIndex - 1;
		}
		else
		{
			lowIndex = midIndex + 1;
		}
		midIndex = (highIndex + lowIndex) / 2;
	}
	//计算FOA相对于该节的偏移量
	DWORD offset = FOA - thePEHeader.SectionHeader.pointer_to_raw_data[midIndex];

	//找到该节的RVA
	DWORD sectionRVA = thePEHeader.SectionHeader.virtual_address[midIndex];

	//所求RVA = 节的RVA + 偏移量
	DWORD RVA = sectionRVA + offset;

	return RVA;
}


//RVA转FOA
DWORD convertRVAtoFOA(DWORD RVA, PEHeader thePEHeader)
{
	//查找RVA所在的节（二分法查找）
	int highIndex = thePEHeader.COFFHeader.number_of_section - 1;
	int lowIndex = 0;
	int midIndex = (highIndex + lowIndex) / 2;
	while (highIndex >= lowIndex)
	{
		if (RVA >= thePEHeader.SectionHeader.virtual_address[midIndex] && RVA < thePEHeader.SectionHeader.virtual_address[midIndex] + thePEHeader.SectionHeader.virtual_size[midIndex])
			break;//找到

		if (RVA < thePEHeader.SectionHeader.virtual_address[midIndex])
		{
			if (midIndex == 0)
			{
				//如果RVA处于第0节之前，说明在节表中，不需要转换了，直接返回
				return RVA;
			}
			highIndex = midIndex - 1;
		}
		else
		{
			lowIndex = midIndex + 1;
		}
		midIndex = (highIndex + lowIndex) / 2;
	}
	//计算RVA相对于该节的偏移量
	DWORD offset = RVA - thePEHeader.SectionHeader.virtual_address[midIndex];

	//找到该节的FOA
	DWORD sectionFOA = thePEHeader.SectionHeader.pointer_to_raw_data[midIndex];

	//所求FOA = 节的FOA + 偏移量
	DWORD FOA = sectionFOA + offset;

	return FOA;
}


//通过函数名查找函数地址 
DWORD getFuncAddressByName(char* funcName, PBYTE pFileBuffer, PEHeader thePEHeader, PEBody thePEBody)
{
	//1.查[函数名称表]的函数名，找到索引
	for (int index = 0; index < thePEBody.ExportDirectory.Number_Of_Names; index++)
	{
		DWORD FOA = convertRVAtoFOA(thePEBody.Functions_Names[index], thePEHeader);
		if (!strcmp(funcName, (const char*)pFileBuffer + FOA)) //strcmp()返回0表示"相同"
		{
			//2.根据索引，查[函数名称序号表]的序号值
			unsigned short ordinal = thePEBody.Functions_NameOrdinals[index];
			//3.将查到的序号作为索引，查[函数地址表]的地址值
			DWORD address = thePEBody.Functions_Address[ordinal];

			return address;
		}
	}
	return -1;
}
//通过逻辑序号(即从1开始数的) 查找函数地址
DWORD getFuncAddressByLogicalOrdinal(DWORD logicalIndex, PEBody thePEBody)
{
	//1.得到函数的物理序号(即从0开始数的)
	DWORD physicalOrdinal = logicalIndex - thePEBody.ExportDirectory.Base;
	//2.根据物理序号查[函数地址表]
	DWORD address = thePEBody.Functions_Address[physicalOrdinal];

	return address;
}

//移动导出目录 (将导出目录以及相关表全部移入新建的节)
void moveExportDirectory(PEHeader* pPEHeader, PEBody* pPEBody, char* filePath, PBYTE pFileBuffer)
{
	//1.1 创建新节,本次为了方便直接建1000h，其实可以精确计算
	if (!addSection(pPEHeader, pPEBody, filePath, &pFileBuffer, ".export", 0x1000))
	{
		printf("新增节失败！！！\n");
		return;
	}
	//1.2 游标：记录复制到哪了(FOA值)
	DWORD cursor_FOA = 0x0;

	//1.3 得到新节的FOA
	DWORD newSection_FOA = pPEHeader->SectionHeader.pointer_to_raw_data[pPEHeader->COFFHeader.number_of_section - 1];
	cursor_FOA = newSection_FOA;

	//2.1 复制【函数地址表】粘贴到新节里
	DWORD size_functions = pPEBody->ExportDirectory.Number_Of_Functions * 0x4;
	memcpy(pFileBuffer + cursor_FOA, pFileBuffer + convertRVAtoFOA(pPEBody->ExportDirectory.Address_Of_Functions, *pPEHeader), size_functions);

	//2.2 修改【导出目录】中的Address of Functions
	*(DWORD*)(pFileBuffer + convertRVAtoFOA(pPEHeader->OptionalHeader.export_directory_offset, *pPEHeader) + 0x7 * 0x4) = convertFOAtoRVA(cursor_FOA, *pPEHeader);
	pPEBody->ExportDirectory.Address_Of_Functions = convertFOAtoRVA(cursor_FOA, *pPEHeader);

	//2.3此时再移动游标
	cursor_FOA += size_functions;

	//3.1 继续复制粘贴【函数名称序号表】
	DWORD size_NameOrdinals = pPEBody->ExportDirectory.Number_Of_Names * 0x2;
	memcpy(pFileBuffer + cursor_FOA, pFileBuffer + convertRVAtoFOA(pPEBody->ExportDirectory.Address_Of_NameOrdinals, *pPEHeader), size_NameOrdinals);

	//3.2 修改【导出目录】中的Address of Name Ordinals
	*(DWORD*)(pFileBuffer + convertRVAtoFOA(pPEHeader->OptionalHeader.export_directory_offset, *pPEHeader) + 0x9 * 0x4) = convertFOAtoRVA(cursor_FOA, *pPEHeader);
	pPEBody->ExportDirectory.Address_Of_NameOrdinals = convertFOAtoRVA(cursor_FOA, *pPEHeader);

	//3.3 此时再移动游标
	cursor_FOA += size_NameOrdinals;

	//4.1 继续复制粘贴【函数名称表】
	DWORD size_Name = pPEBody->ExportDirectory.Number_Of_Names * 0x4;
	memcpy(pFileBuffer + cursor_FOA, pFileBuffer + convertRVAtoFOA(pPEBody->ExportDirectory.Address_Of_Names, *pPEHeader), size_Name);

	//4.2 修改【导出目录】中的Address of Names
	*(DWORD*)(pFileBuffer + convertRVAtoFOA(pPEHeader->OptionalHeader.export_directory_offset, *pPEHeader) + 0x8 * 0x4) = convertFOAtoRVA(cursor_FOA, *pPEHeader);
	pPEBody->ExportDirectory.Address_Of_Names = convertFOAtoRVA(cursor_FOA, *pPEHeader);

	//4.3 此时再移动游标
	cursor_FOA += size_Name;

	//5.逐个复制"函数名字符串"，每复制一个就同时修改【函数名称表】对应的值！
	for (DWORD i = 0; i < pPEBody->ExportDirectory.Number_Of_Names; i++)
	{
		//计算字符串所在的FOA
		DWORD str_FOA = convertRVAtoFOA(pPEBody->ExportDirectory.Address_Of_Names + i * 0x4, *pPEHeader);

		//计算字符串长度，strlen()返回字符个数(不包括结束符)
		DWORD strLen = strlen((char*)(pFileBuffer + str_FOA));

		//字符串复制，strcpy()复制字符串(包括结束符 0x0)
		strcpy((char*)(pFileBuffer + cursor_FOA), (char*)(pFileBuffer + str_FOA));

		//修改【函数名称表】对应项的值！！！！
		*(DWORD*)(pFileBuffer + pPEBody->ExportDirectory.Address_Of_Names + 0x4 * i) = convertFOAtoRVA(cursor_FOA, *pPEHeader);

		//游标多加1，因为有结束符 0x0 !!!!!
		cursor_FOA += (strLen + 1);

	}

	//7.1 继续复制黏贴【导出目录】
	DWORD size_ExportDirectory = 0x28;
	DWORD exportDirectory_FOA = convertRVAtoFOA(pPEHeader->OptionalHeader.export_directory_offset, *pPEHeader);
	memcpy(pFileBuffer + cursor_FOA, pFileBuffer + exportDirectory_FOA, size_ExportDirectory);

	//7.2 修改【可选PE头-导出目录offset】值
	*(DWORD*)(pFileBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x18 + 0x60) = convertFOAtoRVA(cursor_FOA, *pPEHeader);
	pPEHeader->OptionalHeader.export_directory_offset = convertFOAtoRVA(cursor_FOA, *pPEHeader);

	//7.3 此时再移动游标
	cursor_FOA += size_ExportDirectory;

	//8 计算新文件大小 (最后一张节表的Pointer to Raw Data + 文件对齐后的节大小 )
	DWORD newFileLength = pPEHeader->SectionHeader.pointer_to_raw_data[pPEHeader->COFFHeader.number_of_section - 1] + pPEHeader->SectionHeader.size_Of_raw_data[pPEHeader->COFFHeader.number_of_section - 1];

	//9 写入文件
	writePEFile(filePath, newFileLength, pFileBuffer);
}

//移动"重定位表"至新节
void moveRelocationDirectory(PEHeader* pPEHeader, PEBody* pPEBody, char* filePath, PBYTE pFileBuffer)
{
	//1. 创建新节
	if (!addSection(pPEHeader, pPEBody, filePath, &pFileBuffer, ".myreloc", 0x1000))
	{
		printf("新增节失败！！！\n");
		return;
	}

	//2. 得到新节的FOA
	DWORD newSection_FOA = pPEHeader->SectionHeader.pointer_to_raw_data[pPEHeader->COFFHeader.number_of_section - 1];

	//3. 将【重定位目录】复制到新节里
	DWORD relocDir_FOA = convertRVAtoFOA(pPEHeader->OptionalHeader.relocation_directory_offset, *pPEHeader);

	DWORD relocDir_Size = 0x0;
	//计算所有“块”的大小
	for (DWORD i = 0; i < pPEBody->ReloactionDirectory.NumberOfBlock; i++)
	{
		relocDir_Size += pPEBody->ReloactionDirectory.Block[i].Size_Of_Block;
	}
	//再加上终结标识(8字节的0x0)
	relocDir_Size += 0x8;
	//复制！
	memcpy(pFileBuffer + newSection_FOA, pFileBuffer + relocDir_FOA, relocDir_Size);

	//4. 修改【可选PE头-重定位目录offset】
	*(DWORD *)(pFileBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x18 + 0x60 + (0x5 * 0x8)) = pPEHeader->SectionHeader.virtual_address[pPEHeader->COFFHeader.number_of_section - 1];
	pPEHeader->OptionalHeader.relocation_directory_offset = pPEHeader->SectionHeader.virtual_address[pPEHeader->COFFHeader.number_of_section - 1];

	//5. 计算新文件大小 (最后一张节表的Pointer to Raw Data + 文件对齐后的节大小 )
	DWORD newFileLength = pPEHeader->SectionHeader.pointer_to_raw_data[pPEHeader->COFFHeader.number_of_section - 1] + pPEHeader->SectionHeader.size_Of_raw_data[pPEHeader->COFFHeader.number_of_section - 1];

	//写入文件
	writePEFile(filePath, newFileLength, pFileBuffer);
}

// <summary>
//	根据新基址修复重定位表(32位程序)
// </summary>
// <param name="destImageBase">新基址</param>
// <param name="srcImageBase">原基址，不能从PE文件中读，因为可能是动态基址</param>
// <param name="pImageBuffer"></param>
// <param name="pPEHeader"></param>
// <param name="pPEBody"></param>
// <date>2018.12.04</date>
BOOL RepairReLocationDirectory_x86(DWORD destImageBase, DWORD srcImageBase, PBYTE pImageBuffer, PEHeader* pPEHeader, PEBody* pPEBody)
{
	printf("\n开始修复重定位表...,目标基址=%08x \n", destImageBase);
	//0.新基址合法性检查
	if (destImageBase == 0x0)
	{
		printf("错误：传入的新基址新基址=%08x \n", destImageBase);
		return FALSE;
	}

	//1.判断是否存在重定位目标
	if (pPEHeader->OptionalHeader.relocation_directory_offset == 0x0)
	{
		printf("不存在重定位目录，是否因为未编译成release版本导致无重定位表? 退出... \n");
		return FALSE;
	}
	//2. 记录下原基址
	//DWORD srcImageBase = pPEHeader->OptionalHeader.image_base;

	//3.修改ImageBuffer、PEHeader存储的基址
	*(DWORD *)(pImageBuffer + pPEHeader->DOSHeader.offset_to_PE_signature + 0x34) = destImageBase;
	pPEHeader->OptionalHeader.image_base = destImageBase;

	//4. 根据重定位目录修正ImageBuffer中存储的各地址值
	for (DWORD i = 0; i < pPEBody->ReloactionDirectory.NumberOfBlock; i++)
	{
		DWORD numberOfItem = (pPEBody->ReloactionDirectory.Block[i].Size_Of_Block - 0x8) / 0x2;
		for (DWORD j = 0; j < numberOfItem; j++)
		{
			if (pPEBody->ReloactionDirectory.Block[i].Item[j].Type == 0x3)
			{
				//计算需要重定位的内容的地址
				DWORD goal_RVA = pPEBody->ReloactionDirectory.Block[i].Virtual_Address + pPEBody->ReloactionDirectory.Block[i].Item[j].Offset;
				//DWORD goal_FOA = convertRVAtoFOA(goal_RVA, *pPEHeader);
				//因为十六进制的减法的位溢出问题，这里用大地址减去小地址，确保差值是正的！！！！非常重要！！
				if (destImageBase >= pPEHeader->OptionalHeader.image_base)
				{
					//因为要修正的内容是"地址值"，所以占4字节
					*(DWORD*)(pImageBuffer + goal_RVA) += (destImageBase - srcImageBase);
				}
				else
				{
					*(DWORD*)(pImageBuffer + goal_RVA) -= (srcImageBase - destImageBase);
				}

			}
		}
	}
	printf("修复重定位表完毕...  \n");
	return TRUE;
}
// <summary>
//	修复IAT表(32位)
// </summary>
//	即根据导入目录加载各DLL，然后将DLL中的函数地址填入IAT表各项
// <param name="virtualAddr">申请到的基址，指向ImageBuffer的指针</param>
// <param name="pImageBuffer"></param>
// <param name="PEHeader"></param>
// <param name="PEBody"></param>
// <date>2018.12.04</date>
VOID RepairIAT_x86(DWORD virtualAddr, PEBody* pPEBody)
{
	printf("\n开始修复IAT表...\n");
	OutputDebugString("my-开始修复IAT表...");

	for (int i = 0; i < pPEBody->NumberOfImportDirectory; i++)
	{
		//DLL名称字符串
		CHAR* dllName = (CHAR*)(virtualAddr + pPEBody->ImportDirectory[i].Name);
		for (int j = 0; j < pPEBody->INT_Table[i].NumberOfItem; j++)
		{
			//加载DLL并根据函数名称/序号获取函数地址
			DWORD funcAddr = 0;
			if (pPEBody->INT_Table[i].IMAGE_THUNK_DATA[j] & 0x80000000)
			{//若其二进制最高位=1，则是按序号导入
				WORD funcOrdinal = pPEBody->INT_Table[i].IMAGE_THUNK_DATA[j] & 0x0000FFFF;//只要后16位
				funcAddr = (DWORD)GetProcAddress(LoadLibrary(dllName), (LPSTR)funcOrdinal);
			}
			else
			{//若其二进制最高位=0，则是按名称导入
				CHAR* funcName = (CHAR*)(virtualAddr + pPEBody->INT_Table[i].IMAGE_THUNK_DATA[j] + 0x2);//只要后16位
				funcAddr = (DWORD)GetProcAddress(LoadLibrary(dllName), funcName);
			}
			//将函数地址写入PEBody结构体
			pPEBody->IAT_Table[i].funcAddress[j] = funcAddr;
			//将函数地址写入内存
			*(DWORD*)(virtualAddr + pPEBody->ImportDirectory[i].FirstThunk + j * 0x4) = funcAddr;
		}
	}
	ShowDbg("修复IAT表完毕", 0x6636);
}




//提升权限(用管理员权限运行EXE)
bool upPrivileges()
{
	BOOL retn;
	HANDLE hToken;
	retn = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
	if (retn != TRUE)
	{
		printf("提权失败1 \n");
		return 0;
	}
	TOKEN_PRIVILEGES tp; //新特权结构体
	LUID Luid;
	retn = LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Luid);
	if (retn != TRUE)
	{
		printf("提权失败2 \n");
		return 0;
	}
	//给TP和TP里的LUID结构体赋值
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tp.Privileges[0].Luid = Luid;

	AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	if (GetLastError() == ERROR_SUCCESS)
	{
		printf("提权成功！\n");
		return true;
	}
	else
	{
		printf("提权失败3 ,请用管理员身份运行！\n");
		return false;
	}
}

//遍历所有进程
/*
64位进程可以枚举32位进程的模块，但32位进程不可以枚举64位进程的模块。
如果你想枚举64位进程的模块，试下把下面的代码编译为64位的程序.
*/
void traversalProcess()
{
	//提权,才能打开一些进程
	if (!upPrivileges())
	{
		return;
	}
	DWORD PIDArray[500];
	DWORD PIDArray_byteSize;
	EnumProcesses(PIDArray, sizeof(PIDArray), OUT &PIDArray_byteSize);
	//枚举所有进程ID
	int numberOfProcess = (PIDArray_byteSize / sizeof(DWORD));
	for (int i = 0; i < numberOfProcess; i++)
	{
		printf("进程ID=%08X  ", PIDArray[i]);
		//打开进程，返回该进程的句柄 (指定访问权限)
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, PIDArray[i]);
		if (hProcess == 0x0)
		{
			DWORD code = GetLastError();
			printf("打开进程失败,code=%d \n", code);
			continue;
		}
		HMODULE moduleArray[500] = { 0 };
		DWORD moduleArray_byteSize;
		//判断是32位还是64位进程,isWow64Process用于判断某进程是否运行在WOW64下。对于64位程序，Wow64Process参数会返回FALSE！
		BOOL is32BitProcess;
		IsWow64Process(hProcess, &is32BitProcess);
		printf("是否为32位进程=%d ", is32BitProcess);

		//枚举进程的所有模块的句柄（进程要先申请PROCESS_VM_READ访问权限）
		EnumProcessModulesEx(hProcess, moduleArray, sizeof(moduleArray), OUT &moduleArray_byteSize, LIST_MODULES_ALL);
		DWORD code = GetLastError();

		//进程第0个模块的句柄就是进程的基址
		//进程第0个模块的全路径就是进程exe的全路径
		CHAR fullPath[250];
		DWORD bufferSize = GetModuleFileNameEx(hProcess, moduleArray[0], fullPath, sizeof(fullPath));
		printf("进程基址=%08X ", moduleArray[0]);
		printf("进程全路径=%s \n", fullPath);

		//释放进程句柄
		CloseHandle(hProcess);

	}
}
//加壳：源文件src file，壳文件shell file，将源文件放入壳文件的最后一节
void addShell(char* filePath_src, char* filePath_shell)
{
	printf("\n开始加壳...\n");
	//1.读取src的PE文件并分析
	BYTE* pFileBuffer_src;
	PEHeader PEHeader_src;
	PEBody PEBody_src;
	int fileLength_src = readPEFile(filePath_src, &pFileBuffer_src);

	AnalyzePE_FileBuffer_x86(pFileBuffer_src, &PEHeader_src, &PEBody_src);

	//2.将src的fileBuufer加密（异或操作）

	//3.读取shell的PE文件并分析
	BYTE* pFileBuffer_shell;
	PEHeader PEHeader_shell;
	PEBody PEBody_shell;
	int fileLength_shell = readPEFile(filePath_shell, &pFileBuffer_shell);
	AnalyzePE_FileBuffer_x86(pFileBuffer_shell, &PEHeader_shell, &PEBody_shell);

	//4.给shell的fileBuffer新增节
	DWORD FOA_newSecion = addSection(&PEHeader_shell, &PEBody_shell, filePath_shell, &pFileBuffer_shell, ".test", fileLength_src);
	if (FOA_newSecion != -1)
	{
		//5.将加密后的src的fileBuffer存入shell的新增节
		memcpy(pFileBuffer_shell + FOA_newSecion, pFileBuffer_src, fileLength_src);

		//6.加壳结束，存为新文件
		writePEFile(filePath_shell, readPEFile(filePath_shell, &pFileBuffer_shell), pFileBuffer_shell);

		printf("加壳成功...\n");
	}
}

// <summary>
// 打印导入目录、IAT表、INT表
// </summary>
// <param name="PEHeader"></param>
// <param name="PEBody"></param>
// <param name="pFileBuffer"></param>
void PrintImportDirectory(PEHeader PEHeader, PEBody PEBody, PBYTE pFileBuffer)
{
	//打印导入目录
	printf("\n开始打印【导入目录】----------------------- \n");
	for (int i = 0; i < PEBody.NumberOfImportDirectory; i++)
	{
		printf("导入目录%d：", i);
		printf("OriginalFirstThunk=%08X ", PEBody.ImportDirectory[i].OriginalFirstThunk);
		printf("TimeDateStamp=%08X ", PEBody.ImportDirectory[i].TimeDateStamp);
		printf("ForwarderChain=%08X ", PEBody.ImportDirectory[i].ForwarderChain);
		printf("Name=%08X ", PEBody.ImportDirectory[i].Name);
		printf("FirstThunk=%08X \n", PEBody.ImportDirectory[i].FirstThunk);
	}
	printf("\n开始逐个打印【INT、IAT表】----------------------- \n");
	//逐个打印导入目录对应的INT和IAT表
	for (int i = 0; i < PEBody.NumberOfImportDirectory; i++)
	{
		//根据导入目录提供的RVA打印DLL名称字符串
		DWORD str_FOA = convertRVAtoFOA(PEBody.ImportDirectory[i].Name, PEHeader);
		printf("\n导入目录%d的DLL名称字符串=%s --------------------\n", i, pFileBuffer + str_FOA);
		//打印INT表、IAT表以及各项
		for (int j = 0; j < PEBody.INT_Table[i].NumberOfItem; j++)
		{
			printf("此导入目录对应的INT表的第%d项的值=%08X ", j, PEBody.INT_Table[i].IMAGE_THUNK_DATA[j]);
			if (PEBody.INT_Table[i].IMAGE_THUNK_DATA[j] & 0x80000000)
			{//判断其二进制最高位是否为1
				printf("二进制最高位为1，按序号导入 ,序号=%04X \n", PEBody.INT_Table[i].IMAGE_THUNK_DATA[j] & 0x0000FFFF);//只要后16位
			}
			else
			{
				printf("(二进制最高位为0，按名称导入)  ");
				DWORD FOA = convertRVAtoFOA(PEBody.INT_Table[i].IMAGE_THUNK_DATA[j], PEHeader);
				unsigned short hint = *(unsigned short*)(pFileBuffer + FOA);
				char* nameStr = (char*)(pFileBuffer + FOA + 0x2); //从16位后开始
				printf("hint=%04X 函数名字符串=%s \n", hint, nameStr);
			}
			printf("此导入目录对应的IAT表的第%d项的值=%08X \n", j, PEBody.IAT_Table[i].funcAddress[j]);
		}
	}
}




//******************************************加载目标Exe***********************************

// <summary>
// 用于加载EXE(x86)的子线程参数的结构体
// </summary>
struct PARAM_LOADEXE_x86
{
	char* filePath;
	HANDLE hMainThread;
};
// <summary>
// 用于加载EXE(x86)的子线程方法
// </summary>
// <describe></describe>
// <param name="lpThreadParameter"></param>
DWORD WINAPI SubThreadFunc_LoadExe_x86(LPVOID lpThreadParameter)
{
#if MY_X86
	PARAM_LOADEXE_x86 param = *(PARAM_LOADEXE_x86*)lpThreadParameter;
	//1.读EXE、分析PE、拉伸
	PBYTE pFileBuffer = 0;
	PBYTE pImageBuffer = 0;
	PEHeader PEHeader;
	PEBody PEBody;
	int fileLen = readPEFile(param.filePath, OUT &pFileBuffer); //这里是malloc申请到的堆内存
	AnalyzePE_FileBuffer_x86(pFileBuffer, OUT &PEHeader, OUT &PEBody);
	FileBufferToImageBuffer(pFileBuffer, OUT &pImageBuffer, PEHeader);

	//2.申请虚拟内存空间 (堆内存中存放的代码无法访问，必须放入"虚拟内存")
	PBYTE virtualAddr = (PBYTE)VirtualAllocEx(GetCurrentProcess(), (LPVOID)PEHeader.OptionalHeader.image_base, PEHeader.OptionalHeader.size_of_image, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (virtualAddr == 0x0)
	{//期望的基址被占用,随机申请一块虚拟内存
		printf("期望的基址被占用，尝试随机申请...\n");
		virtualAddr = (PBYTE)VirtualAllocEx(GetCurrentProcess(), NULL, PEHeader.OptionalHeader.size_of_image, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		//修复重定位表
		if (!RepairReLocationDirectory_x86((DWORD)virtualAddr, PEHeader.OptionalHeader.image_base, pImageBuffer, &PEHeader, &PEBody))
		{
			return 0;
		}
	}
	//将Imagebuffer从Heap Memory 贴入 Virtual Memory
	memcpy(virtualAddr, pImageBuffer, PEHeader.OptionalHeader.size_of_image);
	//3.修复IAT表
	RepairIAT_x86((DWORD)virtualAddr, &PEBody);

	//4.将主线程跳转至目标EXE的入口处 (设置主线程EIP至exe入口点)
	SuspendThread(param.hMainThread);
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(param.hMainThread, &context))
	{
		printf("获取线程CONTEXT失败 \n");
		getchar();
		return 0;
	}
	context.Eip = (DWORD)virtualAddr + PEHeader.OptionalHeader.address_of_entry_point;
	SetThreadContext(param.hMainThread, &context);
	//5.恢复主线程执行
	ResumeThread(param.hMainThread);
#endif
	return 0;
}
// <summary>
// 加载EXE(x86)
// </summary>
// <describe>
//	1.可以加载某些32位非托管语言的exe，如战网x86(需要放在exe同目录下运行才能加载所需DLL)。
//	2.某些32位exe无法加载，例如网易云音乐x86，原因未知。
//	3.C#托管语言编写的程序无法加载
// </describe>
// <param name="filePath"></param>
void LoadExe_x86(char* filePath)
{
	printf("\n开始加载目标EXE... \n");
	//子线程方法的参数
	PARAM_LOADEXE_x86 param;
	param.filePath = filePath;
	//获取当前线程的真实句柄
	DuplicateHandle
	(
		GetCurrentProcess(),
		GetCurrentThread(),	//此参数为GetCurrentProcess()时，是获取进程句柄
		GetCurrentProcess(),
		OUT &param.hMainThread, //接收真实句柄
		0,
		FALSE,
		DUPLICATE_SAME_ACCESS //复制后的句柄与原句柄具有相同的访问权限
	);
	//创建子线程
	HANDLE hSubThread = CreateThread(NULL, 0, SubThreadFunc_LoadExe_x86, &param, 0, NULL);

	//等待子线程结束
	WaitForSingleObject(hSubThread, INFINITE);
}

//**********************************************************************************

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



//***************************************>>>>消息钩子>>>>********************************************************

//预编译：是否全局钩子
#define GLOBALHOOK 1

// <summary>
// 消息钩子回调函数
// </summary>
LRESULT CALLBACK MessageHookCallback(int code, WPARAM wParam, LPARAM lParam)
{
#if GLOBALHOOK==1
	//当钩子类型=WH_KEYBOARD_LL时，必须是全局钩子，其回调函数为LowLevelKeyboardProc
	//参数wParam=WM_KEYDOWN, WM_KEYUP, WM_SYSKEYDOWN, or WM_SYSKEYUP.
	//参数lParam=A pointer to a KBDLLHOOKSTRUCT structure.
	//返回值：it may return a nonzero value to prevent the system from passing the message to the rest of the hook chain or the target window procedure.
	KBDLLHOOKSTRUCT *kbDllHookStuct = (KBDLLHOOKSTRUCT*)lParam;
	if (wParam == WM_KEYDOWN)
	{
		printf("键盘按下：%x \n", kbDllHookStuct->vkCode);
		ShowDbg("键盘按下:", kbDllHookStuct->vkCode);
	}
#else
	//当钩子类型=WH_KEYBOARD时，我使用线程钩子，其回调函数为KeyboardProc 
	//参数lParam共32位，第32位表示键盘按下/抬起:The transition state. The value is 0 if the key is being pressed and 1 if it is being released.
	if (code == HC_NOREMOVE)
	{//code可以为HC_NOREMOVE 或 HC_ACTION ，这里选择一个，避免接受两次消息

		if (!(lParam & (1 << 31)))
		{//代表按下某键

			MessageBox(0, 0, 0, 0);
			printf("键盘按下：%x \n", wParam);
			ShowDbg("键盘按下:", wParam);
			//GetKeyNameText(lParam, , );
		}
	}
#endif
	return CallNextHookEx(0, code, wParam, lParam);
}


// <summary>
// 设置消息钩子
// </summary>
void Hook_MessageHook()
{
	//全局钩子
	HHOOK keyboardHook = SetWindowsHookExA(WH_KEYBOARD_LL, MessageHookCallback, GetModuleHandleA(NULL), NULL);

	//线程钩子(失败)
	//HHOOK keyboardHook = SetWindowsHookExA(WH_KEYBOARD, MessageHookCallback, NULL, GetCurrentThreadId());

	if (keyboardHook == 0)
	{
		DWORD code = GetLastError();
		printf("设置钩子失败 code=%d \n", code);
		ShowDbg("设置钩子失败 code=:", code);
		return;
	}
	printf("已设置键盘钩子... \n");
	ShowDbg("已设置键盘钩子... ", 0x6636);
	//不可漏掉消息处理，不然程序会卡死
	MSG msg;
	if (GetMessage(&msg, 0, 0, 0))
	{//避免CPU全负载运行
		TranslateMessage(&msg);
		DispatchMessageW(&msg);
	}

	//卸载钩子
	//UnhookWindowsHookEx(keyboardHook);

	return;
}
//***********************************************************************************************************

/**
 * 打开64位进程
 * 参数 ProcessName	进程名(eg: CHAR ProcessName[] = "Overwatch.exe";)
 * 参数 needAccess	以何种权限打开进程 (eg: PROCESS_TERMINATE|PROCESS_VM_READ or PROCESS_ALL_ACCESS)
 */
HANDLE MyOpenProcess_x64(CHAR* ProcessName, DWORD needAccess)
{
#if !MY_X64
	printf("错误：需编译为x64 \n");
	return 0;
#endif
	HANDLE hSnapshot;
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //调用CreatToolhelp32Snapshot来获取快照,用THREADENTRY32来获取线程信息等
	PROCESSENTRY32 *info;
	info = new PROCESSENTRY32;
	info->dwSize = sizeof(PROCESSENTRY32);
	Process32First(hSnapshot, info);
	while (Process32Next(hSnapshot, info) != FALSE)
	{
		info->szExeFile;
		if (strcmp(ProcessName, info->szExeFile) == 0)
		{
			HANDLE hProcess = OpenProcess(needAccess, FALSE, info->th32ProcessID);
			if (hProcess == 0x0)
			{
				printf("打开进程失败,code=%d \n", GetLastError());
				return 0;
			}
			CloseHandle(hSnapshot);
			printf("成功打开目标进程... \n");
			return hProcess;
		}
	}
	CloseHandle(hSnapshot);
	printf("失败：未找到进程[%s] \n", ProcessName);
	return 0;
}
/**
 * 打开32位进程
 * 参数 ProcessName	进程名(eg: CHAR ProcessName[] = "cloudmusic.exe";)
 * 参数 needAccess	以何种权限打开进程 (eg: PROCESS_TERMINATE|PROCESS_VM_READ or PROCESS_ALL_ACCESS)
 */
HANDLE MyOpenProcess_x86(CHAR* ProcessName, DWORD needAccess)
{
#if !MY_X86
	printf("错误：需编译为x86 \n");
	return 0;
#endif
	HANDLE hSnapshot;
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //调用CreatToolhelp32Snapshot来获取快照,用THREADENTRY32来获取线程信息等
	PROCESSENTRY32 *info;
	info = new PROCESSENTRY32;
	info->dwSize = sizeof(PROCESSENTRY32);
	Process32First(hSnapshot, info);
	while (Process32Next(hSnapshot, info) != FALSE)
	{
		info->szExeFile;
		if (strcmp(ProcessName, info->szExeFile) == 0)
		{
			HANDLE hProcess = OpenProcess(needAccess, FALSE, info->th32ProcessID);
			if (hProcess == 0x0)
			{
				printf("打开进程失败,code=%d \n", GetLastError());
				return 0;
			}
			CloseHandle(hSnapshot);
			printf("成功打开目标进程... \n");
			return hProcess;
		}
	}
	CloseHandle(hSnapshot);
	printf("失败：未找到进程[%s] \n", ProcessName);
	return 0;
}

//***************************************>>>>IAT HOOK>>>>********************************************************

/**
 * 暂存被Hook的函数原地址
 */
DWORD Hook_OldFuncAddr_x86;

/**
 * 原MessageBox的函数指针(用于调用原函数或卸载hook)
 */
typedef int (WINAPI *PMESSAGEBOX)(_In_opt_ HWND, _In_opt_ LPCSTR, _In_opt_ LPCSTR, _In_ UINT);
PMESSAGEBOX pMessageBox;

/**
 * MessageBox的IAT Hook替换函数
 */
int WINAPI Hook_IATHook_MyMessageBox_X86(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType)
{
	printf("MessageBox函数：参数3=%s    参数2=%s \n", (TCHAR*)lpCaption, (TCHAR*)lpText);
	PMESSAGEBOX pMessageBox = (PMESSAGEBOX)Hook_OldFuncAddr_x86;
	return pMessageBox(hWnd, lpText, lpCaption, uType);
}

/**
 * 通过模块的导出目录，查找模块的导出函数地址 (模拟API函数：GetProcAddr)
 * 参数   hModule	ImageBuffer的基址
 * 参数   funcName	目标函数名
 * 参数	  PEBody	导出目录所在模块的PEBody
 * 返回值 导出函数地址的VA值
 */
DWORD GetExportFuncAddrByName_ImageBuffer_X86(HMODULE hModule, CHAR* funcName, PEBODY_X86 PEBody)
{
	//1.查[函数名称表]的函数名，找到索引
	for (int index = 0; index < PEBody.ExportDirectory.Number_Of_Names; index++)
	{
		if (strcmp(funcName, (CHAR*)hModule + PEBody.Functions_Names[index]) == 0) //strcmp()返回0表示"相同"
		{
			//2.根据索引，查[函数名称序号表]的序号值
			WORD ordinal = PEBody.Functions_NameOrdinals[index];
			//3.将查到的序号作为索引，查[函数地址表]的地址值
			DWORD funcAddr_VA = (DWORD)hModule + PEBody.Functions_Address[ordinal];
			printf("在导出目录中找到函数名=%s的函数地址=%08X \n", funcName, funcAddr_VA);
			return funcAddr_VA;
		}
	}
	printf("错误：在导出目录中找不到指定函数名... \n");
	return 0;
}

/**
 * 根据目标DLL名和函数名查询IAT表某项的地址
 * 参数 PEBody
 * 参数 imageBase	IAT表所在的模块基址
 * 参数 destDllNameStr	目标DLL名
 * 参数 destFuncNameStr	目标函数名
 */
DWORD GetIATItemAddr_ByFuncName_x86(PEBody PEBody, DWORD imageBase, CHAR* destDllNameStr, CHAR* destFuncNameStr)
{
	printf("\n开始通过函数名和DLL名获取IAT表的项地址... \n");
	//1.判断目标模块是否已加载：获取目标DLL句柄
	HMODULE hDestDll = GetModuleHandle(destDllNameStr);
	if (hDestDll == 0)
	{
		printf("失败：[ImageBuffer]中未装载目标模块 \n");
		return 0;
	}

	//2.判断目标模块原先是否存在该导出函数（合法性检查）
	DWORD destFuncAddr = (DWORD)GetProcAddress(hDestDll, destFuncNameStr); //此API是通过查询[导出目录]获取函数地址
	if (destFuncAddr == 0)
	{
		printf("失败：目标模块不存在该导出函数，请检查函数名... \n");
		return 0;
	}

	//3.判断该模块的指定函数是否被目标ImageBuffer导入 (IAT表中是否存在该函数)
	for (int i = 0; i < PEBody.NumberOfImportDirectory; i++)
	{
		for (int j = 0; j < PEBody.IAT_Table[i].NumberOfItem; j++)
		{
			if (destFuncAddr == PEBody.IAT_Table[i].funcAddress[j])
			{
				DWORD destIAT_VA = (imageBase + PEBody.ImportDirectory[i].FirstThunk);
				DWORD destItem_VA = destIAT_VA + j * 0x4; //项中存储函数地址，一个函数地址占32位(4字节)
				printf("成功: 在[ImageBuffer]的IAT表中找到目标函数地址... \n");
				return destItem_VA;
			}
		}
	}
	printf("失败：[ImageBuffer]虽然已导入目标模块，但未导入目标函数(IAT表中无此项) \n");

	return 0;
}

/**
 * IAT Hook 32位
 * 参数 destDllNameStr	目标函数所在的DLL名 (注意大小写都有可能,例如user32.dll/USER32.dll)
 * 参数 destFuncNameStr	目标函数名 ( eg:TEXT("MessageBoxA") )
 * 参数 hookFuncAddr	被hook函数的替换函数 ( eg:(DWORD)Hook_IATHook_MyMessageBox_X86 )
 */
void Hook_IATHook_x86(char* destDllNameStr, char* destFuncNameStr, DWORD hookFuncAddr)
{
#if !MY_X86
	printf("需编译为x86 \n");
	return;
#endif

	//1.获取当前模块的基址、镜像大小；分析当前模块的PE结构
	MODULEINFO moduleInfo = { 0 };
	GetModuleInformation(GetCurrentProcess(), GetModuleHandle(NULL), OUT &moduleInfo, sizeof(MODULEINFO));
	PEHeader PEHeader = { 0 }; PEBody PEBody = { 0 };
	AnalyzePE_ImageBuffer_x86((PBYTE)moduleInfo.lpBaseOfDll, OUT &PEHeader, OUT &PEBody);

	//2.根据函数名查找IAT表中的项的VA
	DWORD destItem_VA = GetIATItemAddr_ByFuncName_x86(PEBody, (DWORD)moduleInfo.lpBaseOfDll, destDllNameStr, destFuncNameStr);
	if (destItem_VA == 0)return;

	//3.暂存函数原地址
	Hook_OldFuncAddr_x86 = *(DWORD*)(destItem_VA);

	//4.修改IAT表中的项为hook的函数地址
	DWORD oldProtect = 0;
	DWORD newProtect = 0;
	VirtualProtect((PVOID)destItem_VA, sizeof(DWORD), PAGE_READWRITE, &oldProtect);	//修改该内存页的保护属性为可读写
	memcpy((PVOID)destItem_VA, &hookFuncAddr, sizeof(hookFuncAddr));				//写入该内存页
	VirtualProtect((PVOID)destItem_VA, sizeof(DWORD), oldProtect, &newProtect);		//恢复该内存页的保护属性

	//5.测试：调用被Hook的函数
	//MessageBox(0, TEXT("testText"), TEXT("testCaption"), 0);
}
//***********************************************************************************************************



//************************************>>>>Inline HOOK>>>>********************************************************



//***********************************************************************************************************
