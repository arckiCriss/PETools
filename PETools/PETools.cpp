#include "pch.h"
/**
 * 装载FileBuffer：读取文件
 * 参数 filePath
 * 参数 ppFileBuffer
 * 返回 fileLen 读取的文件长度
 */
int LoadFileBuffer(const TCHAR* filePath, OUT PBYTE* ppFileBuffer)
{
	printf("\n开始装载文件缓冲区：%s\n", filePath);

	//打开一个二进制文件，允许读写
	FILE* pFile = NULL;
	if (fopen_s(&pFile, filePath, "rb") != 0)
	{
		printf("错误：打开文件失败... \n");
		return 0;
	}

	//获取文件长度
	fseek(pFile, 0, SEEK_END);	//移动文件位置指针移到文件末尾并偏移0字节
	int fileLen = ftell(pFile);	//获取文件指针的当前位置下标(得到文件长度)
	fseek(pFile, 0, SEEK_SET); 	//文件指针恢复到文件开头

	//申请fileBuffer
	*ppFileBuffer = (PBYTE)malloc(fileLen);
	memset(*ppFileBuffer, 0x0, fileLen);

	//将文件内容写进申请到的fileBuffer
	for (int i = 0; i < fileLen; i++)
	{
		*(*ppFileBuffer + i) = (BYTE)fgetc(pFile);//fgetc返回字符的int值(自动拓展至32位)
	}

	//关闭文件、返回文件长度
	fclose(pFile);

	printf("装载完毕...");
	return fileLen;
}

/**
 * 转换：从Foa到Rva
 * 参数 FOA
 * 参数 PEHeader
 * 返回 RVA
 */
DWORD64 Trans_FOAtoRVA(DWORD64 FOA, PEHEADER PEHeader)
{
	//查找RVA所在的节（二分法查找）
	int highIndex = PEHeader.COFFHeader.Number_Of_Section - 1;
	int lowIndex = 0;
	int midIndex = (highIndex + lowIndex) / 2;
	while (highIndex >= lowIndex)
	{
		if (FOA >= PEHeader.SectionHeader.Pointer_To_Raw_Data[midIndex] && FOA < PEHeader.SectionHeader.Pointer_To_Raw_Data[midIndex] + PEHeader.SectionHeader.Size_Of_Raw_Data[midIndex])
			break;//找到

		if (FOA < PEHeader.SectionHeader.Pointer_To_Raw_Data[midIndex])
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
	DWORD offset = FOA - PEHeader.SectionHeader.Pointer_To_Raw_Data[midIndex];

	//找到该节的RVA
	DWORD sectionRVA = PEHeader.SectionHeader.Virtual_Address[midIndex];

	//所求RVA = 节的RVA + 偏移量
	DWORD RVA = sectionRVA + offset;

	return RVA;
}


/**
 * 转换：从Rva到Foa
 * 参数 RVA
 * 参数 PEHeader
 * 返回 FOA
 */
DWORD64 Trans_RVAtoFOA(DWORD64 RVA, PEHEADER PEHeader)
{
	//查找RVA所在的节（二分法查找）
	int highIndex = PEHeader.COFFHeader.Number_Of_Section - 1;
	int lowIndex = 0;
	int midIndex = (highIndex + lowIndex) / 2;
	while (highIndex >= lowIndex)
	{
		if (RVA >= PEHeader.SectionHeader.Virtual_Address[midIndex] && RVA < PEHeader.SectionHeader.Virtual_Address[midIndex] + PEHeader.SectionHeader.Virtual_Size[midIndex])
			break;//找到

		if (RVA < PEHeader.SectionHeader.Virtual_Address[midIndex])
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
	DWORD offset = RVA - PEHeader.SectionHeader.Virtual_Address[midIndex];

	//找到该节的FOA
	DWORD sectionFOA = PEHeader.SectionHeader.Pointer_To_Raw_Data[midIndex];

	//所求FOA = 节的FOA + 偏移量
	DWORD FOA = sectionFOA + offset;

	return FOA;
}
//计算重定位块的块数
int calcNumberOfBlock(DWORD Block_FOA, PEHEADER thePEHeader, PBYTE pFileBuffer, int count)
{
	DWORD BlockSize = *(DWORD*)(pFileBuffer + Block_FOA + 0x4);
	//判断结束标识(连续8字节都为0x0）
	if (*(DWORD64*)(pFileBuffer + Block_FOA + BlockSize) == 0x0)
	{
		return ++count;
	}
	return calcNumberOfBlock(Block_FOA + BlockSize, thePEHeader, pFileBuffer, ++count);
}

/**
 * 分析PE文件：通过FileBuffer分析
 * 参数 pFileBuffer
 * 参数 pPEHeader
 * 参数 pPEBody
 */
VOID AnalyzePE_ByFileBuffer(PBYTE pFileBuffer, OUT PEHEADER* pPEHeader, OUT PEBODY* pPEBody)
{
	//初始化
	BOOL ISX64 = FALSE;
	memset(pPEHeader, 0x0, sizeof(PEHEADER));
	memset(pPEBody, 0x0, sizeof(PEBODY));

	//-----------------分析PEHeader---------
	//分析[DOS头]
	pPEHeader->DOSHeader.MZ = *((WORD*)pFileBuffer);
	pPEHeader->DOSHeader.Offset_To_PE_Signature = *((DWORD*)(pFileBuffer + 0x3C));
	//分析[标准PE头]
	pPEHeader->COFFHeader.PE_Signature = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + 0x0));
	pPEHeader->COFFHeader.Number_Of_Section = *((WORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + 0x6));
	pPEHeader->COFFHeader.Size_Of_Optional_Headers = *((WORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + 0x14));
	//判断是32位还是64位PE文件
	if (pPEHeader->COFFHeader.Size_Of_Optional_Headers == 0xF0) { ISX64 = TRUE; }
	//分析[可选PE头]
	pPEHeader->OptionalHeader.Magic = *((WORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x0));
	pPEHeader->OptionalHeader.Address_Of_Entry_Point = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x10));
	pPEHeader->OptionalHeader.Section_Alignment = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x20));
	pPEHeader->OptionalHeader.File_Alignment = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x24));
	pPEHeader->OptionalHeader.Size_Of_Image = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x38));
	pPEHeader->OptionalHeader.Size_Of_Headers = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x3C));

	//分析64位和32位PE有差异的结构
	if (ISX64)
	{
		//[ImageBase]
		pPEHeader->OptionalHeader.Image_Base = *((DWORD64*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x18));
		//[可选PE头之数据目录]
		pPEHeader->OptionalHeader.Export_Directory_Offset = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x70));
		pPEHeader->OptionalHeader.Import_Directory_Offset = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x78));
		pPEHeader->OptionalHeader.Relocation_Directory_Offset = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x98));
		pPEHeader->OptionalHeader.Bound_Import_Directory_Offset = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0xC8));
	}
	else
	{
		//[ImageBase]
		pPEHeader->OptionalHeader.Image_Base = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x1C));
		//[可选PE头之数据目录]
		pPEHeader->OptionalHeader.Export_Directory_Offset = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x60));
		pPEHeader->OptionalHeader.Import_Directory_Offset = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x68));
		pPEHeader->OptionalHeader.Relocation_Directory_Offset = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x88));
		pPEHeader->OptionalHeader.Bound_Import_Directory_Offset = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0xB8));
	}

	//根据"节数量"，申请内存
	pPEHeader->SectionHeader.Section_Name = (DWORD64*)malloc(sizeof(DWORD64)*pPEHeader->COFFHeader.Number_Of_Section);
	pPEHeader->SectionHeader.Virtual_Size = (DWORD*)malloc(sizeof(DWORD)*pPEHeader->COFFHeader.Number_Of_Section);
	pPEHeader->SectionHeader.Virtual_Address = (DWORD*)malloc(sizeof(DWORD)*pPEHeader->COFFHeader.Number_Of_Section);
	pPEHeader->SectionHeader.Size_Of_Raw_Data = (DWORD*)malloc(sizeof(DWORD)*pPEHeader->COFFHeader.Number_Of_Section);
	pPEHeader->SectionHeader.Pointer_To_Raw_Data = (DWORD*)malloc(sizeof(DWORD)*pPEHeader->COFFHeader.Number_Of_Section);
	for (int i = 0; i < pPEHeader->COFFHeader.Number_Of_Section; i++)
	{
		pPEHeader->SectionHeader.Section_Name[i] = *((DWORD64*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + pPEHeader->COFFHeader.Size_Of_Optional_Headers + i * 40 + 0x0));
		pPEHeader->SectionHeader.Virtual_Size[i] = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + 0x18 + pPEHeader->COFFHeader.Size_Of_Optional_Headers + i * 40 + 0x8));
		pPEHeader->SectionHeader.Virtual_Address[i] = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + 0x18 + pPEHeader->COFFHeader.Size_Of_Optional_Headers + i * 40 + 0xC));
		pPEHeader->SectionHeader.Size_Of_Raw_Data[i] = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + 0x18 + pPEHeader->COFFHeader.Size_Of_Optional_Headers + i * 40 + 0x10));
		pPEHeader->SectionHeader.Pointer_To_Raw_Data[i] = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + 0x18 + pPEHeader->COFFHeader.Size_Of_Optional_Headers + i * 40 + 0x14));
	}

	//-----------------分析PEBody---------
	//判断导出目录是否存在
	if (pPEHeader->OptionalHeader.Export_Directory_Offset != 0x0)
	{
		//分析【导出目录】
		DWORD exportDirectory_FOA = Trans_RVAtoFOA(pPEHeader->OptionalHeader.Export_Directory_Offset, *pPEHeader);
		pPEBody->ExportDirectory.Ordinal_Base = *(DWORD*)(pFileBuffer + exportDirectory_FOA + 0x4 * 0x4);
		pPEBody->ExportDirectory.Number_Of_Functions = *(DWORD*)(pFileBuffer + exportDirectory_FOA + 0x5 * 0x4);
		pPEBody->ExportDirectory.Number_Of_Names = *(DWORD*)(pFileBuffer + exportDirectory_FOA + 0x6 * 0x4);
		pPEBody->ExportDirectory.Address_Of_Functions = *(DWORD*)(pFileBuffer + exportDirectory_FOA + 0x7 * 0x4);
		pPEBody->ExportDirectory.Address_Of_Names = *(DWORD*)(pFileBuffer + exportDirectory_FOA + 0x8 * 0x4);
		pPEBody->ExportDirectory.Address_Of_NameOrdinals = *(DWORD*)(pFileBuffer + exportDirectory_FOA + 0x9 * 0x4);

		//分析由【导出目录】映射的【函数名称表】【函数名称序号表】
		pPEBody->Functions_Address = (DWORD *)malloc(sizeof(DWORD)*pPEBody->ExportDirectory.Number_Of_Functions);
		pPEBody->Functions_Names = (DWORD *)malloc(sizeof(DWORD)*pPEBody->ExportDirectory.Number_Of_Names);
		pPEBody->Functions_NameOrdinals = (WORD*)malloc(sizeof(DWORD)*pPEBody->ExportDirectory.Number_Of_Names);
		for (DWORD i = 0; i < pPEBody->ExportDirectory.Number_Of_Names; i++)
		{
			pPEBody->Functions_Names[i] = *(DWORD*)(pFileBuffer + Trans_RVAtoFOA(pPEBody->ExportDirectory.Address_Of_Names, *pPEHeader) + 0x4 * i);
			pPEBody->Functions_NameOrdinals[i] = *(WORD*)(pFileBuffer + Trans_RVAtoFOA(pPEBody->ExportDirectory.Address_Of_NameOrdinals, *pPEHeader) + 0x2 * i);
		}
		//分析由【导出目录】映射的【函数地址表】
		for (DWORD i = 0; i < pPEBody->ExportDirectory.Number_Of_Functions; i++)
		{
			pPEBody->Functions_Address[i] = *(DWORD*)(pFileBuffer + Trans_RVAtoFOA(pPEBody->ExportDirectory.Address_Of_Functions, *pPEHeader) + 0x4 * i);
		}
	}
	//分析【重定位目录】
	//先判断重定位目录是否存在
	if (pPEHeader->OptionalHeader.Relocation_Directory_Offset != 0x0)
	{
		DWORD BlockStart_FOA = Trans_RVAtoFOA(pPEHeader->OptionalHeader.Relocation_Directory_Offset, *pPEHeader);
		//计算重定位块的块数，申请堆空间
		pPEBody->ReloactionDirectory.pri_sum_block = calcNumberOfBlock(BlockStart_FOA, *pPEHeader, pFileBuffer);
		pPEBody->ReloactionDirectory.Block = (RELOCATION_BLOCK*)malloc(sizeof(RELOCATION_BLOCK)*pPEBody->ReloactionDirectory.pri_sum_block);
		for (int i = 0; i < pPEBody->ReloactionDirectory.pri_sum_block; i++)
		{

			pPEBody->ReloactionDirectory.Block[i].Virtual_Address = *(DWORD*)(pFileBuffer + BlockStart_FOA + 0x0);
			pPEBody->ReloactionDirectory.Block[i].Size_Of_Block = *(DWORD*)(pFileBuffer + BlockStart_FOA + 0x4);
			int numberOfItem = (pPEBody->ReloactionDirectory.Block[i].Size_Of_Block - 0x8) / 0x2;
			pPEBody->ReloactionDirectory.Block[i].Item = (RELOCATION_ITEM*)malloc(sizeof(RELOCATION_ITEM)*numberOfItem);
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
	if (pPEHeader->OptionalHeader.Import_Directory_Offset != 0x0)
	{
		//计算导入目录的个数
		DWORD FirstImportDir_FOA = Trans_RVAtoFOA(pPEHeader->OptionalHeader.Import_Directory_Offset, *pPEHeader);
		DWORD DirSize = sizeof(IMPORT_DIRECTORY);//单个导入目录Size
		while (true)
		{
			IMPORT_DIRECTORY temp = *(IMPORT_DIRECTORY*)(pFileBuffer + FirstImportDir_FOA + pPEBody->pri_sum_importDirectory * DirSize);
			if (temp.FirstThunk == 0x0 && temp.ForwarderChain == 0x0 && temp.Name == 0x0 && temp.OriginalFirstThunk == 0x0 && temp.TimeDateStamp == 0x0)//判断结构体全为0x0
			{
				break;
			}
			pPEBody->pri_sum_importDirectory++;
		}

		//根据导入目录个数，申请堆空间
		pPEBody->ImportDirectory = (IMPORT_DIRECTORY*)malloc(sizeof(IMPORT_DIRECTORY)*pPEBody->pri_sum_importDirectory);
		pPEBody->INT_Table = (INT_TABLE*)malloc(sizeof(INT_TABLE)* pPEBody->pri_sum_importDirectory);
		pPEBody->IAT_Table = (IAT_TABLE*)malloc(sizeof(IAT_TABLE)* pPEBody->pri_sum_importDirectory);
		memset(pPEBody->INT_Table, 0x0, sizeof(INT_TABLE)* pPEBody->pri_sum_importDirectory);
		memset(pPEBody->IAT_Table, 0x0, sizeof(IAT_TABLE)* pPEBody->pri_sum_importDirectory);
		memset(pPEBody->ImportDirectory, 0x0, sizeof(IMPORT_DIRECTORY)*pPEBody->pri_sum_importDirectory);

		//逐个分析
		for (DWORD i = 0; i < pPEBody->pri_sum_importDirectory; i++)
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
			DWORD OriginalFirstThunk_FOA = Trans_RVAtoFOA(pPEBody->ImportDirectory[i].OriginalFirstThunk, *pPEHeader);
			while (true)
			{
				if (*(DWORD*)(pFileBuffer + OriginalFirstThunk_FOA + pPEBody->INT_Table[i].pri_sum_item * 0x4) == 0x0)
				{
					break;
				}
				pPEBody->INT_Table[i].pri_sum_item++;
			}
			//分析IAT表的项个数
			DWORD FirstThunk_FOA = Trans_RVAtoFOA(pPEBody->ImportDirectory[i].FirstThunk, *pPEHeader);
			while (true)
			{
				if (*(DWORD*)(pFileBuffer + FirstThunk_FOA + pPEBody->IAT_Table[i].pri_sum_item * 0x4) == 0x0)
				{
					break;
				}
				pPEBody->IAT_Table[i].pri_sum_item++;
			}

			//根据INT表的项个数，申请堆内存
			pPEBody->INT_Table[i].IMAGE_THUNK_DATA = (DWORD *)malloc(pPEBody->INT_Table[i].pri_sum_item * 0x4);

			//根据IAT表的项个数，申请堆内存
			pPEBody->IAT_Table[i].funcAddress = (DWORD *)malloc(pPEBody->IAT_Table[i].pri_sum_item * 0x4);

			//为INT表的每个项赋值
			for (DWORD j = 0; j < pPEBody->INT_Table[i].pri_sum_item; j++)
			{
				pPEBody->INT_Table[i].IMAGE_THUNK_DATA[j] = *(DWORD *)(pFileBuffer + OriginalFirstThunk_FOA + j * 0x4);
			}

			//为IAT表的每个项赋值
			for (DWORD j = 0; j < pPEBody->IAT_Table[i].pri_sum_item; j++)
			{
				pPEBody->IAT_Table[i].funcAddress[j] = *(DWORD *)(pFileBuffer + FirstThunk_FOA + j * 0x4);
			}

		}
	}

	//分析【绑定导入目录】：使用动态数组的思路申请内存(循环申请和释放)
	//先判断存在
	if (pPEHeader->OptionalHeader.Bound_Import_Directory_Offset != 0x0)
	{
		//计算【绑定导入目录】的首地址的FOA，注意实际上因为这个FOA、RVA处于节表中，故不需要转换
		DWORD Dir_FOA = Trans_RVAtoFOA(pPEHeader->OptionalHeader.Bound_Import_Directory_Offset, *pPEHeader);
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
			pPEBody->pri_sum_boundImportDirectory++;

			//保存上一轮循环所申请的堆内存指针
			BoundImportDirectory* lastPoint = pPEBody->BoundImportDirectory;

			//申请当前循环的【绑定导入目录】的堆内存
			pPEBody->BoundImportDirectory = (BoundImportDirectory*)malloc(sizeof(BoundImportDirectory)*pPEBody->pri_sum_boundImportDirectory);
			memset(pPEBody->BoundImportDirectory, 0x0, sizeof(BoundImportDirectory)*pPEBody->pri_sum_boundImportDirectory);

			//分配当前循环的【绑定导入目录】的参数
			pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].TimeDateStamp = *(DWORD*)(pFileBuffer + cursor_FOA);
			pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].OffsetModuleName = *(unsigned short*)(pFileBuffer + cursor_FOA + 0x4);
			pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].NumberOfModuleForwarderRefs = *(unsigned short*)(pFileBuffer + cursor_FOA + 0x4 + 0x2);

			//当前循环的【绑定导入目录】的BoundForwarderRef结构的参数
			pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].BoundForwarderRef = (BoundForwarderRef*)malloc(sizeof(BoundForwarderRef)*pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].NumberOfModuleForwarderRefs);
			memset(pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].BoundForwarderRef, 0x0, sizeof(BoundForwarderRef)*pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].NumberOfModuleForwarderRefs);
			for (DWORD i = 0; i < pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].NumberOfModuleForwarderRefs; i++)
			{
				pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].BoundForwarderRef[i].TimeDateStamp = *(DWORD*)(pFileBuffer + cursor_FOA + 0x8 + i * 0x8);
				pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].BoundForwarderRef[i].OffsetModuleName = *(DWORD*)(pFileBuffer + cursor_FOA + 0x8 + i * 0x8 + 0x4);
				pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].BoundForwarderRef[i].Reserved = *(DWORD*)(pFileBuffer + cursor_FOA + 0x8 + i * 0x8 + 0x4 + 0x2);
			}

			//从第2轮循环开始
			if (pPEBody->pri_sum_boundImportDirectory >= 2)
			{
				//将上一次循环申请的堆内存 复制到 新的堆内存
				memcpy(pPEBody->BoundImportDirectory, lastPoint, sizeof(BoundImportDirectory)*(pPEBody->pri_sum_boundImportDirectory - 1));

				//将上一次循环申请的堆内存释放
				free(lastPoint);
			}
			//游标移至下一个绑定导入目录
			cursor_FOA += (pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].NumberOfModuleForwarderRefs * 0x8 + 0x8);

		}
	}
}

/**
 * 装载ImageBuffer：从fileBuffer拉伸至ImageBuffer
 * 参数 filePath
 * 参数 ppFileBuffer
 * 返回 fileLen 读取的文件长度
 */
VOID LoadImageBuffer(PBYTE pFileBuffer, OUT PBYTE* ppImageBuffer, PEHEADER PEHeader)
{
	//申请imageBuffer
	*ppImageBuffer = (PBYTE)malloc(PEHeader.OptionalHeader.Size_Of_Image);
	memset(*ppImageBuffer, 0x0, PEHeader.OptionalHeader.Size_Of_Image);

	//根据[SizeOfHeaders]将FileBuffer内的"头信息"原封不动地拷贝至imageBuffer
	for (DWORD i = 0; i < PEHeader.OptionalHeader.Size_Of_Headers; i++)
	{
		*(*ppImageBuffer + i) = *(pFileBuffer + i);
	}
	//将"节信息"拉伸至imageBuffer
	for (DWORD i = 0; i < PEHeader.COFFHeader.Number_Of_Section; i++)
	{
		for (DWORD j = 0; j < PEHeader.SectionHeader.Size_Of_Raw_Data[i]; j++)
		{
			*(*ppImageBuffer + PEHeader.SectionHeader.Virtual_Address[i] + j) = *(pFileBuffer + PEHeader.SectionHeader.Pointer_To_Raw_Data[i] + j);
		}
	}
}

/**
 * 将ImageBuffer还原至FileBuffer
 * 参数 pImageBuffer
 * 参数 PEHeader
 * 参数 fileLen
 * 参数 [OUT] ppFileBuffer
 */
VOID BackToFileBuffer(PBYTE pImageBuffer, PEHEADER PEHeader, int fileLen, OUT PBYTE* ppFileBuffer)
{
	*ppFileBuffer = (PBYTE)malloc(fileLen);
	memset(*ppFileBuffer, 0x0, fileLen);
	for (int i = 0; i < PEHeader.OptionalHeader.Size_Of_Headers; i++)
	{
		*(*ppFileBuffer + i) = *(pImageBuffer + i);
	}
	for (int i = 0; i < PEHeader.COFFHeader.Number_Of_Section; i++)
	{
		for (int j = 0; j < PEHeader.SectionHeader.Size_Of_Raw_Data[i]; j++)
		{
			*(*ppFileBuffer + PEHeader.SectionHeader.Pointer_To_Raw_Data[i] + j) = *(pImageBuffer + PEHeader.SectionHeader.Virtual_Address[i] + j);
		}
	}
}
//

/**
 * 将FileBuffer写入文件
 * 参数 destFilePath
 * 参数 destfileLen
 * 参数 pFileBuffer
 */
VOID SaveFile(const CHAR* destFilePath, int destfileLen, PBYTE pFileBuffer)
{
	printf("\n开始写入文件...\n");
	printf("File Path = %s \n", destFilePath);
	FILE* pNewFile = NULL;
	int errorCode = fopen_s(&pNewFile, destFilePath, "wb+");
	if (errorCode == 0)
	{
		for (DWORD i = 0; i < destfileLen; i++)
		{
			fputc(*(pFileBuffer + i), pNewFile);
		}
	}
	else
	{
		printf("错误：打开文件失败,code=%d \n", errorCode);
		return;
	}
	fclose(pNewFile);
	printf("写入文件完毕... \n");
}


/**
 * 分析PE文件：通过FileBuffer分析
 * 参数 pImageBuffer
 * 参数 [OUT] pPEHeader
 * 参数 [OUT] pPEBody
 */
VOID AnalyzePE_ByImageBuffer(PBYTE pImageBuffer, OUT PEHEADER* pPEHeader, OUT PEBODY* pPEBody)
{
	//先初始化为0
	memset(pPEHeader, 0x0, sizeof(PEHEADER));
	memset(pPEBody, 0x0, sizeof(PEBODY));

	//分析PEHeader(与FileBuffer的分析相同)
	//初始化
	BOOL ISX64 = FALSE;
	memset(pPEHeader, 0x0, sizeof(PEHEADER));
	memset(pPEBody, 0x0, sizeof(PEBODY));

	//-----------------分析PEHeader---------
	//分析[DOS头]
	pPEHeader->DOSHeader.MZ = *((WORD*)pImageBuffer);
	pPEHeader->DOSHeader.Offset_To_PE_Signature = *((DWORD*)(pImageBuffer + 0x3C));
	//分析[标准PE头]
	pPEHeader->COFFHeader.PE_Signature = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + 0x0));
	pPEHeader->COFFHeader.Number_Of_Section = *((WORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + 0x6));
	pPEHeader->COFFHeader.Size_Of_Optional_Headers = *((WORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + 0x14));
	//判断是32位还是64位PE文件
	if (pPEHeader->COFFHeader.Size_Of_Optional_Headers == 0xF0) { ISX64 = TRUE; }
	//分析[可选PE头]
	pPEHeader->OptionalHeader.Magic = *((WORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x0));
	pPEHeader->OptionalHeader.Address_Of_Entry_Point = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x10));
	pPEHeader->OptionalHeader.Section_Alignment = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x20));
	pPEHeader->OptionalHeader.File_Alignment = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x24));
	pPEHeader->OptionalHeader.Size_Of_Image = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x38));
	pPEHeader->OptionalHeader.Size_Of_Headers = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x3C));

	//分析64位和32位PE有差异的结构
	if (ISX64)
	{
		//[ImageBase]
		pPEHeader->OptionalHeader.Image_Base = *((DWORD64*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x18));
		//[可选PE头之数据目录]
		pPEHeader->OptionalHeader.Export_Directory_Offset = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x70));
		pPEHeader->OptionalHeader.Import_Directory_Offset = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x78));
		pPEHeader->OptionalHeader.Relocation_Directory_Offset = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x98));
		pPEHeader->OptionalHeader.Bound_Import_Directory_Offset = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0xC8));
	}
	else
	{
		//[ImageBase]
		pPEHeader->OptionalHeader.Image_Base = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x1C));
		//[可选PE头之数据目录]
		pPEHeader->OptionalHeader.Export_Directory_Offset = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x60));
		pPEHeader->OptionalHeader.Import_Directory_Offset = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x68));
		pPEHeader->OptionalHeader.Relocation_Directory_Offset = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x88));
		pPEHeader->OptionalHeader.Bound_Import_Directory_Offset = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0xB8));
	}

	//根据"节数量"，申请内存
	pPEHeader->SectionHeader.Section_Name = (DWORD64*)malloc(sizeof(DWORD64)*pPEHeader->COFFHeader.Number_Of_Section);
	pPEHeader->SectionHeader.Virtual_Size = (DWORD*)malloc(sizeof(DWORD)*pPEHeader->COFFHeader.Number_Of_Section);
	pPEHeader->SectionHeader.Virtual_Address = (DWORD*)malloc(sizeof(DWORD)*pPEHeader->COFFHeader.Number_Of_Section);
	pPEHeader->SectionHeader.Size_Of_Raw_Data = (DWORD*)malloc(sizeof(DWORD)*pPEHeader->COFFHeader.Number_Of_Section);
	pPEHeader->SectionHeader.Pointer_To_Raw_Data = (DWORD*)malloc(sizeof(DWORD)*pPEHeader->COFFHeader.Number_Of_Section);
	for (int i = 0; i < pPEHeader->COFFHeader.Number_Of_Section; i++)
	{
		pPEHeader->SectionHeader.Section_Name[i] = *((DWORD64*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + pPEHeader->COFFHeader.Size_Of_Optional_Headers + i * 40 + 0x0));
		pPEHeader->SectionHeader.Virtual_Size[i] = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + 0x18 + pPEHeader->COFFHeader.Size_Of_Optional_Headers + i * 40 + 0x8));
		pPEHeader->SectionHeader.Virtual_Address[i] = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + 0x18 + pPEHeader->COFFHeader.Size_Of_Optional_Headers + i * 40 + 0xC));
		pPEHeader->SectionHeader.Size_Of_Raw_Data[i] = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + 0x18 + pPEHeader->COFFHeader.Size_Of_Optional_Headers + i * 40 + 0x10));
		pPEHeader->SectionHeader.Pointer_To_Raw_Data[i] = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + 0x18 + pPEHeader->COFFHeader.Size_Of_Optional_Headers + i * 40 + 0x14));
	}
	//-------分析PEBody---------
	//分析【导出目录】
	if (pPEHeader->OptionalHeader.Export_Directory_Offset != 0x0)
	{//判断【导出目录】是否存在
		DWORD RVA = pPEHeader->OptionalHeader.Export_Directory_Offset;
		pPEBody->ExportDirectory.Ordinal_Base = *(DWORD*)(pImageBuffer + RVA + 0x4 * 0x4);
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
	if (pPEHeader->OptionalHeader.Relocation_Directory_Offset != 0x0)
	{//先判断重定位目录是否存在

		DWORD RVA = pPEHeader->OptionalHeader.Relocation_Directory_Offset;
		//计算重定位块的块数，申请堆空间
		pPEBody->ReloactionDirectory.pri_sum_block = calcNumberOfBlock(RVA, *pPEHeader, pImageBuffer);
		pPEBody->ReloactionDirectory.Block = (RELOCATION_BLOCK*)malloc(sizeof(RELOCATION_BLOCK)*pPEBody->ReloactionDirectory.pri_sum_block);
		for (int i = 0; i < pPEBody->ReloactionDirectory.pri_sum_block; i++)
		{
			pPEBody->ReloactionDirectory.Block[i].Virtual_Address = *(DWORD*)(pImageBuffer + RVA + 0x0);
			pPEBody->ReloactionDirectory.Block[i].Size_Of_Block = *(DWORD*)(pImageBuffer + RVA + 0x4);
			int numberOfItem = (pPEBody->ReloactionDirectory.Block[i].Size_Of_Block - 0x8) / 0x2;
			pPEBody->ReloactionDirectory.Block[i].Item = (RELOCATION_ITEM*)malloc(sizeof(RELOCATION_ITEM)*numberOfItem);
			for (int index = 0; index < numberOfItem; index++)
			{
				pPEBody->ReloactionDirectory.Block[i].Item[index].Offset = *(unsigned short *)(pImageBuffer + RVA + 0x8 + 0x2 * index) & 0x0FFF;
				pPEBody->ReloactionDirectory.Block[i].Item[index].Type = *(unsigned short *)(pImageBuffer + RVA + 0x8 + 0x2 * index) >> 12;
			}
			RVA += pPEBody->ReloactionDirectory.Block[i].Size_Of_Block;
		}
	}

	//分析【导入目录】
	if (pPEHeader->OptionalHeader.Import_Directory_Offset != 0x0)
	{//先判断导入目录是否存在

		//计算导入目录的个数
		DWORD RVA = pPEHeader->OptionalHeader.Import_Directory_Offset;
		DWORD DirSize = sizeof(IMPORT_DIRECTORY);//单个导入目录Size
		while (true)
		{
			IMPORT_DIRECTORY temp = *(IMPORT_DIRECTORY*)(pImageBuffer + RVA + pPEBody->pri_sum_importDirectory * DirSize);
			if (temp.FirstThunk == 0x0 && temp.ForwarderChain == 0x0 && temp.Name == 0x0 && temp.OriginalFirstThunk == 0x0 && temp.TimeDateStamp == 0x0)//判断结构体全为0x0
			{
				break;
			}
			pPEBody->pri_sum_importDirectory++;
		}

		//根据导入目录个数，申请堆空间
		pPEBody->ImportDirectory = (IMPORT_DIRECTORY*)malloc(sizeof(IMPORT_DIRECTORY)*pPEBody->pri_sum_importDirectory);
		pPEBody->INT_Table = (INT_TABLE*)malloc(sizeof(INT_TABLE)* pPEBody->pri_sum_importDirectory);
		pPEBody->IAT_Table = (IAT_TABLE*)malloc(sizeof(IAT_TABLE)* pPEBody->pri_sum_importDirectory);
		memset(pPEBody->INT_Table, 0x0, sizeof(INT_TABLE)* pPEBody->pri_sum_importDirectory);
		memset(pPEBody->IAT_Table, 0x0, sizeof(IAT_TABLE)* pPEBody->pri_sum_importDirectory);
		memset(pPEBody->ImportDirectory, 0x0, sizeof(IMPORT_DIRECTORY)*pPEBody->pri_sum_importDirectory);

		//逐个分析
		for (DWORD i = 0; i < pPEBody->pri_sum_importDirectory; i++)
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
				if (*(DWORD*)(pImageBuffer + RVA_OriginalFirstThunk + pPEBody->INT_Table[i].pri_sum_item * 0x4) == 0x0)
				{
					break;
				}
				pPEBody->INT_Table[i].pri_sum_item++;
			}
			if (pPEBody->ImportDirectory[i].OriginalFirstThunk == 0x0)
			{
				printf("错误：imageBuffer中的INT表为空，考虑用其他方法获取导入函数的名称... \n");
				pPEBody->INT_Table[i].pri_sum_item = 0;
			}
			//分析IAT表的项个数
			DWORD RVA_FirstThunk = pPEBody->ImportDirectory[i].FirstThunk;
			while (true)
			{
				if (*(DWORD*)(pImageBuffer + RVA_FirstThunk + pPEBody->IAT_Table[i].pri_sum_item * 0x4) == 0x0)
				{
					break;
				}
				pPEBody->IAT_Table[i].pri_sum_item++;
			}
			//根据INT表的项个数，申请堆内存
			pPEBody->INT_Table[i].IMAGE_THUNK_DATA = (DWORD *)malloc(pPEBody->INT_Table[i].pri_sum_item * 0x4);

			//根据IAT表的项个数，申请堆内存
			pPEBody->IAT_Table[i].funcAddress = (DWORD *)malloc(pPEBody->IAT_Table[i].pri_sum_item * 0x4);

			//为INT表的每个项赋值
			for (DWORD j = 0; j < pPEBody->INT_Table[i].pri_sum_item; j++)
			{
				pPEBody->INT_Table[i].IMAGE_THUNK_DATA[j] = *(DWORD *)(pImageBuffer + RVA_OriginalFirstThunk + j * 0x4);
			}
			//为IAT表的每个项赋值
			for (DWORD j = 0; j < pPEBody->IAT_Table[i].pri_sum_item; j++)
			{
				pPEBody->IAT_Table[i].funcAddress[j] = *(DWORD *)(pImageBuffer + RVA_FirstThunk + j * 0x4);
			}
		}
	}

	//分析【绑定导入目录】：使用动态数组的思路申请内存(循环申请和释放)
	//先判断存在
	if (pPEHeader->OptionalHeader.Bound_Import_Directory_Offset != 0x0)
	{
		//计算【绑定导入目录】的首地址的FOA，注意实际上因为这个FOA、RVA处于节表中，故不需要转换
		DWORD RVA_Dir = pPEHeader->OptionalHeader.Bound_Import_Directory_Offset;
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
			pPEBody->pri_sum_boundImportDirectory++;

			//保存上一轮循环所申请的堆内存指针
			BoundImportDirectory* lastPoint = pPEBody->BoundImportDirectory;

			//申请当前循环的【绑定导入目录】的堆内存
			pPEBody->BoundImportDirectory = (BoundImportDirectory*)malloc(sizeof(BoundImportDirectory)*pPEBody->pri_sum_boundImportDirectory);
			memset(pPEBody->BoundImportDirectory, 0x0, sizeof(BoundImportDirectory)*pPEBody->pri_sum_boundImportDirectory);

			//分配当前循环的【绑定导入目录】的参数
			pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].TimeDateStamp = *(DWORD*)(pImageBuffer + RVA_cursor);
			pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].OffsetModuleName = *(unsigned short*)(pImageBuffer + RVA_cursor + 0x4);
			pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].NumberOfModuleForwarderRefs = *(unsigned short*)(pImageBuffer + RVA_cursor + 0x4 + 0x2);

			//当前循环的【绑定导入目录】的BoundForwarderRef结构的参数
			pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].BoundForwarderRef = (BoundForwarderRef*)malloc(sizeof(BoundForwarderRef)*pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].NumberOfModuleForwarderRefs);
			memset(pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].BoundForwarderRef, 0x0, sizeof(BoundForwarderRef)*pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].NumberOfModuleForwarderRefs);
			for (DWORD i = 0; i < pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].NumberOfModuleForwarderRefs; i++)
			{
				pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].BoundForwarderRef[i].TimeDateStamp = *(DWORD*)(pImageBuffer + RVA_cursor + 0x8 + i * 0x8);
				pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].BoundForwarderRef[i].OffsetModuleName = *(DWORD*)(pImageBuffer + RVA_cursor + 0x8 + i * 0x8 + 0x4);
				pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].BoundForwarderRef[i].Reserved = *(DWORD*)(pImageBuffer + RVA_cursor + 0x8 + i * 0x8 + 0x4 + 0x2);
			}

			//从第2轮循环开始
			if (pPEBody->pri_sum_boundImportDirectory >= 2)
			{
				//将上一次循环申请的堆内存 复制到 新的堆内存
				memcpy(pPEBody->BoundImportDirectory, lastPoint, sizeof(BoundImportDirectory)*(pPEBody->pri_sum_boundImportDirectory - 1));

				//将上一次循环申请的堆内存释放
				free(lastPoint);
			}
			//游标移至下一个绑定导入目录
			RVA_cursor += (pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].NumberOfModuleForwarderRefs * 0x8 + 0x8);
		}

	}
}

/**
 * 修复重定位表(ImageBuffer)
 * 参数 destImageBase 新基址
 * 参数 srcImageBase  原基址不从PE文件中直接读取，因为可能是动态基址
 * 参数 pImageBuffer
 * 参数 pPEHeader
 * 参数 pPEBody
 */
BOOL Repair_ReLocDirectory(DWORD64 newImageBase, DWORD64 oldImageBase, PBYTE pImageBuffer, PEHEADER* pPEHeader, PEBODY* pPEBody)
{
	printf("\n开始修复重定位表...新基址=%llX 旧基址=%llX \n", newImageBase, oldImageBase);
	//0.新基址合法性检查
	if (newImageBase == 0)
	{
		printf("错误：传入的新基址=0 \n");
		return FALSE;
	}
	if (pPEHeader->COFFHeader.Size_Of_Optional_Headers == 0xE0 && newImageBase >= 0x100000000)
	{
		printf("错误：原PE文件是32位文件，但新基址大于32位... \n");
		return FALSE;
	}

	//1.判断是否存在重定位表
	if (pPEHeader->OptionalHeader.Relocation_Directory_Offset == 0x0)
	{
		printf("错误：原PE不存在重定位表(exe文件需要编译成release版本才有重定位表）... \n");
		return FALSE;
	}

	//2.修改ImageBuffer缓冲区和PEHeader结构体中的ImageBase
	if (pPEHeader->COFFHeader.Size_Of_Optional_Headers == 0xF0)
	{//64位PE
		pPEHeader->OptionalHeader.Image_Base = newImageBase;
		*(DWORD64 *)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x18) = newImageBase;
	}
	else
	{//32位PE
		pPEHeader->OptionalHeader.Image_Base = newImageBase;
		*(DWORD *)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x1C) = newImageBase;
	}

	//3. 根据重定位目录修正ImageBuffer中存储的各地址值
	for (int i = 0; i < pPEBody->ReloactionDirectory.pri_sum_block; i++)
	{
		DWORD numberOfItem = (pPEBody->ReloactionDirectory.Block[i].Size_Of_Block - 0x8) / 0x2;
		for (int j = 0; j < numberOfItem; j++)
		{
			if (pPEBody->ReloactionDirectory.Block[i].Item[j].Type == 0x3)
			{
				//计算需要重定位的内容的地址
				DWORD goal_RVA = pPEBody->ReloactionDirectory.Block[i].Virtual_Address + pPEBody->ReloactionDirectory.Block[i].Item[j].Offset;
				//因为十六进制的减法的位溢出问题，这里用大地址减去小地址，确保差值是正的！！！！非常重要！！
				if (newImageBase >= pPEHeader->OptionalHeader.Image_Base)
				{
					//因为要修正的内容是"地址值"，32位时占4字节，64位时占8字节
					if (pPEHeader->COFFHeader.Size_Of_Optional_Headers == 0xF0)
						*(DWORD*)(pImageBuffer + goal_RVA) += (newImageBase - oldImageBase);
					else
						*(DWORD64*)(pImageBuffer + goal_RVA) += (newImageBase - oldImageBase);
				}
				else
				{
					if (pPEHeader->COFFHeader.Size_Of_Optional_Headers == 0xF0)
						*(DWORD*)(pImageBuffer + goal_RVA) -= (oldImageBase - newImageBase);
					else
						*(DWORD64*)(pImageBuffer + goal_RVA) -= (oldImageBase - newImageBase);
				}

			}
		}
	}
	printf("修复重定位表完毕...  \n");
	return TRUE;
}
