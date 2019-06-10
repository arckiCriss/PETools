#include "pch.h"
/**
 * װ��FileBuffer����ȡ�ļ�
 * ���� filePath
 * ���� ppFileBuffer
 * ���� fileLen ��ȡ���ļ�����
 */
int LoadFileBuffer(const TCHAR* filePath, OUT PBYTE* ppFileBuffer)
{
	printf("\n��ʼװ���ļ���������%s\n", filePath);

	//��һ���������ļ��������д
	FILE* pFile = NULL;
	if (fopen_s(&pFile, filePath, "rb") != 0)
	{
		printf("���󣺴��ļ�ʧ��... \n");
		return 0;
	}

	//��ȡ�ļ�����
	fseek(pFile, 0, SEEK_END);	//�ƶ��ļ�λ��ָ���Ƶ��ļ�ĩβ��ƫ��0�ֽ�
	int fileLen = ftell(pFile);	//��ȡ�ļ�ָ��ĵ�ǰλ���±�(�õ��ļ�����)
	fseek(pFile, 0, SEEK_SET); 	//�ļ�ָ��ָ����ļ���ͷ

	//����fileBuffer
	*ppFileBuffer = (PBYTE)malloc(fileLen);
	memset(*ppFileBuffer, 0x0, fileLen);

	//���ļ�����д�����뵽��fileBuffer
	for (int i = 0; i < fileLen; i++)
	{
		*(*ppFileBuffer + i) = (BYTE)fgetc(pFile);//fgetc�����ַ���intֵ(�Զ���չ��32λ)
	}

	//�ر��ļ��������ļ�����
	fclose(pFile);

	printf("װ�����...");
	return fileLen;
}

/**
 * ת������Foa��Rva
 * ���� FOA
 * ���� PEHeader
 * ���� RVA
 */
DWORD64 Trans_FOAtoRVA(DWORD64 FOA, PEHEADER PEHeader)
{
	//����RVA���ڵĽڣ����ַ����ң�
	int highIndex = PEHeader.COFFHeader.Number_Of_Section - 1;
	int lowIndex = 0;
	int midIndex = (highIndex + lowIndex) / 2;
	while (highIndex >= lowIndex)
	{
		if (FOA >= PEHeader.SectionHeader.Pointer_To_Raw_Data[midIndex] && FOA < PEHeader.SectionHeader.Pointer_To_Raw_Data[midIndex] + PEHeader.SectionHeader.Size_Of_Raw_Data[midIndex])
			break;//�ҵ�

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
	//����FOA����ڸýڵ�ƫ����
	DWORD offset = FOA - PEHeader.SectionHeader.Pointer_To_Raw_Data[midIndex];

	//�ҵ��ýڵ�RVA
	DWORD sectionRVA = PEHeader.SectionHeader.Virtual_Address[midIndex];

	//����RVA = �ڵ�RVA + ƫ����
	DWORD RVA = sectionRVA + offset;

	return RVA;
}


/**
 * ת������Rva��Foa
 * ���� RVA
 * ���� PEHeader
 * ���� FOA
 */
DWORD64 Trans_RVAtoFOA(DWORD64 RVA, PEHEADER PEHeader)
{
	//����RVA���ڵĽڣ����ַ����ң�
	int highIndex = PEHeader.COFFHeader.Number_Of_Section - 1;
	int lowIndex = 0;
	int midIndex = (highIndex + lowIndex) / 2;
	while (highIndex >= lowIndex)
	{
		if (RVA >= PEHeader.SectionHeader.Virtual_Address[midIndex] && RVA < PEHeader.SectionHeader.Virtual_Address[midIndex] + PEHeader.SectionHeader.Virtual_Size[midIndex])
			break;//�ҵ�

		if (RVA < PEHeader.SectionHeader.Virtual_Address[midIndex])
		{
			if (midIndex == 0)
			{
				//���RVA���ڵ�0��֮ǰ��˵���ڽڱ��У�����Ҫת���ˣ�ֱ�ӷ���
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
	//����RVA����ڸýڵ�ƫ����
	DWORD offset = RVA - PEHeader.SectionHeader.Virtual_Address[midIndex];

	//�ҵ��ýڵ�FOA
	DWORD sectionFOA = PEHeader.SectionHeader.Pointer_To_Raw_Data[midIndex];

	//����FOA = �ڵ�FOA + ƫ����
	DWORD FOA = sectionFOA + offset;

	return FOA;
}
//�����ض�λ��Ŀ���
int calcNumberOfBlock(DWORD Block_FOA, PEHEADER thePEHeader, PBYTE pFileBuffer, int count)
{
	DWORD BlockSize = *(DWORD*)(pFileBuffer + Block_FOA + 0x4);
	//�жϽ�����ʶ(����8�ֽڶ�Ϊ0x0��
	if (*(DWORD64*)(pFileBuffer + Block_FOA + BlockSize) == 0x0)
	{
		return ++count;
	}
	return calcNumberOfBlock(Block_FOA + BlockSize, thePEHeader, pFileBuffer, ++count);
}

/**
 * ����PE�ļ���ͨ��FileBuffer����
 * ���� pFileBuffer
 * ���� pPEHeader
 * ���� pPEBody
 */
VOID AnalyzePE_ByFileBuffer(PBYTE pFileBuffer, OUT PEHEADER* pPEHeader, OUT PEBODY* pPEBody)
{
	//��ʼ��
	BOOL ISX64 = FALSE;
	memset(pPEHeader, 0x0, sizeof(PEHEADER));
	memset(pPEBody, 0x0, sizeof(PEBODY));

	//-----------------����PEHeader---------
	//����[DOSͷ]
	pPEHeader->DOSHeader.MZ = *((WORD*)pFileBuffer);
	pPEHeader->DOSHeader.Offset_To_PE_Signature = *((DWORD*)(pFileBuffer + 0x3C));
	//����[��׼PEͷ]
	pPEHeader->COFFHeader.PE_Signature = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + 0x0));
	pPEHeader->COFFHeader.Number_Of_Section = *((WORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + 0x6));
	pPEHeader->COFFHeader.Size_Of_Optional_Headers = *((WORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + 0x14));
	//�ж���32λ����64λPE�ļ�
	if (pPEHeader->COFFHeader.Size_Of_Optional_Headers == 0xF0) { ISX64 = TRUE; }
	//����[��ѡPEͷ]
	pPEHeader->OptionalHeader.Magic = *((WORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x0));
	pPEHeader->OptionalHeader.Address_Of_Entry_Point = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x10));
	pPEHeader->OptionalHeader.Section_Alignment = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x20));
	pPEHeader->OptionalHeader.File_Alignment = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x24));
	pPEHeader->OptionalHeader.Size_Of_Image = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x38));
	pPEHeader->OptionalHeader.Size_Of_Headers = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x3C));

	//����64λ��32λPE�в���Ľṹ
	if (ISX64)
	{
		//[ImageBase]
		pPEHeader->OptionalHeader.Image_Base = *((DWORD64*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x18));
		//[��ѡPEͷ֮����Ŀ¼]
		pPEHeader->OptionalHeader.Export_Directory_Offset = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x70));
		pPEHeader->OptionalHeader.Import_Directory_Offset = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x78));
		pPEHeader->OptionalHeader.Relocation_Directory_Offset = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x98));
		pPEHeader->OptionalHeader.Bound_Import_Directory_Offset = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0xC8));
	}
	else
	{
		//[ImageBase]
		pPEHeader->OptionalHeader.Image_Base = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x1C));
		//[��ѡPEͷ֮����Ŀ¼]
		pPEHeader->OptionalHeader.Export_Directory_Offset = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x60));
		pPEHeader->OptionalHeader.Import_Directory_Offset = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x68));
		pPEHeader->OptionalHeader.Relocation_Directory_Offset = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x88));
		pPEHeader->OptionalHeader.Bound_Import_Directory_Offset = *((DWORD*)(pFileBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0xB8));
	}

	//����"������"�������ڴ�
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

	//-----------------����PEBody---------
	//�жϵ���Ŀ¼�Ƿ����
	if (pPEHeader->OptionalHeader.Export_Directory_Offset != 0x0)
	{
		//����������Ŀ¼��
		DWORD exportDirectory_FOA = Trans_RVAtoFOA(pPEHeader->OptionalHeader.Export_Directory_Offset, *pPEHeader);
		pPEBody->ExportDirectory.Ordinal_Base = *(DWORD*)(pFileBuffer + exportDirectory_FOA + 0x4 * 0x4);
		pPEBody->ExportDirectory.Number_Of_Functions = *(DWORD*)(pFileBuffer + exportDirectory_FOA + 0x5 * 0x4);
		pPEBody->ExportDirectory.Number_Of_Names = *(DWORD*)(pFileBuffer + exportDirectory_FOA + 0x6 * 0x4);
		pPEBody->ExportDirectory.Address_Of_Functions = *(DWORD*)(pFileBuffer + exportDirectory_FOA + 0x7 * 0x4);
		pPEBody->ExportDirectory.Address_Of_Names = *(DWORD*)(pFileBuffer + exportDirectory_FOA + 0x8 * 0x4);
		pPEBody->ExportDirectory.Address_Of_NameOrdinals = *(DWORD*)(pFileBuffer + exportDirectory_FOA + 0x9 * 0x4);

		//�����ɡ�����Ŀ¼��ӳ��ġ��������Ʊ�������������ű�
		pPEBody->Functions_Address = (DWORD *)malloc(sizeof(DWORD)*pPEBody->ExportDirectory.Number_Of_Functions);
		pPEBody->Functions_Names = (DWORD *)malloc(sizeof(DWORD)*pPEBody->ExportDirectory.Number_Of_Names);
		pPEBody->Functions_NameOrdinals = (WORD*)malloc(sizeof(DWORD)*pPEBody->ExportDirectory.Number_Of_Names);
		for (DWORD i = 0; i < pPEBody->ExportDirectory.Number_Of_Names; i++)
		{
			pPEBody->Functions_Names[i] = *(DWORD*)(pFileBuffer + Trans_RVAtoFOA(pPEBody->ExportDirectory.Address_Of_Names, *pPEHeader) + 0x4 * i);
			pPEBody->Functions_NameOrdinals[i] = *(WORD*)(pFileBuffer + Trans_RVAtoFOA(pPEBody->ExportDirectory.Address_Of_NameOrdinals, *pPEHeader) + 0x2 * i);
		}
		//�����ɡ�����Ŀ¼��ӳ��ġ�������ַ��
		for (DWORD i = 0; i < pPEBody->ExportDirectory.Number_Of_Functions; i++)
		{
			pPEBody->Functions_Address[i] = *(DWORD*)(pFileBuffer + Trans_RVAtoFOA(pPEBody->ExportDirectory.Address_Of_Functions, *pPEHeader) + 0x4 * i);
		}
	}
	//�������ض�λĿ¼��
	//���ж��ض�λĿ¼�Ƿ����
	if (pPEHeader->OptionalHeader.Relocation_Directory_Offset != 0x0)
	{
		DWORD BlockStart_FOA = Trans_RVAtoFOA(pPEHeader->OptionalHeader.Relocation_Directory_Offset, *pPEHeader);
		//�����ض�λ��Ŀ���������ѿռ�
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

	//����������Ŀ¼��
	//���жϵ���Ŀ¼�Ƿ����
	if (pPEHeader->OptionalHeader.Import_Directory_Offset != 0x0)
	{
		//���㵼��Ŀ¼�ĸ���
		DWORD FirstImportDir_FOA = Trans_RVAtoFOA(pPEHeader->OptionalHeader.Import_Directory_Offset, *pPEHeader);
		DWORD DirSize = sizeof(IMPORT_DIRECTORY);//��������Ŀ¼Size
		while (true)
		{
			IMPORT_DIRECTORY temp = *(IMPORT_DIRECTORY*)(pFileBuffer + FirstImportDir_FOA + pPEBody->pri_sum_importDirectory * DirSize);
			if (temp.FirstThunk == 0x0 && temp.ForwarderChain == 0x0 && temp.Name == 0x0 && temp.OriginalFirstThunk == 0x0 && temp.TimeDateStamp == 0x0)//�жϽṹ��ȫΪ0x0
			{
				break;
			}
			pPEBody->pri_sum_importDirectory++;
		}

		//���ݵ���Ŀ¼����������ѿռ�
		pPEBody->ImportDirectory = (IMPORT_DIRECTORY*)malloc(sizeof(IMPORT_DIRECTORY)*pPEBody->pri_sum_importDirectory);
		pPEBody->INT_Table = (INT_TABLE*)malloc(sizeof(INT_TABLE)* pPEBody->pri_sum_importDirectory);
		pPEBody->IAT_Table = (IAT_TABLE*)malloc(sizeof(IAT_TABLE)* pPEBody->pri_sum_importDirectory);
		memset(pPEBody->INT_Table, 0x0, sizeof(INT_TABLE)* pPEBody->pri_sum_importDirectory);
		memset(pPEBody->IAT_Table, 0x0, sizeof(IAT_TABLE)* pPEBody->pri_sum_importDirectory);
		memset(pPEBody->ImportDirectory, 0x0, sizeof(IMPORT_DIRECTORY)*pPEBody->pri_sum_importDirectory);

		//�������
		for (DWORD i = 0; i < pPEBody->pri_sum_importDirectory; i++)
		{
			//��������Ŀ¼
			pPEBody->ImportDirectory[i].OriginalFirstThunk = *(DWORD*)(pFileBuffer + FirstImportDir_FOA + i * DirSize + 0x0 * 0x4);
			pPEBody->ImportDirectory[i].TimeDateStamp = *(DWORD*)(pFileBuffer + FirstImportDir_FOA + i * DirSize + 0x1 * 0x4);
			pPEBody->ImportDirectory[i].ForwarderChain = *(DWORD*)(pFileBuffer + FirstImportDir_FOA + i * DirSize + 0x2 * 0x4);
			pPEBody->ImportDirectory[i].Name = *(DWORD*)(pFileBuffer + FirstImportDir_FOA + i * DirSize + 0x3 * 0x4);
			pPEBody->ImportDirectory[i].FirstThunk = *(DWORD*)(pFileBuffer + FirstImportDir_FOA + i * DirSize + 0x4 * 0x4);

			//����INT��������
			if (pPEBody->ImportDirectory[i].OriginalFirstThunk == 0)
			{//���OriginalFirstThunk=0���ʾINT��Ϊ�գ�����δ����ǰ��IAT����ΪINT�� (��Ϊδ����ǰ��IAT��INT��ͬ)
				printf("ע�⣺��fileBuffer��INT����Ϊ�գ��ʽ�δ����ǰ��IAT����ΪINT��... \n");
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
			//����IAT��������
			DWORD FirstThunk_FOA = Trans_RVAtoFOA(pPEBody->ImportDirectory[i].FirstThunk, *pPEHeader);
			while (true)
			{
				if (*(DWORD*)(pFileBuffer + FirstThunk_FOA + pPEBody->IAT_Table[i].pri_sum_item * 0x4) == 0x0)
				{
					break;
				}
				pPEBody->IAT_Table[i].pri_sum_item++;
			}

			//����INT����������������ڴ�
			pPEBody->INT_Table[i].IMAGE_THUNK_DATA = (DWORD *)malloc(pPEBody->INT_Table[i].pri_sum_item * 0x4);

			//����IAT����������������ڴ�
			pPEBody->IAT_Table[i].funcAddress = (DWORD *)malloc(pPEBody->IAT_Table[i].pri_sum_item * 0x4);

			//ΪINT���ÿ���ֵ
			for (DWORD j = 0; j < pPEBody->INT_Table[i].pri_sum_item; j++)
			{
				pPEBody->INT_Table[i].IMAGE_THUNK_DATA[j] = *(DWORD *)(pFileBuffer + OriginalFirstThunk_FOA + j * 0x4);
			}

			//ΪIAT���ÿ���ֵ
			for (DWORD j = 0; j < pPEBody->IAT_Table[i].pri_sum_item; j++)
			{
				pPEBody->IAT_Table[i].funcAddress[j] = *(DWORD *)(pFileBuffer + FirstThunk_FOA + j * 0x4);
			}

		}
	}

	//�������󶨵���Ŀ¼����ʹ�ö�̬�����˼·�����ڴ�(ѭ��������ͷ�)
	//���жϴ���
	if (pPEHeader->OptionalHeader.Bound_Import_Directory_Offset != 0x0)
	{
		//���㡾�󶨵���Ŀ¼�����׵�ַ��FOA��ע��ʵ������Ϊ���FOA��RVA���ڽڱ��У��ʲ���Ҫת��
		DWORD Dir_FOA = Trans_RVAtoFOA(pPEHeader->OptionalHeader.Bound_Import_Directory_Offset, *pPEHeader);
		//��ǰ�α�
		DWORD cursor_FOA = Dir_FOA;

		while (true)
		{
			//�ж�һ��ȫ0��8�ֽڽṹ����Ϊ������ʶ
			BoundImportDirectory temp = *(BoundImportDirectory*)(pFileBuffer + cursor_FOA);
			if (temp.NumberOfModuleForwarderRefs == 0x0 && temp.OffsetModuleName == 0x0 && temp.TimeDateStamp == 0x0)
			{
				break;
			}

			//���󶨵���Ŀ¼���ĸ���+1
			pPEBody->pri_sum_boundImportDirectory++;

			//������һ��ѭ��������Ķ��ڴ�ָ��
			BoundImportDirectory* lastPoint = pPEBody->BoundImportDirectory;

			//���뵱ǰѭ���ġ��󶨵���Ŀ¼���Ķ��ڴ�
			pPEBody->BoundImportDirectory = (BoundImportDirectory*)malloc(sizeof(BoundImportDirectory)*pPEBody->pri_sum_boundImportDirectory);
			memset(pPEBody->BoundImportDirectory, 0x0, sizeof(BoundImportDirectory)*pPEBody->pri_sum_boundImportDirectory);

			//���䵱ǰѭ���ġ��󶨵���Ŀ¼���Ĳ���
			pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].TimeDateStamp = *(DWORD*)(pFileBuffer + cursor_FOA);
			pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].OffsetModuleName = *(unsigned short*)(pFileBuffer + cursor_FOA + 0x4);
			pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].NumberOfModuleForwarderRefs = *(unsigned short*)(pFileBuffer + cursor_FOA + 0x4 + 0x2);

			//��ǰѭ���ġ��󶨵���Ŀ¼����BoundForwarderRef�ṹ�Ĳ���
			pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].BoundForwarderRef = (BoundForwarderRef*)malloc(sizeof(BoundForwarderRef)*pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].NumberOfModuleForwarderRefs);
			memset(pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].BoundForwarderRef, 0x0, sizeof(BoundForwarderRef)*pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].NumberOfModuleForwarderRefs);
			for (DWORD i = 0; i < pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].NumberOfModuleForwarderRefs; i++)
			{
				pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].BoundForwarderRef[i].TimeDateStamp = *(DWORD*)(pFileBuffer + cursor_FOA + 0x8 + i * 0x8);
				pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].BoundForwarderRef[i].OffsetModuleName = *(DWORD*)(pFileBuffer + cursor_FOA + 0x8 + i * 0x8 + 0x4);
				pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].BoundForwarderRef[i].Reserved = *(DWORD*)(pFileBuffer + cursor_FOA + 0x8 + i * 0x8 + 0x4 + 0x2);
			}

			//�ӵ�2��ѭ����ʼ
			if (pPEBody->pri_sum_boundImportDirectory >= 2)
			{
				//����һ��ѭ������Ķ��ڴ� ���Ƶ� �µĶ��ڴ�
				memcpy(pPEBody->BoundImportDirectory, lastPoint, sizeof(BoundImportDirectory)*(pPEBody->pri_sum_boundImportDirectory - 1));

				//����һ��ѭ������Ķ��ڴ��ͷ�
				free(lastPoint);
			}
			//�α�������һ���󶨵���Ŀ¼
			cursor_FOA += (pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].NumberOfModuleForwarderRefs * 0x8 + 0x8);

		}
	}
}

/**
 * װ��ImageBuffer����fileBuffer������ImageBuffer
 * ���� filePath
 * ���� ppFileBuffer
 * ���� fileLen ��ȡ���ļ�����
 */
VOID LoadImageBuffer(PBYTE pFileBuffer, OUT PBYTE* ppImageBuffer, PEHEADER PEHeader)
{
	//����imageBuffer
	*ppImageBuffer = (PBYTE)malloc(PEHeader.OptionalHeader.Size_Of_Image);
	memset(*ppImageBuffer, 0x0, PEHeader.OptionalHeader.Size_Of_Image);

	//����[SizeOfHeaders]��FileBuffer�ڵ�"ͷ��Ϣ"ԭ�ⲻ���ؿ�����imageBuffer
	for (DWORD i = 0; i < PEHeader.OptionalHeader.Size_Of_Headers; i++)
	{
		*(*ppImageBuffer + i) = *(pFileBuffer + i);
	}
	//��"����Ϣ"������imageBuffer
	for (DWORD i = 0; i < PEHeader.COFFHeader.Number_Of_Section; i++)
	{
		for (DWORD j = 0; j < PEHeader.SectionHeader.Size_Of_Raw_Data[i]; j++)
		{
			*(*ppImageBuffer + PEHeader.SectionHeader.Virtual_Address[i] + j) = *(pFileBuffer + PEHeader.SectionHeader.Pointer_To_Raw_Data[i] + j);
		}
	}
}

/**
 * ��ImageBuffer��ԭ��FileBuffer
 * ���� pImageBuffer
 * ���� PEHeader
 * ���� fileLen
 * ���� [OUT] ppFileBuffer
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
 * ��FileBufferд���ļ�
 * ���� destFilePath
 * ���� destfileLen
 * ���� pFileBuffer
 */
VOID SaveFile(const CHAR* destFilePath, int destfileLen, PBYTE pFileBuffer)
{
	printf("\n��ʼд���ļ�...\n");
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
		printf("���󣺴��ļ�ʧ��,code=%d \n", errorCode);
		return;
	}
	fclose(pNewFile);
	printf("д���ļ����... \n");
}


/**
 * ����PE�ļ���ͨ��FileBuffer����
 * ���� pImageBuffer
 * ���� [OUT] pPEHeader
 * ���� [OUT] pPEBody
 */
VOID AnalyzePE_ByImageBuffer(PBYTE pImageBuffer, OUT PEHEADER* pPEHeader, OUT PEBODY* pPEBody)
{
	//�ȳ�ʼ��Ϊ0
	memset(pPEHeader, 0x0, sizeof(PEHEADER));
	memset(pPEBody, 0x0, sizeof(PEBODY));

	//����PEHeader(��FileBuffer�ķ�����ͬ)
	//��ʼ��
	BOOL ISX64 = FALSE;
	memset(pPEHeader, 0x0, sizeof(PEHEADER));
	memset(pPEBody, 0x0, sizeof(PEBODY));

	//-----------------����PEHeader---------
	//����[DOSͷ]
	pPEHeader->DOSHeader.MZ = *((WORD*)pImageBuffer);
	pPEHeader->DOSHeader.Offset_To_PE_Signature = *((DWORD*)(pImageBuffer + 0x3C));
	//����[��׼PEͷ]
	pPEHeader->COFFHeader.PE_Signature = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + 0x0));
	pPEHeader->COFFHeader.Number_Of_Section = *((WORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + 0x6));
	pPEHeader->COFFHeader.Size_Of_Optional_Headers = *((WORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + 0x14));
	//�ж���32λ����64λPE�ļ�
	if (pPEHeader->COFFHeader.Size_Of_Optional_Headers == 0xF0) { ISX64 = TRUE; }
	//����[��ѡPEͷ]
	pPEHeader->OptionalHeader.Magic = *((WORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x0));
	pPEHeader->OptionalHeader.Address_Of_Entry_Point = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x10));
	pPEHeader->OptionalHeader.Section_Alignment = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x20));
	pPEHeader->OptionalHeader.File_Alignment = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x24));
	pPEHeader->OptionalHeader.Size_Of_Image = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x38));
	pPEHeader->OptionalHeader.Size_Of_Headers = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x3C));

	//����64λ��32λPE�в���Ľṹ
	if (ISX64)
	{
		//[ImageBase]
		pPEHeader->OptionalHeader.Image_Base = *((DWORD64*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x18));
		//[��ѡPEͷ֮����Ŀ¼]
		pPEHeader->OptionalHeader.Export_Directory_Offset = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x70));
		pPEHeader->OptionalHeader.Import_Directory_Offset = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x78));
		pPEHeader->OptionalHeader.Relocation_Directory_Offset = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x98));
		pPEHeader->OptionalHeader.Bound_Import_Directory_Offset = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0xC8));
	}
	else
	{
		//[ImageBase]
		pPEHeader->OptionalHeader.Image_Base = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x1C));
		//[��ѡPEͷ֮����Ŀ¼]
		pPEHeader->OptionalHeader.Export_Directory_Offset = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x60));
		pPEHeader->OptionalHeader.Import_Directory_Offset = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x68));
		pPEHeader->OptionalHeader.Relocation_Directory_Offset = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x88));
		pPEHeader->OptionalHeader.Bound_Import_Directory_Offset = *((DWORD*)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0xB8));
	}

	//����"������"�������ڴ�
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
	//-------����PEBody---------
	//����������Ŀ¼��
	if (pPEHeader->OptionalHeader.Export_Directory_Offset != 0x0)
	{//�жϡ�����Ŀ¼���Ƿ����
		DWORD RVA = pPEHeader->OptionalHeader.Export_Directory_Offset;
		pPEBody->ExportDirectory.Ordinal_Base = *(DWORD*)(pImageBuffer + RVA + 0x4 * 0x4);
		pPEBody->ExportDirectory.Number_Of_Functions = *(DWORD*)(pImageBuffer + RVA + 0x5 * 0x4);
		pPEBody->ExportDirectory.Number_Of_Names = *(DWORD*)(pImageBuffer + RVA + 0x6 * 0x4);
		pPEBody->ExportDirectory.Address_Of_Functions = *(DWORD*)(pImageBuffer + RVA + 0x7 * 0x4);
		pPEBody->ExportDirectory.Address_Of_Names = *(DWORD*)(pImageBuffer + RVA + 0x8 * 0x4);
		pPEBody->ExportDirectory.Address_Of_NameOrdinals = *(DWORD*)(pImageBuffer + RVA + 0x9 * 0x4);

		//�����ɡ�����Ŀ¼��ӳ��ġ��������Ʊ�������������ű�
		pPEBody->Functions_Address = (DWORD *)malloc(sizeof(DWORD)*pPEBody->ExportDirectory.Number_Of_Functions);
		pPEBody->Functions_Names = (DWORD *)malloc(sizeof(DWORD)*pPEBody->ExportDirectory.Number_Of_Names);
		pPEBody->Functions_NameOrdinals = (unsigned short *)malloc(sizeof(DWORD)*pPEBody->ExportDirectory.Number_Of_Names);
		for (DWORD i = 0; i < pPEBody->ExportDirectory.Number_Of_Names; i++)
		{
			pPEBody->Functions_Names[i] = *(DWORD*)(pImageBuffer + pPEBody->ExportDirectory.Address_Of_Names + 0x4 * i);
			pPEBody->Functions_NameOrdinals[i] = *(unsigned short*)(pImageBuffer + pPEBody->ExportDirectory.Address_Of_NameOrdinals + 0x2 * i);
		}
		//�����ɡ�����Ŀ¼��ӳ��ġ�������ַ��
		for (DWORD i = 0; i < pPEBody->ExportDirectory.Number_Of_Functions; i++)
		{
			pPEBody->Functions_Address[i] = *(DWORD*)(pImageBuffer + pPEBody->ExportDirectory.Address_Of_Functions + 0x4 * i);
		}
	}
	//�������ض�λĿ¼��
	if (pPEHeader->OptionalHeader.Relocation_Directory_Offset != 0x0)
	{//���ж��ض�λĿ¼�Ƿ����

		DWORD RVA = pPEHeader->OptionalHeader.Relocation_Directory_Offset;
		//�����ض�λ��Ŀ���������ѿռ�
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

	//����������Ŀ¼��
	if (pPEHeader->OptionalHeader.Import_Directory_Offset != 0x0)
	{//���жϵ���Ŀ¼�Ƿ����

		//���㵼��Ŀ¼�ĸ���
		DWORD RVA = pPEHeader->OptionalHeader.Import_Directory_Offset;
		DWORD DirSize = sizeof(IMPORT_DIRECTORY);//��������Ŀ¼Size
		while (true)
		{
			IMPORT_DIRECTORY temp = *(IMPORT_DIRECTORY*)(pImageBuffer + RVA + pPEBody->pri_sum_importDirectory * DirSize);
			if (temp.FirstThunk == 0x0 && temp.ForwarderChain == 0x0 && temp.Name == 0x0 && temp.OriginalFirstThunk == 0x0 && temp.TimeDateStamp == 0x0)//�жϽṹ��ȫΪ0x0
			{
				break;
			}
			pPEBody->pri_sum_importDirectory++;
		}

		//���ݵ���Ŀ¼����������ѿռ�
		pPEBody->ImportDirectory = (IMPORT_DIRECTORY*)malloc(sizeof(IMPORT_DIRECTORY)*pPEBody->pri_sum_importDirectory);
		pPEBody->INT_Table = (INT_TABLE*)malloc(sizeof(INT_TABLE)* pPEBody->pri_sum_importDirectory);
		pPEBody->IAT_Table = (IAT_TABLE*)malloc(sizeof(IAT_TABLE)* pPEBody->pri_sum_importDirectory);
		memset(pPEBody->INT_Table, 0x0, sizeof(INT_TABLE)* pPEBody->pri_sum_importDirectory);
		memset(pPEBody->IAT_Table, 0x0, sizeof(IAT_TABLE)* pPEBody->pri_sum_importDirectory);
		memset(pPEBody->ImportDirectory, 0x0, sizeof(IMPORT_DIRECTORY)*pPEBody->pri_sum_importDirectory);

		//�������
		for (DWORD i = 0; i < pPEBody->pri_sum_importDirectory; i++)
		{
			//��������Ŀ¼
			pPEBody->ImportDirectory[i].OriginalFirstThunk = *(DWORD*)(pImageBuffer + RVA + i * DirSize + 0x0 * 0x4);
			pPEBody->ImportDirectory[i].TimeDateStamp = *(DWORD*)(pImageBuffer + RVA + i * DirSize + 0x1 * 0x4);
			pPEBody->ImportDirectory[i].ForwarderChain = *(DWORD*)(pImageBuffer + RVA + i * DirSize + 0x2 * 0x4);
			pPEBody->ImportDirectory[i].Name = *(DWORD*)(pImageBuffer + RVA + i * DirSize + 0x3 * 0x4);
			pPEBody->ImportDirectory[i].FirstThunk = *(DWORD*)(pImageBuffer + RVA + i * DirSize + 0x4 * 0x4);

			//����INT��������
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
				printf("����imageBuffer�е�INT��Ϊ�գ�����������������ȡ���뺯��������... \n");
				pPEBody->INT_Table[i].pri_sum_item = 0;
			}
			//����IAT��������
			DWORD RVA_FirstThunk = pPEBody->ImportDirectory[i].FirstThunk;
			while (true)
			{
				if (*(DWORD*)(pImageBuffer + RVA_FirstThunk + pPEBody->IAT_Table[i].pri_sum_item * 0x4) == 0x0)
				{
					break;
				}
				pPEBody->IAT_Table[i].pri_sum_item++;
			}
			//����INT����������������ڴ�
			pPEBody->INT_Table[i].IMAGE_THUNK_DATA = (DWORD *)malloc(pPEBody->INT_Table[i].pri_sum_item * 0x4);

			//����IAT����������������ڴ�
			pPEBody->IAT_Table[i].funcAddress = (DWORD *)malloc(pPEBody->IAT_Table[i].pri_sum_item * 0x4);

			//ΪINT���ÿ���ֵ
			for (DWORD j = 0; j < pPEBody->INT_Table[i].pri_sum_item; j++)
			{
				pPEBody->INT_Table[i].IMAGE_THUNK_DATA[j] = *(DWORD *)(pImageBuffer + RVA_OriginalFirstThunk + j * 0x4);
			}
			//ΪIAT���ÿ���ֵ
			for (DWORD j = 0; j < pPEBody->IAT_Table[i].pri_sum_item; j++)
			{
				pPEBody->IAT_Table[i].funcAddress[j] = *(DWORD *)(pImageBuffer + RVA_FirstThunk + j * 0x4);
			}
		}
	}

	//�������󶨵���Ŀ¼����ʹ�ö�̬�����˼·�����ڴ�(ѭ��������ͷ�)
	//���жϴ���
	if (pPEHeader->OptionalHeader.Bound_Import_Directory_Offset != 0x0)
	{
		//���㡾�󶨵���Ŀ¼�����׵�ַ��FOA��ע��ʵ������Ϊ���FOA��RVA���ڽڱ��У��ʲ���Ҫת��
		DWORD RVA_Dir = pPEHeader->OptionalHeader.Bound_Import_Directory_Offset;
		//��ǰ�α�
		DWORD RVA_cursor = RVA_Dir;

		while (true)
		{
			//�ж�һ��ȫ0��8�ֽڽṹ����Ϊ������ʶ
			BoundImportDirectory temp = *(BoundImportDirectory*)(pImageBuffer + RVA_cursor);
			if (temp.NumberOfModuleForwarderRefs == 0x0 && temp.OffsetModuleName == 0x0 && temp.TimeDateStamp == 0x0)
			{
				break;
			}

			//���󶨵���Ŀ¼���ĸ���+1
			pPEBody->pri_sum_boundImportDirectory++;

			//������һ��ѭ��������Ķ��ڴ�ָ��
			BoundImportDirectory* lastPoint = pPEBody->BoundImportDirectory;

			//���뵱ǰѭ���ġ��󶨵���Ŀ¼���Ķ��ڴ�
			pPEBody->BoundImportDirectory = (BoundImportDirectory*)malloc(sizeof(BoundImportDirectory)*pPEBody->pri_sum_boundImportDirectory);
			memset(pPEBody->BoundImportDirectory, 0x0, sizeof(BoundImportDirectory)*pPEBody->pri_sum_boundImportDirectory);

			//���䵱ǰѭ���ġ��󶨵���Ŀ¼���Ĳ���
			pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].TimeDateStamp = *(DWORD*)(pImageBuffer + RVA_cursor);
			pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].OffsetModuleName = *(unsigned short*)(pImageBuffer + RVA_cursor + 0x4);
			pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].NumberOfModuleForwarderRefs = *(unsigned short*)(pImageBuffer + RVA_cursor + 0x4 + 0x2);

			//��ǰѭ���ġ��󶨵���Ŀ¼����BoundForwarderRef�ṹ�Ĳ���
			pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].BoundForwarderRef = (BoundForwarderRef*)malloc(sizeof(BoundForwarderRef)*pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].NumberOfModuleForwarderRefs);
			memset(pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].BoundForwarderRef, 0x0, sizeof(BoundForwarderRef)*pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].NumberOfModuleForwarderRefs);
			for (DWORD i = 0; i < pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].NumberOfModuleForwarderRefs; i++)
			{
				pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].BoundForwarderRef[i].TimeDateStamp = *(DWORD*)(pImageBuffer + RVA_cursor + 0x8 + i * 0x8);
				pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].BoundForwarderRef[i].OffsetModuleName = *(DWORD*)(pImageBuffer + RVA_cursor + 0x8 + i * 0x8 + 0x4);
				pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].BoundForwarderRef[i].Reserved = *(DWORD*)(pImageBuffer + RVA_cursor + 0x8 + i * 0x8 + 0x4 + 0x2);
			}

			//�ӵ�2��ѭ����ʼ
			if (pPEBody->pri_sum_boundImportDirectory >= 2)
			{
				//����һ��ѭ������Ķ��ڴ� ���Ƶ� �µĶ��ڴ�
				memcpy(pPEBody->BoundImportDirectory, lastPoint, sizeof(BoundImportDirectory)*(pPEBody->pri_sum_boundImportDirectory - 1));

				//����һ��ѭ������Ķ��ڴ��ͷ�
				free(lastPoint);
			}
			//�α�������һ���󶨵���Ŀ¼
			RVA_cursor += (pPEBody->BoundImportDirectory[pPEBody->pri_sum_boundImportDirectory - 1].NumberOfModuleForwarderRefs * 0x8 + 0x8);
		}

	}
}

/**
 * �޸��ض�λ��(ImageBuffer)
 * ���� destImageBase �»�ַ
 * ���� srcImageBase  ԭ��ַ����PE�ļ���ֱ�Ӷ�ȡ����Ϊ�����Ƕ�̬��ַ
 * ���� pImageBuffer
 * ���� pPEHeader
 * ���� pPEBody
 */
BOOL Repair_ReLocDirectory(DWORD64 newImageBase, DWORD64 oldImageBase, PBYTE pImageBuffer, PEHEADER* pPEHeader, PEBODY* pPEBody)
{
	printf("\n��ʼ�޸��ض�λ��...�»�ַ=%llX �ɻ�ַ=%llX \n", newImageBase, oldImageBase);
	//0.�»�ַ�Ϸ��Լ��
	if (newImageBase == 0)
	{
		printf("���󣺴�����»�ַ=0 \n");
		return FALSE;
	}
	if (pPEHeader->COFFHeader.Size_Of_Optional_Headers == 0xE0 && newImageBase >= 0x100000000)
	{
		printf("����ԭPE�ļ���32λ�ļ������»�ַ����32λ... \n");
		return FALSE;
	}

	//1.�ж��Ƿ�����ض�λ��
	if (pPEHeader->OptionalHeader.Relocation_Directory_Offset == 0x0)
	{
		printf("����ԭPE�������ض�λ��(exe�ļ���Ҫ�����release�汾�����ض�λ��... \n");
		return FALSE;
	}

	//2.�޸�ImageBuffer��������PEHeader�ṹ���е�ImageBase
	if (pPEHeader->COFFHeader.Size_Of_Optional_Headers == 0xF0)
	{//64λPE
		pPEHeader->OptionalHeader.Image_Base = newImageBase;
		*(DWORD64 *)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x18) = newImageBase;
	}
	else
	{//32λPE
		pPEHeader->OptionalHeader.Image_Base = newImageBase;
		*(DWORD *)(pImageBuffer + pPEHeader->DOSHeader.Offset_To_PE_Signature + len_COFFHEADER + 0x1C) = newImageBase;
	}

	//3. �����ض�λĿ¼����ImageBuffer�д洢�ĸ���ֵַ
	for (int i = 0; i < pPEBody->ReloactionDirectory.pri_sum_block; i++)
	{
		DWORD numberOfItem = (pPEBody->ReloactionDirectory.Block[i].Size_Of_Block - 0x8) / 0x2;
		for (int j = 0; j < numberOfItem; j++)
		{
			if (pPEBody->ReloactionDirectory.Block[i].Item[j].Type == 0x3)
			{
				//������Ҫ�ض�λ�����ݵĵ�ַ
				DWORD goal_RVA = pPEBody->ReloactionDirectory.Block[i].Virtual_Address + pPEBody->ReloactionDirectory.Block[i].Item[j].Offset;
				//��Ϊʮ�����Ƶļ�����λ������⣬�����ô��ַ��ȥС��ַ��ȷ����ֵ�����ģ��������ǳ���Ҫ����
				if (newImageBase >= pPEHeader->OptionalHeader.Image_Base)
				{
					//��ΪҪ������������"��ֵַ"��32λʱռ4�ֽڣ�64λʱռ8�ֽ�
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
	printf("�޸��ض�λ�����...  \n");
	return TRUE;
}
