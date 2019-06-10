#pragma once
#include "pch.h"

#define len_COFFHEADER 0x18
#define len_SECTIONHEADER 0x28

struct DOS_HEADER
{
	WORD MZ;						//ƫ��0x0
	DWORD Offset_To_PE_Signature;	//ƫ��0x3C ��"PEǩ��"��FOA
};
struct COFF_HEADER
{
	//��0x18�ֽ� (����"PEǩ��")
	DWORD PE_Signature;			   //ƫ��0x0  PEǩ��
	WORD Number_Of_Section;		   //ƫ��0x6 
	WORD Size_Of_Optional_Headers; //ƫ��0x14 ֵ=0xE0��ʾ32λ�ļ���ֵ=0xF0��ʾ64λ�ļ�
};
struct OPTIONAL_HEADER
{
	//��һ����ռ0x70�ֽ�(64λPE)��0x60�ֽ�(32λPE)
	WORD Magic; 					//ƫ��0x0  ��ʾ�����ļ���״̬��0x10B������32λ�����ļ�;0x20B������64λ�����ļ�;0x107������ROM����
	DWORD Address_Of_Entry_Point;	//ƫ��0x10
	DWORD64 Image_Base;				//ƫ��0x18(64λPE) ƫ��0x1C(32λPE)
	DWORD Section_Alignment;		//ƫ��0x20 �ڴ����ֵ
	DWORD File_Alignment;			//ƫ��0x24 �ļ�����ֵ
	DWORD Size_Of_Image;			//ƫ��0x38
	DWORD Size_Of_Headers;			//ƫ��0x3C

	//�ڶ�����ռ0x80�ֽ�
	DWORD Export_Directory_Offset;			//ƫ��0x70(64λPE) ƫ��0x60(32λPE) ����Ŀ¼��RVA
	DWORD Import_Directory_Offset;			//ƫ��0x78(64λPE) ƫ��0x68(32λPE)  ����Ŀ¼��RVA
	DWORD Relocation_Directory_Offset;		//ƫ��0x98(64λPE) ƫ��0x88(32λPE)  �ض�λĿ¼RVA
	DWORD Bound_Import_Directory_Offset;	//ƫ��0xC8(64λPE) ƫ��0xB8(32λPE)  �󶨵���Ŀ¼��RVA
};
//struct OPTIONAL_HEADER_X86
//{
//	//��һ����ռ0x60�ֽ�(32λPE)
//	WORD Magic; 					//ƫ��0x0  ����޷�������ָ���˾����ļ���״̬��0x10B��������һ��32λ�����ļ�;0x20B��������һ��64λ�����ļ�;0x107��������һ��ROM����
//	DWORD Address_Of_Entry_Point;	//ƫ��0x10
//	DWORD Image_Base;				//ƫ��0x1C
//	DWORD Section_Alignment;		//ƫ��0x20 �ڴ����ֵ
//	DWORD File_Alignment;			//ƫ��0x24 �ļ�����ֵ
//	DWORD Size_Of_Image;			//ƫ��0x38
//	DWORD Size_Of_Headers;			//ƫ��0x3C
//
//	//�ڶ�����ռ0x80�ֽ�
//	DWORD Export_Directory_Offset;			//ƫ��0x60  ����Ŀ¼��RVA
//	DWORD Import_Directory_Offset;			//ƫ��0x68  ����Ŀ¼��RVA
//	DWORD Relocation_Directory_Offset;		//ƫ��0x88  �ض�λĿ¼RVA
//	DWORD Bound_Import_Directory_Offset;	//ƫ��0xB8  �󶨵���Ŀ¼��RVA
//};
struct SECTION_HEADER
{
	//ÿ���ڱ�ռ0x28�ֽ�
	DWORD64* Section_Name;		//ƫ��0x0
	DWORD* Virtual_Size;		//ƫ��0x8
	DWORD* Virtual_Address;		//ƫ��0xC
	DWORD* Size_Of_Raw_Data;	//ƫ��0x10
	DWORD* Pointer_To_Raw_Data;	//ƫ��0x14
};
struct PEHEADER
{
	DOS_HEADER DOSHeader;
	COFF_HEADER COFFHeader;
	OPTIONAL_HEADER OptionalHeader;
	SECTION_HEADER SectionHeader;
};
//struct PEHEADER_X86
//{
//	DOS_HEADER DOSHeader;
//	COFF_HEADER COFFHeader;
//	OPTIONAL_HEADER_X86 OptionalHeader;
//	SECTION_HEADER SectionHeader;
//};

//>>>>>>>>������>>>>>>>>>>>>>>>>
struct EXPORT_DIRECTORY
{
	DWORD Ordinal_Base;				//ƫ��0x10 ����������ŵ���ʼ��� (�����������=�������+��ʼ��ţ����������0��ʼ)
	DWORD Number_Of_Functions;		//ƫ��0x14 ��������������
	DWORD Number_Of_Names;			//ƫ��0x18 �������Ʊ�򵼳�������ű��Ԫ����Ŀ
	DWORD Address_Of_Functions;		//ƫ��0x1C ������ַ���RVA
	DWORD Address_Of_Names;			//ƫ��0x20 �������Ʊ��RVA
	DWORD Address_Of_NameOrdinals;	//ƫ��0x24 ������ű��RVA
};
//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

//>>>>>>>>>>>>>>>�ض�λ��>>>>>>>>>>>>>>>
//�����ض�λ���еĵ����ض�λ��
struct RELOCATION_ITEM
{
	BYTE Type;		//��char�洢��4λ���˷�4λ
	DWORD Offset;	//��uint�洢��12λ���˷�4λ
};
//�����ض�λ��
struct RELOCATION_BLOCK
{
	DWORD Virtual_Address;			//��ǰҳ��ʼ��ַ��RVA
	DWORD Size_Of_Block;			//��ǰ�ض�λ��Ĵ�С
	RELOCATION_ITEM* Item;			//���ɸ��ض�λ��
};
struct RELOCATION_DIRECTORY
{
	RELOCATION_BLOCK* Block;	//���ɸ��ض�λ��
	int pri_sum_block;			//˽�У��ض�λ������
};
//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

//>>>>>>>>>>>>>>>>�����>>>>>>>>>>>>>>>>>>>>>
//��������Ŀ¼
struct IMPORT_DIRECTORY
{
	DWORD OriginalFirstThunk;	//���RVAֵ��ָ���ӦINT�������
	DWORD TimeDateStamp;		//ʱ�������ʶ��ǰ������Ƿ��ѱ���
	DWORD ForwarderChain;		//��ʱδ֪
	DWORD Name;					//���RVAֵ��ָ���ӦDLL�������ַ������ַ�����0x0����
	DWORD FirstThunk;			//���RVAֵ��ָ���ӦIAT�������

};
//һ������Ŀ¼ӳ���INT��
struct INT_TABLE
{
	//��ֵ����߶�����λ=1��������λ���"�����������"
	//��ֵ����߶�����λ=0������RVAֵ��ָ��һ��_IMAGE_IMPORT_BY_NAME�ṹ(ϵͳ����Ѷ���˽ṹ)
	DWORD* IMAGE_THUNK_DATA;
	int pri_sum_item;			//˽�У���ʶ��ǰINT�����м�����
};

//һ������Ŀ¼ӳ���IAT��
struct IAT_TABLE
{
	DWORD* funcAddress;			//������ַ
	int pri_sum_item;			//˽�У���ʶ��ǰIAT�����м�����
};
//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

//>>>>>>>>>>>>>>>>�󶨵���Ŀ¼>>>>>>>>>>>>>>>>>>>>>
//һ���ⲿ����DLL�Ľṹ��һ���󶨵���Ŀ¼�п����ж����
struct BoundForwarderRef
{
	DWORD TimeDateStamp;	//ʱ���
	WORD Reserved;			//�����ֶ�
	WORD OffsetModuleName;
};
//һ���󶨵���Ŀ¼
struct BoundImportDirectory
{
	DWORD TimeDateStamp;	//ʱ���
	WORD OffsetModuleName;
	WORD NumberOfModuleForwarderRefs;
	BoundForwarderRef* BoundForwarderRef;
};
//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

struct PEBODY
{
	EXPORT_DIRECTORY ExportDirectory;			//����Ŀ¼
	DWORD* Functions_Address;					//����Ŀ¼ӳ��ĺ�����ַ���еĸ�������ַ
	DWORD* Functions_Names;						//����Ŀ¼ӳ��ĺ������Ʊ�ĸ���������RVAֵ
	WORD* Functions_NameOrdinals;				//����Ŀ¼ӳ��ĺ�����ű�ĸ����
	RELOCATION_DIRECTORY ReloactionDirectory;	//�ض�λĿ¼

	IMPORT_DIRECTORY* ImportDirectory;			//���ɸ�����Ŀ¼
	INT_TABLE* INT_Table;						//���ɸ�����Ŀ¼ӳ������ɸ�INT��
	IAT_TABLE* IAT_Table;						//���ɸ�����Ŀ¼ӳ������ɸ�IAT��
	BoundImportDirectory* BoundImportDirectory;	//���ɸ��󶨵���Ŀ¼

	int pri_sum_importDirectory;				//˽�У����ڱ�ʶ����Ŀ¼�ĸ���
	int pri_sum_boundImportDirectory;			//˽�У����ڱ�ʶ�󶨵���Ŀ¼�ĸ���
};


