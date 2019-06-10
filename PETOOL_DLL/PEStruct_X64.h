#pragma once
#include "stdafx.h"

struct DOSHEADER_X64
{
	WORD MZ;						//ƫ��0x0
	DWORD Offset_To_PE_Signature;	//ƫ��0x3C ��"PEǩ��"��FOA
};
struct COFFHEADER_X64
{
	//��0x18�ֽ� (����"PEǩ��")
	WORD Number_Of_Section;		   //ƫ��0x2
	WORD Size_Of_Optional_Headers; //ƫ��0x10 ����32λ�ļ���˵����Ӧ��224������64λ�ļ���˵����Ӧ��240
};
struct OPTIONALHEADER_X64
{
	//��һ����ռ0x70�ֽ�
	WORD Magic; 					//ƫ��0x0  ����޷�������ָ���˾����ļ���״̬��0x10B��������һ��32λ�����ļ�;0x20B��������һ��64λ�����ļ�;0x107��������һ��ROM����
	DWORD Address_Of_Entry_Point;	//ƫ��0x10
	DWORD64 Image_Base;				//ƫ��0x18
	DWORD Section_Alignment;		//ƫ��0x20 �ڴ����ֵ
	DWORD File_Alignment;			//ƫ��0x24 �ļ�����ֵ
	DWORD Size_Of_Image;			//ƫ��0x38
	DWORD Size_Of_Headers;			//ƫ��0x3C

	//�ڶ�����ռ0x80�ֽ�
	DWORD Export_Directory_Offset;			//ƫ��0x70  ����Ŀ¼��RVA
	DWORD Import_Directory_Offset;			//ƫ��0x78  ����Ŀ¼��RVA
	DWORD Relocation_Directory_Offset;		//ƫ��0x98  �ض�λĿ¼RVA
	DWORD Bound_Import_Directory_Offset;	//ƫ��0xC8  �󶨵���Ŀ¼��RVA
};
struct SectionHeader_X64
{
	//ÿ���ڱ�ռ0x28�ֽ�
	DWORD64* Section_Name;		//ƫ��0x0
	DWORD* Virtual_Size;		//ƫ��0x8
	DWORD* Virtual_Address;		//ƫ��0xC
	DWORD* Size_Of_Raw_Data;	//ƫ��0x10
	DWORD* Pointer_To_Raw_Data;	//ƫ��0x14
};
struct PEHEADER_X64
{
	DOSHEADER_X64 DOSHeader;
	COFFHEADER_X64 COFFHeader;
	OPTIONALHEADER_X64 OptionalHeader;
	SectionHeader_X64 SectionHeader;
};

