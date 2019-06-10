#pragma once
#include "stdafx.h"

struct DOSHEADER_X64
{
	WORD MZ;						//偏移0x0
	DWORD Offset_To_PE_Signature;	//偏移0x3C 到"PE签名"的FOA
};
struct COFFHEADER_X64
{
	//共0x18字节 (包括"PE签名")
	WORD Number_Of_Section;		   //偏移0x2
	WORD Size_Of_Optional_Headers; //偏移0x10 对于32位文件来说，它应是224；对于64位文件来说，它应是240
};
struct OPTIONALHEADER_X64
{
	//第一部分占0x70字节
	WORD Magic; 					//偏移0x0  这个无符号整数指出了镜像文件的状态。0x10B表明这是一个32位镜像文件;0x20B表明这是一个64位镜像文件;0x107表明这是一个ROM镜像
	DWORD Address_Of_Entry_Point;	//偏移0x10
	DWORD64 Image_Base;				//偏移0x18
	DWORD Section_Alignment;		//偏移0x20 内存对齐值
	DWORD File_Alignment;			//偏移0x24 文件对齐值
	DWORD Size_Of_Image;			//偏移0x38
	DWORD Size_Of_Headers;			//偏移0x3C

	//第二部分占0x80字节
	DWORD Export_Directory_Offset;			//偏移0x70  导出目录的RVA
	DWORD Import_Directory_Offset;			//偏移0x78  导入目录的RVA
	DWORD Relocation_Directory_Offset;		//偏移0x98  重定位目录RVA
	DWORD Bound_Import_Directory_Offset;	//偏移0xC8  绑定导入目录的RVA
};
struct SectionHeader_X64
{
	//每个节表占0x28字节
	DWORD64* Section_Name;		//偏移0x0
	DWORD* Virtual_Size;		//偏移0x8
	DWORD* Virtual_Address;		//偏移0xC
	DWORD* Size_Of_Raw_Data;	//偏移0x10
	DWORD* Pointer_To_Raw_Data;	//偏移0x14
};
struct PEHEADER_X64
{
	DOSHEADER_X64 DOSHeader;
	COFFHEADER_X64 COFFHeader;
	OPTIONALHEADER_X64 OptionalHeader;
	SectionHeader_X64 SectionHeader;
};

