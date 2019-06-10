#pragma once
#include "pch.h"

#define len_COFFHEADER 0x18
#define len_SECTIONHEADER 0x28

struct DOS_HEADER
{
	WORD MZ;						//偏移0x0
	DWORD Offset_To_PE_Signature;	//偏移0x3C 到"PE签名"的FOA
};
struct COFF_HEADER
{
	//共0x18字节 (包括"PE签名")
	DWORD PE_Signature;			   //偏移0x0  PE签名
	WORD Number_Of_Section;		   //偏移0x6 
	WORD Size_Of_Optional_Headers; //偏移0x14 值=0xE0表示32位文件；值=0xF0表示64位文件
};
struct OPTIONAL_HEADER
{
	//第一部分占0x70字节(64位PE)或0x60字节(32位PE)
	WORD Magic; 					//偏移0x0  表示镜像文件的状态：0x10B表明是32位镜像文件;0x20B表明是64位镜像文件;0x107表明是ROM镜像
	DWORD Address_Of_Entry_Point;	//偏移0x10
	DWORD64 Image_Base;				//偏移0x18(64位PE) 偏移0x1C(32位PE)
	DWORD Section_Alignment;		//偏移0x20 内存对齐值
	DWORD File_Alignment;			//偏移0x24 文件对齐值
	DWORD Size_Of_Image;			//偏移0x38
	DWORD Size_Of_Headers;			//偏移0x3C

	//第二部分占0x80字节
	DWORD Export_Directory_Offset;			//偏移0x70(64位PE) 偏移0x60(32位PE) 导出目录的RVA
	DWORD Import_Directory_Offset;			//偏移0x78(64位PE) 偏移0x68(32位PE)  导入目录的RVA
	DWORD Relocation_Directory_Offset;		//偏移0x98(64位PE) 偏移0x88(32位PE)  重定位目录RVA
	DWORD Bound_Import_Directory_Offset;	//偏移0xC8(64位PE) 偏移0xB8(32位PE)  绑定导入目录的RVA
};
//struct OPTIONAL_HEADER_X86
//{
//	//第一部分占0x60字节(32位PE)
//	WORD Magic; 					//偏移0x0  这个无符号整数指出了镜像文件的状态。0x10B表明这是一个32位镜像文件;0x20B表明这是一个64位镜像文件;0x107表明这是一个ROM镜像
//	DWORD Address_Of_Entry_Point;	//偏移0x10
//	DWORD Image_Base;				//偏移0x1C
//	DWORD Section_Alignment;		//偏移0x20 内存对齐值
//	DWORD File_Alignment;			//偏移0x24 文件对齐值
//	DWORD Size_Of_Image;			//偏移0x38
//	DWORD Size_Of_Headers;			//偏移0x3C
//
//	//第二部分占0x80字节
//	DWORD Export_Directory_Offset;			//偏移0x60  导出目录的RVA
//	DWORD Import_Directory_Offset;			//偏移0x68  导入目录的RVA
//	DWORD Relocation_Directory_Offset;		//偏移0x88  重定位目录RVA
//	DWORD Bound_Import_Directory_Offset;	//偏移0xB8  绑定导入目录的RVA
//};
struct SECTION_HEADER
{
	//每个节表占0x28字节
	DWORD64* Section_Name;		//偏移0x0
	DWORD* Virtual_Size;		//偏移0x8
	DWORD* Virtual_Address;		//偏移0xC
	DWORD* Size_Of_Raw_Data;	//偏移0x10
	DWORD* Pointer_To_Raw_Data;	//偏移0x14
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

//>>>>>>>>导出表>>>>>>>>>>>>>>>>
struct EXPORT_DIRECTORY
{
	DWORD Ordinal_Base;				//偏移0x10 函数导出序号的起始序号 (函数导出序号=函数序号+起始序号，函数序号由0开始)
	DWORD Number_Of_Functions;		//偏移0x14 导出函数的数量
	DWORD Number_Of_Names;			//偏移0x18 导出名称表或导出名称序号表的元素数目
	DWORD Address_Of_Functions;		//偏移0x1C 导出地址表的RVA
	DWORD Address_Of_Names;			//偏移0x20 导出名称表的RVA
	DWORD Address_Of_NameOrdinals;	//偏移0x24 导出序号表的RVA
};
//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

//>>>>>>>>>>>>>>>重定位表>>>>>>>>>>>>>>>
//单个重定位块中的单个重定位项
struct RELOCATION_ITEM
{
	BYTE Type;		//用char存储高4位，浪费4位
	DWORD Offset;	//用uint存储低12位，浪费4位
};
//单个重定位块
struct RELOCATION_BLOCK
{
	DWORD Virtual_Address;			//当前页起始地址的RVA
	DWORD Size_Of_Block;			//当前重定位块的大小
	RELOCATION_ITEM* Item;			//若干个重定位项
};
struct RELOCATION_DIRECTORY
{
	RELOCATION_BLOCK* Block;	//若干个重定位块
	int pri_sum_block;			//私有：重定位块总数
};
//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

//>>>>>>>>>>>>>>>>导入表>>>>>>>>>>>>>>>>>>>>>
//单个导入目录
struct IMPORT_DIRECTORY
{
	DWORD OriginalFirstThunk;	//存放RVA值，指向对应INT表的首项
	DWORD TimeDateStamp;		//时间戳：标识当前导入表是否已被绑定
	DWORD ForwarderChain;		//暂时未知
	DWORD Name;					//存放RVA值，指向对应DLL的名称字符串，字符串以0x0结束
	DWORD FirstThunk;			//存放RVA值，指向对应IAT表的首项

};
//一个导出目录映射的INT表
struct INT_TABLE
{
	//若值的最高二进制位=1，则其余位存放"函数名称序号"
	//若值的最高二进制位=0，则存放RVA值，指向一个_IMAGE_IMPORT_BY_NAME结构(系统类库已定义此结构)
	DWORD* IMAGE_THUNK_DATA;
	int pri_sum_item;			//私有：标识当前INT表中有几个项
};

//一个导出目录映射的IAT表
struct IAT_TABLE
{
	DWORD* funcAddress;			//函数地址
	int pri_sum_item;			//私有：标识当前IAT表中有几个项
};
//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

//>>>>>>>>>>>>>>>>绑定导入目录>>>>>>>>>>>>>>>>>>>>>
//一个外部依赖DLL的结构（一个绑定导入目录中可能有多个）
struct BoundForwarderRef
{
	DWORD TimeDateStamp;	//时间戳
	WORD Reserved;			//保留字段
	WORD OffsetModuleName;
};
//一个绑定导入目录
struct BoundImportDirectory
{
	DWORD TimeDateStamp;	//时间戳
	WORD OffsetModuleName;
	WORD NumberOfModuleForwarderRefs;
	BoundForwarderRef* BoundForwarderRef;
};
//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

struct PEBODY
{
	EXPORT_DIRECTORY ExportDirectory;			//导出目录
	DWORD* Functions_Address;					//导出目录映射的函数地址表中的各函数地址
	DWORD* Functions_Names;						//导出目录映射的函数名称表的各函数名称RVA值
	WORD* Functions_NameOrdinals;				//导出目录映射的函数序号表的各序号
	RELOCATION_DIRECTORY ReloactionDirectory;	//重定位目录

	IMPORT_DIRECTORY* ImportDirectory;			//若干个导入目录
	INT_TABLE* INT_Table;						//若干个导入目录映射的若干个INT表
	IAT_TABLE* IAT_Table;						//若干个导入目录映射的若干个IAT表
	BoundImportDirectory* BoundImportDirectory;	//若干个绑定导入目录

	int pri_sum_importDirectory;				//私有：用于标识导入目录的个数
	int pri_sum_boundImportDirectory;			//私有：用于标识绑定导入目录的个数
};


