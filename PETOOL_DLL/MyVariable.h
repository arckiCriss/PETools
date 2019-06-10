#pragma once
struct DOSHeader
{
	unsigned short MZ;
	DWORD offset_to_PE_signature;
};
struct COFFHeader
{
	unsigned short number_of_section;
	unsigned short size_of_optional_Headers;
};
struct OptionalHeader
{
	DWORD size_of_image;
	DWORD size_of_headers;
	DWORD address_of_entry_point;
	DWORD image_base;

	DWORD export_directory_offset;		//导出目录的RVA
	DWORD relocation_directory_offset;	//重定位目录RVA
	DWORD import_directory_offset;		//导入目录的RVA
	DWORD bound_import_directory_offset;	//绑定导入目录的RVA
};
struct SectionHeader
{
	unsigned long long* section_name;
	DWORD* virtual_size;
	DWORD* virtual_address;
	DWORD* size_Of_raw_data;
	DWORD* pointer_to_raw_data;
};
typedef struct PEHeader
{
	DOSHeader DOSHeader;
	COFFHeader COFFHeader;
	OptionalHeader OptionalHeader;
	SectionHeader SectionHeader;
}PEHEADER_X86;

struct ExportDirectory
{
	DWORD Address_Of_Functions;		//函数地址表
	DWORD Address_Of_Names;			//函数名称表
	DWORD Address_Of_NameOrdinals;	//函数序号表

	DWORD Number_Of_Functions;
	DWORD Number_Of_Names;
	DWORD Base;
};

struct Item
{
	BYTE Type;		//用char存储高4位，浪费4位
	DWORD Offset;	//用uint存储低12位，浪费4位
};

struct Block//重定位块	
{
	DWORD Virtual_Address;	//当前页起始地址的RVA
	DWORD Size_Of_Block;		//块的大小
	Item* Item;						//重定位项
};

struct ReloactionDirectory
{
	Block* Block;

	int NumberOfBlock;	//私有：用于标识块数
};

//单个导入目录
struct ImportDirectory
{
	DWORD OriginalFirstThunk;//存放RVA值，指向对应INT表的首项
	DWORD TimeDateStamp;		//时间戳：标识当前导入表是否已被绑定
	DWORD ForwarderChain;	//暂时未知
	DWORD Name;				//存放RVA值，指向对应DLL的名称字符串，字符串以0x0结束
	DWORD FirstThunk;		//存放RVA值，指向对应IAT表的首项

};
//一个导出目录映射的INT表
struct INT_Table
{
		//若值的最高二进制位=1，则其余位存放"函数名称序号"
		//若值的最高二进制位=0，则存放RVA值，指向一个_IMAGE_IMPORT_BY_NAME结构(系统类库已定义此结构)
		DWORD* IMAGE_THUNK_DATA;	

		int NumberOfItem;	//私有：标识当前INT表中有几个项
};

//一个导出目录映射的IAT表
struct IAT_Table
{
	DWORD* funcAddress;	 //函数地址

	int NumberOfItem;			//私有：标识当前IAT表中有几个项
};
//一个外部依赖DLL的结构（一个绑定导入目录中可能有多个）
struct BoundForwarderRef
{
	DWORD TimeDateStamp;			//时间戳
	WORD OffsetModuleName;
	WORD Reserved;			//保留字段
};
//一个绑定导入目录
struct BoundImportDirectory 
{
	DWORD TimeDateStamp;			//时间戳
	WORD OffsetModuleName;
	WORD NumberOfModuleForwarderRefs;
	BoundForwarderRef* BoundForwarderRef;			
};
typedef struct PEBody
{
	ExportDirectory ExportDirectory;			//导出目录
	DWORD* Functions_Address;			//导出目录映射的函数地址表中的各函数地址
	DWORD* Functions_Names;				//导出目录映射的函数名称表的各函数名称RVA值
	WORD* Functions_NameOrdinals;		//导出目录映射的函数序号表的各序号
	ReloactionDirectory ReloactionDirectory;	//重定位目录

	ImportDirectory* ImportDirectory;			//若干个导入目录
	INT_Table* INT_Table;						//若干个导入目录映射的若干个INT表
	IAT_Table* IAT_Table;						//若干个导入目录映射的若干个IAT表
	BoundImportDirectory* BoundImportDirectory;	//若干个绑定导入目录

	int NumberOfImportDirectory;				//私有：用于标识导入目录的个数
	int NumberOfBoundImportDirectory;			//私有：用于标识绑定导入目录的个数
}PEBODY_X86;
