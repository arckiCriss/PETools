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

	DWORD export_directory_offset;		//����Ŀ¼��RVA
	DWORD relocation_directory_offset;	//�ض�λĿ¼RVA
	DWORD import_directory_offset;		//����Ŀ¼��RVA
	DWORD bound_import_directory_offset;	//�󶨵���Ŀ¼��RVA
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
	DWORD Address_Of_Functions;		//������ַ��
	DWORD Address_Of_Names;			//�������Ʊ�
	DWORD Address_Of_NameOrdinals;	//������ű�

	DWORD Number_Of_Functions;
	DWORD Number_Of_Names;
	DWORD Base;
};

struct Item
{
	BYTE Type;		//��char�洢��4λ���˷�4λ
	DWORD Offset;	//��uint�洢��12λ���˷�4λ
};

struct Block//�ض�λ��	
{
	DWORD Virtual_Address;	//��ǰҳ��ʼ��ַ��RVA
	DWORD Size_Of_Block;		//��Ĵ�С
	Item* Item;						//�ض�λ��
};

struct ReloactionDirectory
{
	Block* Block;

	int NumberOfBlock;	//˽�У����ڱ�ʶ����
};

//��������Ŀ¼
struct ImportDirectory
{
	DWORD OriginalFirstThunk;//���RVAֵ��ָ���ӦINT�������
	DWORD TimeDateStamp;		//ʱ�������ʶ��ǰ������Ƿ��ѱ���
	DWORD ForwarderChain;	//��ʱδ֪
	DWORD Name;				//���RVAֵ��ָ���ӦDLL�������ַ������ַ�����0x0����
	DWORD FirstThunk;		//���RVAֵ��ָ���ӦIAT�������

};
//һ������Ŀ¼ӳ���INT��
struct INT_Table
{
		//��ֵ����߶�����λ=1��������λ���"�����������"
		//��ֵ����߶�����λ=0������RVAֵ��ָ��һ��_IMAGE_IMPORT_BY_NAME�ṹ(ϵͳ����Ѷ���˽ṹ)
		DWORD* IMAGE_THUNK_DATA;	

		int NumberOfItem;	//˽�У���ʶ��ǰINT�����м�����
};

//һ������Ŀ¼ӳ���IAT��
struct IAT_Table
{
	DWORD* funcAddress;	 //������ַ

	int NumberOfItem;			//˽�У���ʶ��ǰIAT�����м�����
};
//һ���ⲿ����DLL�Ľṹ��һ���󶨵���Ŀ¼�п����ж����
struct BoundForwarderRef
{
	DWORD TimeDateStamp;			//ʱ���
	WORD OffsetModuleName;
	WORD Reserved;			//�����ֶ�
};
//һ���󶨵���Ŀ¼
struct BoundImportDirectory 
{
	DWORD TimeDateStamp;			//ʱ���
	WORD OffsetModuleName;
	WORD NumberOfModuleForwarderRefs;
	BoundForwarderRef* BoundForwarderRef;			
};
typedef struct PEBody
{
	ExportDirectory ExportDirectory;			//����Ŀ¼
	DWORD* Functions_Address;			//����Ŀ¼ӳ��ĺ�����ַ���еĸ�������ַ
	DWORD* Functions_Names;				//����Ŀ¼ӳ��ĺ������Ʊ�ĸ���������RVAֵ
	WORD* Functions_NameOrdinals;		//����Ŀ¼ӳ��ĺ�����ű�ĸ����
	ReloactionDirectory ReloactionDirectory;	//�ض�λĿ¼

	ImportDirectory* ImportDirectory;			//���ɸ�����Ŀ¼
	INT_Table* INT_Table;						//���ɸ�����Ŀ¼ӳ������ɸ�INT��
	IAT_Table* IAT_Table;						//���ɸ�����Ŀ¼ӳ������ɸ�IAT��
	BoundImportDirectory* BoundImportDirectory;	//���ɸ��󶨵���Ŀ¼

	int NumberOfImportDirectory;				//˽�У����ڱ�ʶ����Ŀ¼�ĸ���
	int NumberOfBoundImportDirectory;			//˽�У����ڱ�ʶ�󶨵���Ŀ¼�ĸ���
}PEBODY_X86;
