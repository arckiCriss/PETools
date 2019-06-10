#pragma once
struct DOSHeader
{
	unsigned short MZ;
	unsigned int offset_to_PE_signature;
};
struct COFFHeader
{
	unsigned short number_of_section;
	unsigned short size_of_optional_Headers;
};
struct OptionalHeader
{
	unsigned int size_of_image;
	unsigned int size_of_headers;
	unsigned int address_of_entry_point;
	unsigned int image_base;

	unsigned int export_directory_offset;		//����Ŀ¼��RVA
	unsigned int relocation_directory_offset;	//�ض�λĿ¼RVA
	unsigned int import_directory_offset;		//����Ŀ¼��RVA
	unsigned int bound_import_directory_offset;	//�󶨵���Ŀ¼��RVA
};
struct SectionHeader
{
	unsigned long long* section_name;
	unsigned int* virtual_size;
	unsigned int* virtual_address;
	unsigned int* size_Of_raw_data;
	unsigned int* pointer_to_raw_data;
};
struct PEHeader
{
	DOSHeader DOSHeader;
	COFFHeader COFFHeader;
	OptionalHeader OptionalHeader;
	SectionHeader SectionHeader;
};

struct ExportDirectory
{
	unsigned int Address_Of_Functions;		//������ַ��
	unsigned int Address_Of_Names;			//�������Ʊ�
	unsigned int Address_Of_NameOrdinals;	//������ű�

	unsigned int Number_Of_Functions;
	unsigned int Number_Of_Names;
	unsigned int Base;
};

struct Item
{
	unsigned char Type;		//��char�洢��4λ���˷�4λ
	unsigned int Offset;	//��uint�洢��12λ���˷�4λ
};

struct Block//�ض�λ��	
{
	unsigned int Virtual_Address;	//��ǰҳ��ʼ��ַ��RVA
	unsigned int Size_Of_Block;		//��Ĵ�С
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
	unsigned int OriginalFirstThunk;//���RVAֵ��ָ���ӦINT�������
	unsigned int TimeDateStamp;		//ʱ�������ʶ��ǰ������Ƿ��ѱ���
	unsigned int ForwarderChain;	//��ʱδ֪
	unsigned int Name;				//���RVAֵ��ָ���ӦDLL�������ַ������ַ�����0x0����
	unsigned int FirstThunk;		//���RVAֵ��ָ���ӦIAT�������


};
//һ������Ŀ¼ӳ���INT��
struct INT_Table
{
	//��ֵ����߶�����λ=1��������λ���"�����������"
	//��ֵ����߶�����λ=0������RVAֵ��ָ��һ��_IMAGE_IMPORT_BY_NAME�ṹ(ϵͳ����Ѷ���˽ṹ)
	unsigned int* IMAGE_THUNK_DATA;

	int NumberOfItem;	//˽�У���ʶ��ǰINT�����м�����
};

//һ������Ŀ¼ӳ���IAT��
struct IAT_Table
{
	unsigned int* funcAddress;	 //������ַ

	int NumberOfItem;			//˽�У���ʶ��ǰIAT�����м�����
};
//һ���ⲿ����DLL�Ľṹ��һ���󶨵���Ŀ¼�п����ж����
struct BoundForwarderRef
{
	unsigned int TimeDateStamp;			//ʱ���
	unsigned short OffsetModuleName;
	unsigned short Reserved;			//�����ֶ�
};
//һ���󶨵���Ŀ¼
struct BoundImportDirectory
{
	unsigned int TimeDateStamp;			//ʱ���
	unsigned short OffsetModuleName;
	unsigned short NumberOfModuleForwarderRefs;
	BoundForwarderRef* BoundForwarderRef;
};




struct PEBody
{
	ExportDirectory ExportDirectory;			//����Ŀ¼
	unsigned int* Functions_Address;			//����Ŀ¼ӳ��ĺ�����ַ���еĸ�������ַ
	unsigned int* Functions_Names;				//����Ŀ¼ӳ��ĺ������Ʊ�ĸ���������RVAֵ
	unsigned short* Functions_NameOrdinals;		//����Ŀ¼ӳ��ĺ�����ű�ĸ����
	ReloactionDirectory ReloactionDirectory;	//�ض�λĿ¼

	ImportDirectory* ImportDirectory;			//���ɸ�����Ŀ¼
	INT_Table* INT_Table;						//���ɸ�����Ŀ¼ӳ������ɸ�INT��
	IAT_Table* IAT_Table;						//���ɸ�����Ŀ¼ӳ������ɸ�IAT��
	BoundImportDirectory* BoundImportDirectory;	//���ɸ��󶨵���Ŀ¼

	int NumberOfImportDirectory;				//˽�У����ڱ�ʶ����Ŀ¼�ĸ���
	int NumberOfBoundImportDirectory;			//˽�У����ڱ�ʶ�󶨵���Ŀ¼�ĸ���
};