#include "MyVariable.h"
#pragma once
//��PE�ļ��������ļ�����
extern "C" __declspec(dllexport) int readPEFile(char* filePath, OUT PBYTE* pFileBuffer);
//��ӡfileBuffer
extern "C" __declspec(dllexport) void printFileBuffer(PBYTE MemoryEntry, int MemoryLength);
//��fileBufferתImageBuffer
extern "C" __declspec(dllexport) void FileBufferToImageBuffer(PBYTE pFileBuffer, OUT PBYTE* pImageBuffer_address, PEHeader PEHeader);

extern "C" __declspec(dllexport) void imageBufferToNewBuffer(PBYTE pImageBuffer, PBYTE* pNewBuffer_address, int fileLength, PEHeader PEHeader);
extern "C" __declspec(dllexport) void writePEFile(char* filePath, int fileLength, PBYTE pNewBuffer);
extern "C" __declspec(dllexport) void insertCode(PBYTE pImageBuffer);
//����PE����(����FileBuffer)(x86)
extern "C" __declspec(dllexport) void AnalyzePE_FileBuffer_x86(PBYTE pFileBuffer,OUT PEHeader* pPEHeader,OUT PEBody* pPEBody);
//����PE����(����ImageBuffer)(x86)
extern "C" __declspec(dllexport) VOID AnalyzePE_ImageBuffer_x86(PBYTE pImageBuffer, OUT PEHeader* pPEHeader, OUT PEBody* pPEBody);
//������
extern "C" __declspec(dllexport) DWORD addSection(PEHeader* pPEHeader, PEBody* pPEBody, char* filePath, PBYTE* pFileBuffer, char* sectionName, DWORD addSize);
//RVAתFOA
extern "C" __declspec(dllexport) DWORD convertRVAtoFOA(DWORD RVA, PEHeader thePEHeader);
//���ݺ��������Һ�����ַ
extern "C" __declspec(dllexport) DWORD getFuncAddressByName(char* funcName, PBYTE pFileBuffer, PEHeader thePEHeader, PEBody thePEBody);
//����"�߼����"���Һ�����ַ
extern "C" __declspec(dllexport)  DWORD getFuncAddressByLogicalOrdinal(DWORD logicalIndex, PEBody thePEBody);
//�ƶ������������½�
extern "C" __declspec(dllexport) void moveExportDirectory(PEHeader* pPEHeader, PEBody* pPEBody, char* filePath, PBYTE pFileBuffer);
//�ƶ����ض�λĿ¼�����½�
extern "C" __declspec(dllexport) void moveRelocationDirectory(PEHeader* pPEHeader, PEBody* pPEBody, char* filePath, PBYTE pFileBuffer);
//��������
extern "C" __declspec(dllexport) void traversalProcess();
//�ӿ�
extern "C" __declspec(dllexport) void addShell(char* filePath_src, char* filePath_shell);
//����Ȩ��(���ù���ԱȨ������EXE)
extern "C" __declspec(dllexport) bool upPrivileges();

//����Ŀ��EXE��������
extern "C" __declspec(dllexport) void LoadExe_x86(char* filePath);
//�޸�IAT��
extern "C" __declspec(dllexport) VOID RepairIAT_x86(DWORD virtualAddr, PEBody* pPEBody);

//����"�ض�λBlock"�Ŀ���
int calcNumberOfBlock(DWORD Block_FOA, PEHeader thePEHeader, PBYTE pFileBuffer, int count = 0);
//��ӡ����Ŀ¼
void PrintImportDirectory(PEHeader PEHeader, PEBody PEBody, PBYTE pFileBuffer);
// ���ڼ���EXE(x86)�����̷߳���
DWORD WINAPI SubThreadFunc_LoadExe_x86(LPVOID lpThreadParameter);

//����ת�ַ���
CHAR* HexToStr(DWORD srcHex);
CHAR* DecToStr(DWORD srcDec);
//��ӡʮ����������hex��msg��OutputDebugString (���ֽڵ�hex��)
void ShowDbg(const char* msgStr, DWORD hex);

//��Ϣ����
void Hook_MessageHook();

//IAT����
void Hook_IATHook_x86(char* destDllName, char* destFuncName, DWORD hookFuncAddr);
int WINAPI Hook_IATHook_MyMessageBox_X86(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType);

//ͨ���������򿪽���
HANDLE MyOpenProcess_x86(CHAR* ProcessName, DWORD needAccess);
HANDLE MyOpenProcess_x64(CHAR* ProcessName, DWORD needAccess);

//�����»�ַ���޸��ض�λ��(ImageBuffer)
BOOL RepairReLocationDirectory_x86(DWORD destImageBase, DWORD srcImageBase, PBYTE pImageBuffer, PEHeader* pPEHeader, PEBody* pPEBody);



