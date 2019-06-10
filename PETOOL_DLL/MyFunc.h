#include "MyVariable.h"
#pragma once
//读PE文件，返回文件长度
extern "C" __declspec(dllexport) int readPEFile(char* filePath, OUT PBYTE* pFileBuffer);
//打印fileBuffer
extern "C" __declspec(dllexport) void printFileBuffer(PBYTE MemoryEntry, int MemoryLength);
//从fileBuffer转ImageBuffer
extern "C" __declspec(dllexport) void FileBufferToImageBuffer(PBYTE pFileBuffer, OUT PBYTE* pImageBuffer_address, PEHeader PEHeader);

extern "C" __declspec(dllexport) void imageBufferToNewBuffer(PBYTE pImageBuffer, PBYTE* pNewBuffer_address, int fileLength, PEHeader PEHeader);
extern "C" __declspec(dllexport) void writePEFile(char* filePath, int fileLength, PBYTE pNewBuffer);
extern "C" __declspec(dllexport) void insertCode(PBYTE pImageBuffer);
//分析PE参数(根据FileBuffer)(x86)
extern "C" __declspec(dllexport) void AnalyzePE_FileBuffer_x86(PBYTE pFileBuffer,OUT PEHeader* pPEHeader,OUT PEBody* pPEBody);
//分析PE参数(根据ImageBuffer)(x86)
extern "C" __declspec(dllexport) VOID AnalyzePE_ImageBuffer_x86(PBYTE pImageBuffer, OUT PEHeader* pPEHeader, OUT PEBody* pPEBody);
//新增节
extern "C" __declspec(dllexport) DWORD addSection(PEHeader* pPEHeader, PEBody* pPEBody, char* filePath, PBYTE* pFileBuffer, char* sectionName, DWORD addSize);
//RVA转FOA
extern "C" __declspec(dllexport) DWORD convertRVAtoFOA(DWORD RVA, PEHeader thePEHeader);
//根据函数名查找函数地址
extern "C" __declspec(dllexport) DWORD getFuncAddressByName(char* funcName, PBYTE pFileBuffer, PEHeader thePEHeader, PEBody thePEBody);
//根据"逻辑序号"查找函数地址
extern "C" __declspec(dllexport)  DWORD getFuncAddressByLogicalOrdinal(DWORD logicalIndex, PEBody thePEBody);
//移动“导出表”至新节
extern "C" __declspec(dllexport) void moveExportDirectory(PEHeader* pPEHeader, PEBody* pPEBody, char* filePath, PBYTE pFileBuffer);
//移动“重定位目录”至新节
extern "C" __declspec(dllexport) void moveRelocationDirectory(PEHeader* pPEHeader, PEBody* pPEBody, char* filePath, PBYTE pFileBuffer);
//遍历进程
extern "C" __declspec(dllexport) void traversalProcess();
//加壳
extern "C" __declspec(dllexport) void addShell(char* filePath_src, char* filePath_shell);
//提升权限(请用管理员权限运行EXE)
extern "C" __declspec(dllexport) bool upPrivileges();

//加载目标EXE至本进程
extern "C" __declspec(dllexport) void LoadExe_x86(char* filePath);
//修复IAT表
extern "C" __declspec(dllexport) VOID RepairIAT_x86(DWORD virtualAddr, PEBody* pPEBody);

//计算"重定位Block"的块数
int calcNumberOfBlock(DWORD Block_FOA, PEHeader thePEHeader, PBYTE pFileBuffer, int count = 0);
//打印导入目录
void PrintImportDirectory(PEHeader PEHeader, PEBody PEBody, PBYTE pFileBuffer);
// 用于加载EXE(x86)的子线程方法
DWORD WINAPI SubThreadFunc_LoadExe_x86(LPVOID lpThreadParameter);

//数字转字符串
CHAR* HexToStr(DWORD srcHex);
CHAR* DecToStr(DWORD srcDec);
//打印十六进制数字hex和msg到OutputDebugString (四字节的hex数)
void ShowDbg(const char* msgStr, DWORD hex);

//消息钩子
void Hook_MessageHook();

//IAT钩子
void Hook_IATHook_x86(char* destDllName, char* destFuncName, DWORD hookFuncAddr);
int WINAPI Hook_IATHook_MyMessageBox_X86(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType);

//通过进程名打开进程
HANDLE MyOpenProcess_x86(CHAR* ProcessName, DWORD needAccess);
HANDLE MyOpenProcess_x64(CHAR* ProcessName, DWORD needAccess);

//根据新基址，修复重定位表(ImageBuffer)
BOOL RepairReLocationDirectory_x86(DWORD destImageBase, DWORD srcImageBase, PBYTE pImageBuffer, PEHeader* pPEHeader, PEBody* pPEBody);



