#pragma once
#include "pch.h"

//装载FileBuffer：读取文件
int LoadFileBuffer(const TCHAR* filePath, OUT PBYTE* ppFileBuffer);
//装载ImageBuffer：从FileBuffer拉伸至ImageBuffer
VOID LoadImageBuffer(PBYTE pFileBuffer, OUT PBYTE* ppImageBuffer, PEHEADER PEHeader);
//还原ImageBuffer至FileBuffer
VOID BackToFileBuffer(PBYTE pImageBuffer, PEHEADER PEHeader, int fileLen, OUT PBYTE* ppFileBuffer);
//将FileBuffer写入文件
VOID SaveFile(const CHAR* destFilePath, int destfileLen, PBYTE pFileBuffer);

//转换Foa和Rva
DWORD64 Trans_RVAtoFOA(DWORD64 RVA, PEHEADER PEHeader);
DWORD64 Trans_FOAtoRVA(DWORD64 FOA, PEHEADER PEHeader);

//分析PE文件
int calcNumberOfBlock(DWORD Block_FOA, PEHEADER thePEHeader, PBYTE pFileBuffer, int count = 0);
VOID AnalyzePE_ByFileBuffer(PBYTE pFileBuffer, OUT PEHEADER* pPEHeader, OUT PEBODY* pPEBody);
VOID AnalyzePE_ByImageBuffer(PBYTE pImageBuffer, OUT PEHEADER* pPEHeader, OUT PEBODY* pPEBody);

//修复重定位目录(ImageBuffer)
BOOL Repair_ReLocDirectory(DWORD64 newImageBase, DWORD64 oldImageBase, PBYTE pImageBuffer, PEHEADER* pPEHeader, PEBODY* pPEBody);



