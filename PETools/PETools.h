#pragma once
#include "pch.h"

//װ��FileBuffer����ȡ�ļ�
int LoadFileBuffer(const TCHAR* filePath, OUT PBYTE* ppFileBuffer);
//װ��ImageBuffer����FileBuffer������ImageBuffer
VOID LoadImageBuffer(PBYTE pFileBuffer, OUT PBYTE* ppImageBuffer, PEHEADER PEHeader);
//��ԭImageBuffer��FileBuffer
VOID BackToFileBuffer(PBYTE pImageBuffer, PEHEADER PEHeader, int fileLen, OUT PBYTE* ppFileBuffer);
//��FileBufferд���ļ�
VOID SaveFile(const CHAR* destFilePath, int destfileLen, PBYTE pFileBuffer);

//ת��Foa��Rva
DWORD64 Trans_RVAtoFOA(DWORD64 RVA, PEHEADER PEHeader);
DWORD64 Trans_FOAtoRVA(DWORD64 FOA, PEHEADER PEHeader);

//����PE�ļ�
int calcNumberOfBlock(DWORD Block_FOA, PEHEADER thePEHeader, PBYTE pFileBuffer, int count = 0);
VOID AnalyzePE_ByFileBuffer(PBYTE pFileBuffer, OUT PEHEADER* pPEHeader, OUT PEBODY* pPEBody);
VOID AnalyzePE_ByImageBuffer(PBYTE pImageBuffer, OUT PEHEADER* pPEHeader, OUT PEBODY* pPEBody);

//�޸��ض�λĿ¼(ImageBuffer)
BOOL Repair_ReLocDirectory(DWORD64 newImageBase, DWORD64 oldImageBase, PBYTE pImageBuffer, PEHEADER* pPEHeader, PEBODY* pPEBody);



