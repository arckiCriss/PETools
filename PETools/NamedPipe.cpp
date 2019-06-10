#include "pch.h"
#include "NamedPipe.h"

//命名管道
#define PIPE_NAME "\\\\.\\Pipe\\test"
void NamedPipe::OnClient()
{
	char msg[1024] = { 0 };			//消息 (消息格式" w-7fff7123 ")
	char command[1] = { 0 };		//消息：命令e/w/r
	char strFirstLen[1] = { 0 };	//消息：首局代码长度
	char address[1022] = { 0 };		//消息：下断地址

	DWORD ReadNum = 0;
	if (WaitNamedPipe(PIPE_NAME, NMPWAIT_WAIT_FOREVER) == FALSE) { printf("等待命名管道实例失败！\n"); return; }
	HANDLE hPipe = CreateFile(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hPipe == INVALID_HANDLE_VALUE) { printf("创建命名管道失败！\n"); CloseHandle(hPipe); return; }
	printf("【info】与服务器连接成功！\n");

	//**************硬断反检测*****************
	HardwareBP((LPVOID)AddVectoredExceptionHandler, VEH_AddVectoredExceptionHandler, DRX::Dr0, 3).SetVEHHook(硬断_仅执行);
	//****************************************

	while (true)
	{//接收消息
		Sleep(1);
		if (ReadFile(hPipe, msg, 1024, &ReadNum, NULL) == FALSE) { printf("【error】读取数据失败！\n"); break; }
		printf("【msg】接收到消息：%s \n", msg);
		//处理消息：消息格式"w-7fff7123" 
		command[0] = msg[0];
		memcpy(&address[0], &msg[2], 1022);
		DWORD64 hex = 0;
		sscanf(address, "%llx", &hex);//**************

		switch (command[0])
		{
			case 'e':
			{
				printf("【handle】硬件断点(仅执行)，下断地址=%p... 等待输入首句代码长度 = ", hex);
				if (ReadFile(hPipe, strFirstLen, 1, &ReadNum, NULL) == FALSE)
				{//再次输入：首句代码的长度
					printf("【error】读取数据失败！\n");
					break;
				}
				int firstLen = strFirstLen[0] - '0';
				printf("%d \n", firstLen);
				HardwareBP((LPVOID)hex, VEH_DEBUG, DRX::Dr1, firstLen).SetVEHHook(硬断_仅执行);
				break;
			}
			case 'r':
			{
				printf("【handle】硬件断点(读或写)，下断地址=%p... \n", hex);
				HardwareBP((LPVOID)hex, VEH_DEBUG, DRX::Dr2, 0).SetVEHHook(硬断_读或写);
				break;
			}
			case 'w':
			{
				printf("【handle】硬件断点(仅写入)，下断地址=%p... \n", hex);
				HardwareBP((LPVOID)hex, VEH_DEBUG, DRX::Dr3, 0).SetVEHHook(硬断_仅写入);
				break;
			}
			default:
				printf("【error】管道接收到的格式不正确... \n");
				break;
		}
	}
	printf("关闭管道！\n");
	CloseHandle(hPipe);
	system("pause");
}

void NamedPipe::OnServer()
{
	char buffer[1024];
	DWORD WriteNum;
	HANDLE hPipe = CreateNamedPipe(PIPE_NAME, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE, 1, 0, 0, 1000, NULL);
	if (hPipe == INVALID_HANDLE_VALUE) { printf("【error】创建命名管道失败！\n"); system("pause"); CloseHandle(hPipe); return; }
	if (ConnectNamedPipe(hPipe, NULL) == FALSE) { printf("【error】与客户机连接失败！\n"); CloseHandle(hPipe); system("pause"); return; }
	printf("【info】成功连接客户端...\n");
	while (true)
	{//等待数据输入
		Sleep(1);
		printf("输入地址值:  ");
		scanf("%s", &buffer);
		if (WriteFile(hPipe, buffer, strlen(buffer), &WriteNum, NULL) == FALSE) { printf("数据写入管道失败！\n"); break; }
	}
	printf("关闭管道！\n");
	CloseHandle(hPipe);
	system("pause");
}
