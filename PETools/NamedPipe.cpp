#include "pch.h"
#include "NamedPipe.h"

//�����ܵ�
#define PIPE_NAME "\\\\.\\Pipe\\test"
void NamedPipe::OnClient()
{
	char msg[1024] = { 0 };			//��Ϣ (��Ϣ��ʽ" w-7fff7123 ")
	char command[1] = { 0 };		//��Ϣ������e/w/r
	char strFirstLen[1] = { 0 };	//��Ϣ���׾ִ��볤��
	char address[1022] = { 0 };		//��Ϣ���¶ϵ�ַ

	DWORD ReadNum = 0;
	if (WaitNamedPipe(PIPE_NAME, NMPWAIT_WAIT_FOREVER) == FALSE) { printf("�ȴ������ܵ�ʵ��ʧ�ܣ�\n"); return; }
	HANDLE hPipe = CreateFile(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hPipe == INVALID_HANDLE_VALUE) { printf("���������ܵ�ʧ�ܣ�\n"); CloseHandle(hPipe); return; }
	printf("��info������������ӳɹ���\n");

	//**************Ӳ�Ϸ����*****************
	HardwareBP((LPVOID)AddVectoredExceptionHandler, VEH_AddVectoredExceptionHandler, DRX::Dr0, 3).SetVEHHook(Ӳ��_��ִ��);
	//****************************************

	while (true)
	{//������Ϣ
		Sleep(1);
		if (ReadFile(hPipe, msg, 1024, &ReadNum, NULL) == FALSE) { printf("��error����ȡ����ʧ�ܣ�\n"); break; }
		printf("��msg�����յ���Ϣ��%s \n", msg);
		//������Ϣ����Ϣ��ʽ"w-7fff7123" 
		command[0] = msg[0];
		memcpy(&address[0], &msg[2], 1022);
		DWORD64 hex = 0;
		sscanf(address, "%llx", &hex);//**************

		switch (command[0])
		{
			case 'e':
			{
				printf("��handle��Ӳ���ϵ�(��ִ��)���¶ϵ�ַ=%p... �ȴ������׾���볤�� = ", hex);
				if (ReadFile(hPipe, strFirstLen, 1, &ReadNum, NULL) == FALSE)
				{//�ٴ����룺�׾����ĳ���
					printf("��error����ȡ����ʧ�ܣ�\n");
					break;
				}
				int firstLen = strFirstLen[0] - '0';
				printf("%d \n", firstLen);
				HardwareBP((LPVOID)hex, VEH_DEBUG, DRX::Dr1, firstLen).SetVEHHook(Ӳ��_��ִ��);
				break;
			}
			case 'r':
			{
				printf("��handle��Ӳ���ϵ�(����д)���¶ϵ�ַ=%p... \n", hex);
				HardwareBP((LPVOID)hex, VEH_DEBUG, DRX::Dr2, 0).SetVEHHook(Ӳ��_����д);
				break;
			}
			case 'w':
			{
				printf("��handle��Ӳ���ϵ�(��д��)���¶ϵ�ַ=%p... \n", hex);
				HardwareBP((LPVOID)hex, VEH_DEBUG, DRX::Dr3, 0).SetVEHHook(Ӳ��_��д��);
				break;
			}
			default:
				printf("��error���ܵ����յ��ĸ�ʽ����ȷ... \n");
				break;
		}
	}
	printf("�رչܵ���\n");
	CloseHandle(hPipe);
	system("pause");
}

void NamedPipe::OnServer()
{
	char buffer[1024];
	DWORD WriteNum;
	HANDLE hPipe = CreateNamedPipe(PIPE_NAME, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE, 1, 0, 0, 1000, NULL);
	if (hPipe == INVALID_HANDLE_VALUE) { printf("��error�����������ܵ�ʧ�ܣ�\n"); system("pause"); CloseHandle(hPipe); return; }
	if (ConnectNamedPipe(hPipe, NULL) == FALSE) { printf("��error����ͻ�������ʧ�ܣ�\n"); CloseHandle(hPipe); system("pause"); return; }
	printf("��info���ɹ����ӿͻ���...\n");
	while (true)
	{//�ȴ���������
		Sleep(1);
		printf("�����ֵַ:  ");
		scanf("%s", &buffer);
		if (WriteFile(hPipe, buffer, strlen(buffer), &WriteNum, NULL) == FALSE) { printf("����д��ܵ�ʧ�ܣ�\n"); break; }
	}
	printf("�رչܵ���\n");
	CloseHandle(hPipe);
	system("pause");
}
