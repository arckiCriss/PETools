#include "pch.h"
#include "HardwareBP.h"

//���壺4�����ԼĴ����������쳣����������Ĳ���
HardwareBP_Params g_HardwareBP_Params_DR0;
HardwareBP_Params g_HardwareBP_Params_DR1;
HardwareBP_Params g_HardwareBP_Params_DR2;
HardwareBP_Params g_HardwareBP_Params_DR3;

/*
 * �����ú�����ֱ�ӷ������������ô�
 * ���� ExceptionInfo
 */
VOID RetCall(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	//����rip��rsp�غ������ô�
	ExceptionInfo->ContextRecord->Rip = *(DWORD64*)(ExceptionInfo->ContextRecord->Rsp);
	ExceptionInfo->ContextRecord->Rsp += 0x8;
}

/*
 * ����ִ��ԭʼ��������ԭʼ�������׾���뱻ճ��λ�ü���ִ�У�
 * ���� ExceptionInfo
 * ���� pFirstCode
 */
VOID ResumeCall(struct _EXCEPTION_POINTERS* ExceptionInfo, LPVOID pFirstCode)
{
	//����rip��ԭʼ�����׾����ճ����(������������Ӳ���ϵ�)
	ExceptionInfo->ContextRecord->Rip = (DWORD64)pFirstCode;
}

//���ڵ���4���쳣������
LONG NTAPI MyVectoredExceptionHandle(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	//Ӳ���ϵ�ֻ�ᴥ��STATUS_SINGLE_STEP�����쳣
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
	{
		//���Dr6�ĵ�4λ�Ƿ���1��λ,�Ϳ����жϸõ����Ƿ�����ΪӲ���ϵ㱻���µ�
		//���Dr6����һλΪ1���ж�����Dr0~Dr3�е��ĸ��ϵ���µ�
		//Dr0->0001��Dr1->0010��Dr2->0100��Dr3->1000��
		if ((ExceptionInfo->ContextRecord->Dr6 & 0x1) && g_HardwareBP_Params_DR0.pVEHFunc != 0x0) //��ȫ��飺��DR��Ӳ���Ƿ��������ֶ�������(��ΪDR7������Ϊ��������DR)
		{
			return g_HardwareBP_Params_DR0.pVEHFunc(ExceptionInfo, g_HardwareBP_Params_DR0);
		}
		if ((ExceptionInfo->ContextRecord->Dr6 & 0x2) && g_HardwareBP_Params_DR1.pVEHFunc != 0x0)
		{
			return g_HardwareBP_Params_DR1.pVEHFunc(ExceptionInfo, g_HardwareBP_Params_DR1);
		}
		if ((ExceptionInfo->ContextRecord->Dr6 & 0x4) && g_HardwareBP_Params_DR2.pVEHFunc != 0x0)
		{
			return g_HardwareBP_Params_DR2.pVEHFunc(ExceptionInfo, g_HardwareBP_Params_DR2);
		}
		if ((ExceptionInfo->ContextRecord->Dr6 & 0x8) && g_HardwareBP_Params_DR3.pVEHFunc != 0x0)
		{
			return g_HardwareBP_Params_DR3.pVEHFunc(ExceptionInfo, g_HardwareBP_Params_DR3);
		}
	}

	//�����������¸������쳣������
	return EXCEPTION_CONTINUE_SEARCH;
}

HardwareBP::HardwareBP(LPVOID BreakPointAddress, PVEH_Func pVEHFunc, enum DRX Drx, int firstCodeLen)
{
	this->BreakPointAddress = BreakPointAddress;
	this->pVEHFunc = pVEHFunc;
	this->Drx = Drx;
	this->firstCodeLen = firstCodeLen;
	this->pFirstCode = 0x0;
}

VOID WINAPI HardwareBP::SetVEHHook(DWORD64 Dr7Type)
{
	//1.���VEH�����쳣������(�ҵķַ�����) ������=1��ʾ����Veh����ͷ����=0��ʾ���뵽VEH����β��
	AddVectoredExceptionHandler(1, MyVectoredExceptionHandle);

	//2.����ԭʼ�����׾���룬����ĩβ����Զ��ָ���ת��ԭʼ����
	if (this->firstCodeLen != 0x0)
	{
		this->pFirstCode = (LPVOID)VirtualAlloc(NULL, this->firstCodeLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		HardCode_FarJMP farJmp;
		farJmp.PUSH = 0x68;
		farJmp.Addr_Low32 = (DWORD)((DWORD64)this->BreakPointAddress + this->firstCodeLen);
		farJmp.MOV_DWORD_PTR_SS = 0x042444C7;
		farJmp.Addr_High32 = ((DWORD64)((DWORD64)this->BreakPointAddress + this->firstCodeLen)) >> 32;
		farJmp.RET = 0xC3;
		memcpy((LPVOID)this->pFirstCode, this->BreakPointAddress, this->firstCodeLen);
		memcpy((LPVOID)((DWORD64)this->pFirstCode + this->firstCodeLen), &farJmp, sizeof(farJmp));
	}

	//3.���ݲ�ͬ�ĵ��ԼĴ����ֱ�����VEH����
	switch (Drx)
	{
		case Dr0:
		{
			g_HardwareBP_Params_DR0.pVEHFunc = this->pVEHFunc;
			g_HardwareBP_Params_DR0.pFirstCode = this->pFirstCode;
			g_HardwareBP_Params_DR0.BreakPointAddress = this->BreakPointAddress;
			break;
		}
		case Dr1:
		{
			g_HardwareBP_Params_DR1.pVEHFunc = this->pVEHFunc;
			g_HardwareBP_Params_DR1.pFirstCode = this->pFirstCode;
			g_HardwareBP_Params_DR1.BreakPointAddress = this->BreakPointAddress;
			break;
		}
		case Dr2:
		{
			g_HardwareBP_Params_DR2.pVEHFunc = this->pVEHFunc;
			g_HardwareBP_Params_DR2.pFirstCode = this->pFirstCode;
			g_HardwareBP_Params_DR2.BreakPointAddress = this->BreakPointAddress;
			break;
		}
		case Dr3:
		{
			g_HardwareBP_Params_DR3.pVEHFunc = this->pVEHFunc;
			g_HardwareBP_Params_DR3.pFirstCode = this->pFirstCode;
			g_HardwareBP_Params_DR3.BreakPointAddress = this->BreakPointAddress;
			break;
		}
	}

	//4.���������̣߳������������Ӳ���ϵ�
	HookAllThread(this->Drx, Dr7Type);
}

/*
 * �������߳���Ӳ��
 * ���� Drx-��������Ӳ�ϵĵ��ԼĴ���
 * ���� Dr7Type-Ӳ�ϵ����ͣ���ִ�С���д�롢����д��
 */
BOOL HardwareBP::HookAllThread(enum DRX Drx, DWORD64 Dr7Type)
{
	CONTEXT context;
	context.ContextFlags = CONTEXT_ALL;
	DWORD64 CurrentThreadID = GetCurrentThreadId();
	DWORD64 CurrentProcessID = GetCurrentProcessId();

	// �����߳̿���
	THREADENTRY32 threadEntry32 = { sizeof(THREADENTRY32) };
	HANDLE  hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE) { printf("��error�������߳̿���ʧ��... \n"); return FALSE; }
	// ��ȡ��һ���߳�
	Thread32First(hThreadSnap, &threadEntry32);
	do
	{
		//ɸѡ��ǰ�����µ������̣߳��������Ӳ���ϵ�
		//����ǵ�ǰ�߳�����������Ϊ����ǰ�̺߳���ûЧ��
		if (threadEntry32.th32OwnerProcessID == CurrentProcessID
			&& threadEntry32.th32ThreadID != CurrentThreadID)
		{
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry32.th32ThreadID);
			if (hThread == 0) { printf("��error����ID=0x%llX���߳�ʧ��...Code=%d \n", GetLastError()); return FALSE; };
			SuspendThread(hThread);
			GetThreadContext(hThread, &context);
			switch (Drx)
			{//��ע�⣬��ΪDR7����Ϊ�������мĴ�����Ӳ�ϣ������������ֻ����ĳһ��DR����ô��Ҫ�ڴ����ж�����DR������Ӳ������ȫ���
				case Dr0: {context.Dr0 = (DWORD64)this->BreakPointAddress; break; }
				case Dr1: {context.Dr1 = (DWORD64)this->BreakPointAddress; break; }
				case Dr2: {context.Dr2 = (DWORD64)this->BreakPointAddress; break; }
				case Dr3: {context.Dr3 = (DWORD64)this->BreakPointAddress; break; }
				default: {printf("��error��hook�߳�ʱ�������󣬴����DRX����ȷ... \n"); return FALSE; }
			}

			context.Dr7 = Dr7Type;
			//context.Dr7 = 0x55;		//�ֲ��ϵ�+ִ�жϵ� (��Ч)
			//context.Dr7 = 0xFFFF0055;	//�ֲ��ϵ�+����д���ݶϵ㣨��Ч��
			//context.Dr7 = 0x55550055;	//�ֲ��ϵ�+д��ϵ㣨��Ч��
			//context.Dr7 = 0xAA;		//ȫ�ֶϵ�+ִ�жϵ㣨��Ч...��

			SetThreadContext(hThread, &context);
			ResumeThread(hThread);
		}
	} while (Thread32Next(hThreadSnap, &threadEntry32));
	printf("��info���Ѷ������̵߳�[DR%d]�Ĵ�������Ӳ���ϵ�,�¶ϵ�ַ=%p,�ϵ�����=0x%llx \n", Drx, this->BreakPointAddress, Dr7Type);
	return TRUE;
}

/*
 * VEH�쳣��������AddVectoredExceptionHandler
 * ���� ExceptionInfo
 */
LONG NTAPI VEH_AddVectoredExceptionHandler(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params)
{
	//ֻ��ע��ǰ������ַ�ĵ����쳣
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP
		&& (DWORD64)ExceptionInfo->ExceptionRecord->ExceptionAddress == (DWORD64)HardwareBP_Params.BreakPointAddress)
	{
		//����ԭ�ͣ� PVOID AddVectoredExceptionHandler(ULONG	First,PVECTORED_EXCEPTION_HANDLER Handler);
		//rcx ����1 ��First 
		//rdx ����2 ��Handler 
		ULONG First = (ULONG)ExceptionInfo->ContextRecord->Rcx;
		PVECTORED_EXCEPTION_HANDLER Handler = (PVECTORED_EXCEPTION_HANDLER)ExceptionInfo->ContextRecord->Rdx;
		printf("��info������AddVectoredExceptionHandler��Ӳ���ϵ��쳣������1 First=%016x ����2 Handle=%016x \n", First, Handler);

		//����1��Ϊ0x0(����������������쳣������������)
		ExceptionInfo->ContextRecord->Rcx = 0x0;

		//����ִ��ԭʼ��������ԭʼ�������׾���뱻ճ��λ�ü���ִ�У�
		ResumeCall(ExceptionInfo, HardwareBP_Params.pFirstCode);

		return EXCEPTION_CONTINUE_EXECUTION;
	}
	//�����¸�VEH����
	return EXCEPTION_CONTINUE_SEARCH;
}

/*
 * VEH�쳣��������D3D11-Present
 * ���� ExceptionInfo
 */
LONG NTAPI VEH_D3D11Present(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params)
{
	//ֻ��ע�����쳣 && ֻ��ע��ǰ������ַ���쳣
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP
		&& (DWORD64)ExceptionInfo->ExceptionRecord->ExceptionAddress == (DWORD64)HardwareBP_Params.BreakPointAddress)
	{
		//Present����������ԭ�ͣ�HRESULT __stdcall hkD3D11Present(IDXGISwapChain* pSwapChain, UINT SyscInterval, UINT Flags)
		//rcx ����1��this�ṹ�����ָ�룬����������ĵ�ַ
		//edx ����2: UINT SyscInterval
		//r8d ����3: UINT Flags
		pSwapChain_Game = (IDXGISwapChain*)ExceptionInfo->ContextRecord->Rcx;
		UINT SyscInterval = (DWORD)ExceptionInfo->ContextRecord->Rdx;
		UINT Flags = (DWORD)ExceptionInfo->ContextRecord->R8;

		//͸��
		if (WallHack_MyPresent(pSwapChain_Game, SyscInterval, Flags)) {}

		//����ִ��ԭʼ��������ԭʼ�������׾���뱻ճ��λ�ü���ִ�У�
		ResumeCall(ExceptionInfo, HardwareBP_Params.pFirstCode);

		//�쳣�Ѵ�������ִ��RIP������
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	//�����¸�VEH����
	return EXCEPTION_CONTINUE_SEARCH;
}

/*
 * VEH�쳣��������D3D11-DrawIndexed
 * ���� ExceptionInfo
 */
LONG NTAPI VEH_D3D11DrawIndexed(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params)
{
	//ֻ��ע�����쳣 && ֻ��ע��ǰ������ַ���쳣
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP
		&& (DWORD64)ExceptionInfo->ExceptionRecord->ExceptionAddress == (DWORD64)HardwareBP_Params.BreakPointAddress)
	{
		//����ԭ�� ��void __stdcall DrawIndexed(ID3D11DeviceContext* pContext,_In_  UINT IndexCount,_In_  UINT StartIndexLocation,_In_  INT BaseVertexLocation)
		//rcx ����1��this�ṹ�����ָ�룬�����Ķ���ĵ�ַ
		//edx ����2: UINT IndexCount
		//r8d ����3: UINT StartIndexLocation
		//r9d ����4��INT BaseVertexLocation
		ID3D11DeviceContext* pContext = (ID3D11DeviceContext*)ExceptionInfo->ContextRecord->Rcx;
		UINT IndexCount = (DWORD)ExceptionInfo->ContextRecord->Rdx;
		UINT StartIndexLocation = (DWORD)ExceptionInfo->ContextRecord->R8;
		UINT BaseVertexLocation = (DWORD)ExceptionInfo->ContextRecord->R9;

		//͸��
		if (WallHack_MyDrawIndexed(HardwareBP_Params.pFirstCode, pContext, IndexCount, StartIndexLocation, BaseVertexLocation))
		{
			ResumeCall(ExceptionInfo, HardwareBP_Params.pFirstCode);
		}
		else
		{
			RetCall(ExceptionInfo);
		}
		//�쳣�Ѵ�������ִ��RIP������
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	//�쳣δ���������¸�VEH����
	return EXCEPTION_CONTINUE_SEARCH;
}

/*
 * VEH�쳣��������D3D11-CreateQuery
 * ���� ExceptionInfo
 */
LONG NTAPI VEH_D3D11CreateQuery(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params)
{
	//ֻ��ע�����쳣 && ֻ��ע��ǰ������ַ���쳣
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP
		&& (DWORD64)ExceptionInfo->ExceptionRecord->ExceptionAddress == (DWORD64)HardwareBP_Params.BreakPointAddress)
	{
		//printf("��info������CreateQuery��Ӳ���ϵ��쳣...\n");

		//CreateQuery����������ԭ�ͣ�void __stdcall D3D11CreateQueryHook (ID3D11Device* pDevice, const D3D11_QUERY_DESC *pQueryDesc, ID3D11Query **ppQuery);
		//rcx ����1��pDevice ����ָ��
		//rdx ����2: pQueryDesc
		//r8  ����3: ppQuery
		pDevice_Game = (ID3D11Device*)ExceptionInfo->ContextRecord->Rcx;
		D3D11_QUERY_DESC* pQueryDesc = (D3D11_QUERY_DESC*)ExceptionInfo->ContextRecord->Rdx;
		ID3D11Query** ppQuery = (ID3D11Query * *)ExceptionInfo->ContextRecord->R8;

		//Disable Occlusion which prevents rendering player models through certain objects
		if (pQueryDesc->Query == D3D11_QUERY_OCCLUSION)
		{
			//printf("��info�������ڵ���ѯ...\n");
			//�޸���������������ִ��
			D3D11_QUERY_DESC oqueryDesc = CD3D11_QUERY_DESC();
			(&oqueryDesc)->MiscFlags = pQueryDesc->MiscFlags;
			(&oqueryDesc)->Query = D3D11_QUERY_TIMESTAMP;
			ExceptionInfo->ContextRecord->Rdx = (DWORD64)& oqueryDesc;
		}

		//����ִ��ԭʼ����
		ResumeCall(ExceptionInfo, HardwareBP_Params.pFirstCode);

		//�쳣�Ѵ�������ִ��RIP������
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	//�����¸�VEH����
	return EXCEPTION_CONTINUE_SEARCH;
}
/*
 * VEH�쳣��������GetThreadContext
 * ���� ExceptionInfo
 */
LONG NTAPI VEH_GetThreadContext(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params)
{
	//ֻ��ע��ǰ������ַ�ĵ����쳣
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP
		&& (DWORD64)ExceptionInfo->ExceptionRecord->ExceptionAddress == (DWORD64)HardwareBP_Params.BreakPointAddress)
	{
		printf("��info������GetThreadContext��Ӳ���ϵ��쳣..................  \n");
		//����ִ��ԭʼ����
		ResumeCall(ExceptionInfo, HardwareBP_Params.pFirstCode);
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	//�����¸�VEH����
	return EXCEPTION_CONTINUE_SEARCH;
}


/*
 * VEH�쳣��������IsDebuggerPresent
 * ���� ExceptionInfo
 */
LONG NTAPI VEH_IsDebuggerPresent(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params)
{
	//ֻ��ע��ǰ������ַ�ĵ����쳣
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP
		&& (DWORD64)ExceptionInfo->ExceptionRecord->ExceptionAddress == (DWORD64)HardwareBP_Params.BreakPointAddress)
	{

		//printf("��info������IsDebuggerPresent��Ӳ���ϵ��쳣 \n");
		//����ִ��ԭʼ����
		ResumeCall(ExceptionInfo, HardwareBP_Params.pFirstCode);
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	//�����¸�VEH����
	return EXCEPTION_CONTINUE_SEARCH;
}

/*
 * VEH�쳣��������D3D11-CreateQuery
 * ���� ExceptionInfo
 */
LONG NTAPI VEH_CreateQuery(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params)
{
	//ֻ��ע�����쳣 && ֻ��ע��ǰ������ַ���쳣
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP
		&& (DWORD64)ExceptionInfo->ExceptionRecord->ExceptionAddress == (DWORD64)HardwareBP_Params.BreakPointAddress)
	{
		//printf("��info������CreateQuery��Ӳ���ϵ��쳣...\n");

		//CreateQuery����������ԭ�ͣ�void __stdcall D3D11CreateQueryHook (ID3D11Device* pDevice, const D3D11_QUERY_DESC *pQueryDesc, ID3D11Query **ppQuery);
		//rcx ����1��pDevice ����ָ��
		//rdx ����2: pQueryDesc
		//r8  ����3: ppQuery
		pDevice_Game = (ID3D11Device*)ExceptionInfo->ContextRecord->Rcx;
		D3D11_QUERY_DESC* pQueryDesc = (D3D11_QUERY_DESC*)ExceptionInfo->ContextRecord->Rdx;
		ID3D11Query** ppQuery = (ID3D11Query * *)ExceptionInfo->ContextRecord->R8;

		//Disable Occlusion which prevents rendering player models through certain objects
		if (pQueryDesc->Query == D3D11_QUERY_OCCLUSION)
		{
			//printf("��info�������ڵ���ѯ...\n");
			//�޸���������������ִ��
			D3D11_QUERY_DESC oqueryDesc = CD3D11_QUERY_DESC();
			(&oqueryDesc)->MiscFlags = pQueryDesc->MiscFlags;
			(&oqueryDesc)->Query = D3D11_QUERY_TIMESTAMP;
			ExceptionInfo->ContextRecord->Rdx = (DWORD64)& oqueryDesc;
		}
		//����ִ��ԭʼ����
		ResumeCall(ExceptionInfo, HardwareBP_Params.pFirstCode);

		//�쳣�Ѵ�������ִ��RIP������
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	//�����¸�VEH����
	return EXCEPTION_CONTINUE_SEARCH;
}

/*
 * VEH�쳣��������D3D11-PSSetShaderResources
 * ���� ExceptionInfo
 */
LONG NTAPI VEH_PSSetShaderResources(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params)
{
	//ֻ��ע��ǰ������ַ�ĵ����쳣
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP
		&& (DWORD64)ExceptionInfo->ExceptionRecord->ExceptionAddress == (DWORD64)HardwareBP_Params.BreakPointAddress)
	{
		//printf("��info������PSSetShaderResources��Ӳ���ϵ��쳣...\n");

		//����ԭ�ͣ�void(__stdcall *D3D11PSSetShaderResourcesHook) (ID3D11DeviceContext* pContext, UINT StartSlot, UINT NumViews, ID3D11ShaderResourceView *const *ppShaderResourceViews);
		//rcx ����1 ��pContext ����ָ��
		//rdx ����2 ��StartSlot ����ָ��
		//r8  ����3 ��NumViews ����ָ��
		//r9  ����4 ��ppShaderResourceViews ����ָ��
		ID3D11DeviceContext* pContext = (ID3D11DeviceContext*)ExceptionInfo->ContextRecord->Rcx;
		UINT StartSlot = ExceptionInfo->ContextRecord->Rdx;
		UINT NumViews = ExceptionInfo->ContextRecord->R8;
		ID3D11ShaderResourceView* const* ppShaderResourceViews = (ID3D11ShaderResourceView * const*)ExceptionInfo->ContextRecord->R9;

		//����ִ��ԭʼ��������ԭʼ�������׾���뱻ճ��λ�ü���ִ�У�
		ResumeCall(ExceptionInfo, HardwareBP_Params.pFirstCode);

		//�쳣�Ѵ�������ִ��RIP������
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	//�����¸�VEH����
	return EXCEPTION_CONTINUE_SEARCH;
}

/*
 * VEH�쳣������������...
 * ���� ExceptionInfo
 */
LONG NTAPI VEH_DEBUG(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params)
{
	//�������ǣ���ִ�жϵ�
	if (ExceptionInfo->ExceptionRecord->ExceptionAddress == HardwareBP_Params.BreakPointAddress)
	{
		printf("��info������DEBUGӲ��(��ִ�жϵ�)... ExceptionAddress = %p Dr6=%016llx \n", ExceptionInfo->ExceptionRecord->ExceptionAddress, ExceptionInfo->ContextRecord->Dr6);
		printf("[rax=%llX] [rcx=%llX] [rdx=%llX] [rbx=%llX] [rsp=%llX] [rbp=%llX] [rsi=%llX] [rdi=%llX] \n[r8=%llX] [r9=%llX] [r10=%llX] [r11=%llX] [r12=%llX] [r13=%llX] [r14=%llX] [r15=%llX] \n",
			ExceptionInfo->ContextRecord->Rax, ExceptionInfo->ContextRecord->Rcx, ExceptionInfo->ContextRecord->Rdx, ExceptionInfo->ContextRecord->Rbx,
			ExceptionInfo->ContextRecord->Rsp, ExceptionInfo->ContextRecord->Rbp, ExceptionInfo->ContextRecord->Rsi, ExceptionInfo->ContextRecord->Rdi,
			ExceptionInfo->ContextRecord->R8, ExceptionInfo->ContextRecord->R9, ExceptionInfo->ContextRecord->R10, ExceptionInfo->ContextRecord->R11,
			ExceptionInfo->ContextRecord->R12, ExceptionInfo->ContextRecord->R13, ExceptionInfo->ContextRecord->R14, ExceptionInfo->ContextRecord->R15);

		//����ִ��ԭʼ��������ԭʼ�������׾���뱻ճ��λ�ü���ִ�У�
		ResumeCall(ExceptionInfo, HardwareBP_Params.pFirstCode);
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	//�������ǣ���д��ϵ㡢����д�ϵ�
	printf("��info������DEBUGӲ��(��д��ϵ㡢����д�ϵ�)... ExceptionAddress = %p Dr6=%016llx \n", ExceptionInfo->ExceptionRecord->ExceptionAddress, ExceptionInfo->ContextRecord->Dr6);
	printf("[rax=%llX] [rcx=%llX] [rdx=%llX] [rbx=%llX] [rsp=%llX] [rbp=%llX] [rsi=%llX] [rdi=%llX] \n[r8=%llX] [r9=%llX] [r10=%llX] [r11=%llX] [r12=%llX] [r13=%llX] [r14=%llX] [r15=%llX] \n",
		ExceptionInfo->ContextRecord->Rax, ExceptionInfo->ContextRecord->Rcx, ExceptionInfo->ContextRecord->Rdx, ExceptionInfo->ContextRecord->Rbx,
		ExceptionInfo->ContextRecord->Rsp, ExceptionInfo->ContextRecord->Rbp, ExceptionInfo->ContextRecord->Rsi, ExceptionInfo->ContextRecord->Rdi,
		ExceptionInfo->ContextRecord->R8, ExceptionInfo->ContextRecord->R9, ExceptionInfo->ContextRecord->R10, ExceptionInfo->ContextRecord->R11,
		ExceptionInfo->ContextRecord->R12, ExceptionInfo->ContextRecord->R13, ExceptionInfo->ContextRecord->R14, ExceptionInfo->ContextRecord->R15);
	return EXCEPTION_CONTINUE_EXECUTION;

}