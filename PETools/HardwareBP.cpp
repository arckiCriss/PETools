#include "pch.h"
#include "HardwareBP.h"

//定义：4个调试寄存器触发的异常处理函数所需的参数
HardwareBP_Params g_HardwareBP_Params_DR0;
HardwareBP_Params g_HardwareBP_Params_DR1;
HardwareBP_Params g_HardwareBP_Params_DR2;
HardwareBP_Params g_HardwareBP_Params_DR3;

/*
 * 结束该函数，直接返回至函数调用处
 * 参数 ExceptionInfo
 */
VOID RetCall(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	//修正rip和rsp回函数调用处
	ExceptionInfo->ContextRecord->Rip = *(DWORD64*)(ExceptionInfo->ContextRecord->Rsp);
	ExceptionInfo->ContextRecord->Rsp += 0x8;
}

/*
 * 继续执行原始函数（从原始函数的首句代码被粘贴位置继续执行）
 * 参数 ExceptionInfo
 * 参数 pFirstCode
 */
VOID ResumeCall(struct _EXCEPTION_POINTERS* ExceptionInfo, LPVOID pFirstCode)
{
	//修正rip至原始函数首句代码粘贴处(这样就能跳过硬件断点)
	ExceptionInfo->ContextRecord->Rip = (DWORD64)pFirstCode;
}

//用于调用4个异常处理函数
LONG NTAPI MyVectoredExceptionHandle(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	//硬件断点只会触发STATUS_SINGLE_STEP单步异常
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
	{
		//检测Dr6的低4位是否有1的位,就可以判断该单步是否是因为硬件断点被断下的
		//检测Dr6的哪一位为1来判断是由Dr0~Dr3中的哪个断点断下的
		//Dr0->0001；Dr1->0010；Dr2->0100；Dr3->1000；
		if ((ExceptionInfo->ContextRecord->Dr6 & 0x1) && g_HardwareBP_Params_DR0.pVEHFunc != 0x0) //安全检查：该DR的硬断是否是我们手动开启的(因为DR7被设置为启动所有DR)
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

	//不处理，交由下个向量异常处理函数
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
	//1.添加VEH向量异常处理函数(我的分发函数) ，参数=1表示插入Veh链的头部，=0表示插入到VEH链的尾部
	AddVectoredExceptionHandler(1, MyVectoredExceptionHandle);

	//2.复制原始函数首句代码，并在末尾增加远跳指令，跳转回原始函数
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

	//3.根据不同的调试寄存器分别设置VEH参数
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

	//4.遍历所有线程，逐个挂起并设置硬件断点
	HookAllThread(this->Drx, Dr7Type);
}

/*
 * 对所有线程下硬断
 * 参数 Drx-用于设置硬断的调试寄存器
 * 参数 Dr7Type-硬断的类型（仅执行、仅写入、读或写）
 */
BOOL HardwareBP::HookAllThread(enum DRX Drx, DWORD64 Dr7Type)
{
	CONTEXT context;
	context.ContextFlags = CONTEXT_ALL;
	DWORD64 CurrentThreadID = GetCurrentThreadId();
	DWORD64 CurrentProcessID = GetCurrentProcessId();

	// 创建线程快照
	THREADENTRY32 threadEntry32 = { sizeof(THREADENTRY32) };
	HANDLE  hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE) { printf("【error】创建线程快照失败... \n"); return FALSE; }
	// 获取第一个线程
	Thread32First(hThreadSnap, &threadEntry32);
	do
	{
		//筛选当前进程下的所有线程，逐个设置硬件断点
		//如果是当前线程则跳过，因为挂起当前线程好像没效果
		if (threadEntry32.th32OwnerProcessID == CurrentProcessID
			&& threadEntry32.th32ThreadID != CurrentThreadID)
		{
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry32.th32ThreadID);
			if (hThread == 0) { printf("【error】打开ID=0x%llX的线程失败...Code=%d \n", GetLastError()); return FALSE; };
			SuspendThread(hThread);
			GetThreadContext(hThread, &context);
			switch (Drx)
			{//需注意，因为DR7设置为启用所有寄存器的硬断，所以如果我们只启用某一个DR，那么需要在代码中对其他DR触发的硬断做安全检查
				case Dr0: {context.Dr0 = (DWORD64)this->BreakPointAddress; break; }
				case Dr1: {context.Dr1 = (DWORD64)this->BreakPointAddress; break; }
				case Dr2: {context.Dr2 = (DWORD64)this->BreakPointAddress; break; }
				case Dr3: {context.Dr3 = (DWORD64)this->BreakPointAddress; break; }
				default: {printf("【error】hook线程时发生错误，传入的DRX不正确... \n"); return FALSE; }
			}

			context.Dr7 = Dr7Type;
			//context.Dr7 = 0x55;		//局部断点+执行断点 (有效)
			//context.Dr7 = 0xFFFF0055;	//局部断点+读或写数据断点（有效）
			//context.Dr7 = 0x55550055;	//局部断点+写入断点（有效）
			//context.Dr7 = 0xAA;		//全局断点+执行断点（无效...）

			SetThreadContext(hThread, &context);
			ResumeThread(hThread);
		}
	} while (Thread32Next(hThreadSnap, &threadEntry32));
	printf("【info】已对所有线程的[DR%d]寄存器设置硬件断点,下断地址=%p,断点类型=0x%llx \n", Drx, this->BreakPointAddress, Dr7Type);
	return TRUE;
}

/*
 * VEH异常处理函数：AddVectoredExceptionHandler
 * 参数 ExceptionInfo
 */
LONG NTAPI VEH_AddVectoredExceptionHandler(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params)
{
	//只关注当前函数地址的单步异常
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP
		&& (DWORD64)ExceptionInfo->ExceptionRecord->ExceptionAddress == (DWORD64)HardwareBP_Params.BreakPointAddress)
	{
		//函数原型： PVOID AddVectoredExceptionHandler(ULONG	First,PVECTORED_EXCEPTION_HANDLER Handler);
		//rcx 参数1 ：First 
		//rdx 参数2 ：Handler 
		ULONG First = (ULONG)ExceptionInfo->ContextRecord->Rcx;
		PVECTORED_EXCEPTION_HANDLER Handler = (PVECTORED_EXCEPTION_HANDLER)ExceptionInfo->ContextRecord->Rdx;
		printf("【info】捕获到AddVectoredExceptionHandler的硬件断点异常，参数1 First=%016x 参数2 Handle=%016x \n", First, Handler);

		//参数1改为0x0(即不允许添加向量异常处理函数至顶层)
		ExceptionInfo->ContextRecord->Rcx = 0x0;

		//继续执行原始函数（从原始函数的首句代码被粘贴位置继续执行）
		ResumeCall(ExceptionInfo, HardwareBP_Params.pFirstCode);

		return EXCEPTION_CONTINUE_EXECUTION;
	}
	//交由下个VEH处理
	return EXCEPTION_CONTINUE_SEARCH;
}

/*
 * VEH异常处理函数：D3D11-Present
 * 参数 ExceptionInfo
 */
LONG NTAPI VEH_D3D11Present(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params)
{
	//只关注单步异常 && 只关注当前函数地址的异常
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP
		&& (DWORD64)ExceptionInfo->ExceptionRecord->ExceptionAddress == (DWORD64)HardwareBP_Params.BreakPointAddress)
	{
		//Present函数函数的原型：HRESULT __stdcall hkD3D11Present(IDXGISwapChain* pSwapChain, UINT SyscInterval, UINT Flags)
		//rcx 参数1：this结构体对象指针，交换链对象的地址
		//edx 参数2: UINT SyscInterval
		//r8d 参数3: UINT Flags
		pSwapChain_Game = (IDXGISwapChain*)ExceptionInfo->ContextRecord->Rcx;
		UINT SyscInterval = (DWORD)ExceptionInfo->ContextRecord->Rdx;
		UINT Flags = (DWORD)ExceptionInfo->ContextRecord->R8;

		//透视
		if (WallHack_MyPresent(pSwapChain_Game, SyscInterval, Flags)) {}

		//继续执行原始函数（从原始函数的首句代码被粘贴位置继续执行）
		ResumeCall(ExceptionInfo, HardwareBP_Params.pFirstCode);

		//异常已处理，继续执行RIP处代码
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	//交由下个VEH处理
	return EXCEPTION_CONTINUE_SEARCH;
}

/*
 * VEH异常处理函数：D3D11-DrawIndexed
 * 参数 ExceptionInfo
 */
LONG NTAPI VEH_D3D11DrawIndexed(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params)
{
	//只关注单步异常 && 只关注当前函数地址的异常
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP
		&& (DWORD64)ExceptionInfo->ExceptionRecord->ExceptionAddress == (DWORD64)HardwareBP_Params.BreakPointAddress)
	{
		//函数原型 ：void __stdcall DrawIndexed(ID3D11DeviceContext* pContext,_In_  UINT IndexCount,_In_  UINT StartIndexLocation,_In_  INT BaseVertexLocation)
		//rcx 参数1：this结构体对象指针，上下文对象的地址
		//edx 参数2: UINT IndexCount
		//r8d 参数3: UINT StartIndexLocation
		//r9d 参数4：INT BaseVertexLocation
		ID3D11DeviceContext* pContext = (ID3D11DeviceContext*)ExceptionInfo->ContextRecord->Rcx;
		UINT IndexCount = (DWORD)ExceptionInfo->ContextRecord->Rdx;
		UINT StartIndexLocation = (DWORD)ExceptionInfo->ContextRecord->R8;
		UINT BaseVertexLocation = (DWORD)ExceptionInfo->ContextRecord->R9;

		//透视
		if (WallHack_MyDrawIndexed(HardwareBP_Params.pFirstCode, pContext, IndexCount, StartIndexLocation, BaseVertexLocation))
		{
			ResumeCall(ExceptionInfo, HardwareBP_Params.pFirstCode);
		}
		else
		{
			RetCall(ExceptionInfo);
		}
		//异常已处理，继续执行RIP处代码
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	//异常未处理，交由下个VEH处理
	return EXCEPTION_CONTINUE_SEARCH;
}

/*
 * VEH异常处理函数：D3D11-CreateQuery
 * 参数 ExceptionInfo
 */
LONG NTAPI VEH_D3D11CreateQuery(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params)
{
	//只关注单步异常 && 只关注当前函数地址的异常
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP
		&& (DWORD64)ExceptionInfo->ExceptionRecord->ExceptionAddress == (DWORD64)HardwareBP_Params.BreakPointAddress)
	{
		//printf("【info】捕获到CreateQuery的硬件断点异常...\n");

		//CreateQuery函数函数的原型：void __stdcall D3D11CreateQueryHook (ID3D11Device* pDevice, const D3D11_QUERY_DESC *pQueryDesc, ID3D11Query **ppQuery);
		//rcx 参数1：pDevice 对象指针
		//rdx 参数2: pQueryDesc
		//r8  参数3: ppQuery
		pDevice_Game = (ID3D11Device*)ExceptionInfo->ContextRecord->Rcx;
		D3D11_QUERY_DESC* pQueryDesc = (D3D11_QUERY_DESC*)ExceptionInfo->ContextRecord->Rdx;
		ID3D11Query** ppQuery = (ID3D11Query * *)ExceptionInfo->ContextRecord->R8;

		//Disable Occlusion which prevents rendering player models through certain objects
		if (pQueryDesc->Query == D3D11_QUERY_OCCLUSION)
		{
			//printf("【info】禁用遮挡查询...\n");
			//修改描述参数、继续执行
			D3D11_QUERY_DESC oqueryDesc = CD3D11_QUERY_DESC();
			(&oqueryDesc)->MiscFlags = pQueryDesc->MiscFlags;
			(&oqueryDesc)->Query = D3D11_QUERY_TIMESTAMP;
			ExceptionInfo->ContextRecord->Rdx = (DWORD64)& oqueryDesc;
		}

		//继续执行原始函数
		ResumeCall(ExceptionInfo, HardwareBP_Params.pFirstCode);

		//异常已处理，继续执行RIP处代码
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	//交由下个VEH处理
	return EXCEPTION_CONTINUE_SEARCH;
}
/*
 * VEH异常处理函数：GetThreadContext
 * 参数 ExceptionInfo
 */
LONG NTAPI VEH_GetThreadContext(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params)
{
	//只关注当前函数地址的单步异常
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP
		&& (DWORD64)ExceptionInfo->ExceptionRecord->ExceptionAddress == (DWORD64)HardwareBP_Params.BreakPointAddress)
	{
		printf("【info】捕获到GetThreadContext的硬件断点异常..................  \n");
		//继续执行原始函数
		ResumeCall(ExceptionInfo, HardwareBP_Params.pFirstCode);
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	//交由下个VEH处理
	return EXCEPTION_CONTINUE_SEARCH;
}


/*
 * VEH异常处理函数：IsDebuggerPresent
 * 参数 ExceptionInfo
 */
LONG NTAPI VEH_IsDebuggerPresent(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params)
{
	//只关注当前函数地址的单步异常
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP
		&& (DWORD64)ExceptionInfo->ExceptionRecord->ExceptionAddress == (DWORD64)HardwareBP_Params.BreakPointAddress)
	{

		//printf("【info】捕获到IsDebuggerPresent的硬件断点异常 \n");
		//继续执行原始函数
		ResumeCall(ExceptionInfo, HardwareBP_Params.pFirstCode);
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	//交由下个VEH处理
	return EXCEPTION_CONTINUE_SEARCH;
}

/*
 * VEH异常处理函数：D3D11-CreateQuery
 * 参数 ExceptionInfo
 */
LONG NTAPI VEH_CreateQuery(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params)
{
	//只关注单步异常 && 只关注当前函数地址的异常
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP
		&& (DWORD64)ExceptionInfo->ExceptionRecord->ExceptionAddress == (DWORD64)HardwareBP_Params.BreakPointAddress)
	{
		//printf("【info】捕获到CreateQuery的硬件断点异常...\n");

		//CreateQuery函数函数的原型：void __stdcall D3D11CreateQueryHook (ID3D11Device* pDevice, const D3D11_QUERY_DESC *pQueryDesc, ID3D11Query **ppQuery);
		//rcx 参数1：pDevice 对象指针
		//rdx 参数2: pQueryDesc
		//r8  参数3: ppQuery
		pDevice_Game = (ID3D11Device*)ExceptionInfo->ContextRecord->Rcx;
		D3D11_QUERY_DESC* pQueryDesc = (D3D11_QUERY_DESC*)ExceptionInfo->ContextRecord->Rdx;
		ID3D11Query** ppQuery = (ID3D11Query * *)ExceptionInfo->ContextRecord->R8;

		//Disable Occlusion which prevents rendering player models through certain objects
		if (pQueryDesc->Query == D3D11_QUERY_OCCLUSION)
		{
			//printf("【info】禁用遮挡查询...\n");
			//修改描述参数、继续执行
			D3D11_QUERY_DESC oqueryDesc = CD3D11_QUERY_DESC();
			(&oqueryDesc)->MiscFlags = pQueryDesc->MiscFlags;
			(&oqueryDesc)->Query = D3D11_QUERY_TIMESTAMP;
			ExceptionInfo->ContextRecord->Rdx = (DWORD64)& oqueryDesc;
		}
		//继续执行原始函数
		ResumeCall(ExceptionInfo, HardwareBP_Params.pFirstCode);

		//异常已处理，继续执行RIP处代码
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	//交由下个VEH处理
	return EXCEPTION_CONTINUE_SEARCH;
}

/*
 * VEH异常处理函数：D3D11-PSSetShaderResources
 * 参数 ExceptionInfo
 */
LONG NTAPI VEH_PSSetShaderResources(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params)
{
	//只关注当前函数地址的单步异常
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP
		&& (DWORD64)ExceptionInfo->ExceptionRecord->ExceptionAddress == (DWORD64)HardwareBP_Params.BreakPointAddress)
	{
		//printf("【info】捕获到PSSetShaderResources的硬件断点异常...\n");

		//函数原型：void(__stdcall *D3D11PSSetShaderResourcesHook) (ID3D11DeviceContext* pContext, UINT StartSlot, UINT NumViews, ID3D11ShaderResourceView *const *ppShaderResourceViews);
		//rcx 参数1 ：pContext 对象指针
		//rdx 参数2 ：StartSlot 对象指针
		//r8  参数3 ：NumViews 对象指针
		//r9  参数4 ：ppShaderResourceViews 对象指针
		ID3D11DeviceContext* pContext = (ID3D11DeviceContext*)ExceptionInfo->ContextRecord->Rcx;
		UINT StartSlot = ExceptionInfo->ContextRecord->Rdx;
		UINT NumViews = ExceptionInfo->ContextRecord->R8;
		ID3D11ShaderResourceView* const* ppShaderResourceViews = (ID3D11ShaderResourceView * const*)ExceptionInfo->ContextRecord->R9;

		//继续执行原始函数（从原始函数的首句代码被粘贴位置继续执行）
		ResumeCall(ExceptionInfo, HardwareBP_Params.pFirstCode);

		//异常已处理，继续执行RIP处代码
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	//交由下个VEH处理
	return EXCEPTION_CONTINUE_SEARCH;
}

/*
 * VEH异常处理函数：测试...
 * 参数 ExceptionInfo
 */
LONG NTAPI VEH_DEBUG(struct _EXCEPTION_POINTERS* ExceptionInfo, struct HardwareBP_Params HardwareBP_Params)
{
	//触发的是：仅执行断点
	if (ExceptionInfo->ExceptionRecord->ExceptionAddress == HardwareBP_Params.BreakPointAddress)
	{
		printf("【info】捕获DEBUG硬断(仅执行断点)... ExceptionAddress = %p Dr6=%016llx \n", ExceptionInfo->ExceptionRecord->ExceptionAddress, ExceptionInfo->ContextRecord->Dr6);
		printf("[rax=%llX] [rcx=%llX] [rdx=%llX] [rbx=%llX] [rsp=%llX] [rbp=%llX] [rsi=%llX] [rdi=%llX] \n[r8=%llX] [r9=%llX] [r10=%llX] [r11=%llX] [r12=%llX] [r13=%llX] [r14=%llX] [r15=%llX] \n",
			ExceptionInfo->ContextRecord->Rax, ExceptionInfo->ContextRecord->Rcx, ExceptionInfo->ContextRecord->Rdx, ExceptionInfo->ContextRecord->Rbx,
			ExceptionInfo->ContextRecord->Rsp, ExceptionInfo->ContextRecord->Rbp, ExceptionInfo->ContextRecord->Rsi, ExceptionInfo->ContextRecord->Rdi,
			ExceptionInfo->ContextRecord->R8, ExceptionInfo->ContextRecord->R9, ExceptionInfo->ContextRecord->R10, ExceptionInfo->ContextRecord->R11,
			ExceptionInfo->ContextRecord->R12, ExceptionInfo->ContextRecord->R13, ExceptionInfo->ContextRecord->R14, ExceptionInfo->ContextRecord->R15);

		//继续执行原始函数（从原始函数的首句代码被粘贴位置继续执行）
		ResumeCall(ExceptionInfo, HardwareBP_Params.pFirstCode);
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	//触发的是：仅写入断点、读或写断点
	printf("【info】捕获DEBUG硬断(仅写入断点、读或写断点)... ExceptionAddress = %p Dr6=%016llx \n", ExceptionInfo->ExceptionRecord->ExceptionAddress, ExceptionInfo->ContextRecord->Dr6);
	printf("[rax=%llX] [rcx=%llX] [rdx=%llX] [rbx=%llX] [rsp=%llX] [rbp=%llX] [rsi=%llX] [rdi=%llX] \n[r8=%llX] [r9=%llX] [r10=%llX] [r11=%llX] [r12=%llX] [r13=%llX] [r14=%llX] [r15=%llX] \n",
		ExceptionInfo->ContextRecord->Rax, ExceptionInfo->ContextRecord->Rcx, ExceptionInfo->ContextRecord->Rdx, ExceptionInfo->ContextRecord->Rbx,
		ExceptionInfo->ContextRecord->Rsp, ExceptionInfo->ContextRecord->Rbp, ExceptionInfo->ContextRecord->Rsi, ExceptionInfo->ContextRecord->Rdi,
		ExceptionInfo->ContextRecord->R8, ExceptionInfo->ContextRecord->R9, ExceptionInfo->ContextRecord->R10, ExceptionInfo->ContextRecord->R11,
		ExceptionInfo->ContextRecord->R12, ExceptionInfo->ContextRecord->R13, ExceptionInfo->ContextRecord->R14, ExceptionInfo->ContextRecord->R15);
	return EXCEPTION_CONTINUE_EXECUTION;

}