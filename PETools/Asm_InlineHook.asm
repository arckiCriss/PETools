.CODE

;masn里面16进制要用后缀h，不能前缀0x
;rcx是第1个参数 存储了全局变量结构体的地址
;[栈顶-8]处事先偷偷存放了rcx的原始值，避免因传参时使用rcx而丢失rcx的原值
ASM_SaveReg PROC
	MOV qword ptr[rcx-0h],rax		;将rax存入全局变量结构体的第 1个成员
	MOV qword ptr[rcx+8h],rbx		;将rbx存入全局变量结构体的第 2个成员
	MOV qword ptr[rcx+18h],rdx		;将rdx存入全局变量结构体的第 4个成员
	MOV qword ptr[rcx+20h],rsi		;将rsi存入全局变量结构体的第 5个成员
	MOV qword ptr[rcx+28h],rdi		;将rdi存入全局变量结构体的第 6个成员
	MOV qword ptr[rcx+38h],rbp		;将rbp存入全局变量结构体的第 8个成员
	MOV qword ptr[rcx+40h],r8		;将r8 存入全局变量结构体的第 9个成员
	MOV qword ptr[rcx+48h],r9		;将r9 存入全局变量结构体的第10个成员
	MOV qword ptr[rcx+50h],r10		;将r10存入全局变量结构体的第11个成员
	MOV qword ptr[rcx+58h],r11		;将r11存入全局变量结构体的第12个成员
	MOV qword ptr[rcx+60h],r12		;将r12存入全局变量结构体的第13个成员
	MOV qword ptr[rcx+68h],r13		;将r13存入全局变量结构体的第14个成员
	MOV qword ptr[rcx+70h],r14		;将r14存入全局变量结构体的第15个成员
	MOV qword ptr[rcx+78h],r15		;将r15存入全局变量结构体的第16个成员 [至此，以上寄存器可以被正常使用]
	POP rax							;将本函数回调地址存入rax    [rsp+8，此时的rsp=原始函数的原rsp]	 
	MOV qword ptr[rcx+30h],rsp		;存入原始函数的rsp
	PUSH rax						;重新恢复本函数的回调地址	[rsp-8，此时的rsp=当前函数调用时的rsp]
	MOV rbx	,[rsp-8]				;将原始函数rcx的值取出
	MOV qword ptr[rcx+10h],rbx		;将原始函数rcx的值存入				 [至此，栈顶+8处偷偷存放的原rcx值使用完毕] 
	PUSHF							;将低16位的标志寄存器入栈，栈顶指针+2
	POP word ptr[rcx+80h]			;标志寄存器出栈，存入结构体的第16个成员 (以word出栈，保持堆栈平衡)
									;[至此，已保存所有原函数信息]
	SUB rsp,140h					;>>>提升堆栈>>>
										;1.确保位于[栈顶+8]处的原函数回调地址不会被以后调用的函数破坏，rsp-140h 
										;2.确保本函数返回时rsp的值是16字节对齐（即0x10的整数倍）,否则后续一旦有函数执行movap指令就会异常。
	PUSH rax						;将本函数回调地址入栈，rsp-8
	RET								;返回，rsp+8
ASM_SaveReg ENDP 


;masn里面16进制要用后缀h，不能前缀0x
;rcx是第1个参数 存储了全局变量结构体的地址
;rdx是第2个参数 存储了原始函数被覆盖代码的粘贴位置
ASM_RecoverReg PROC
	ADD rsp,140h			;>>>堆栈>>>降低由ASM_SaveReg()提升的堆栈		[此时,rsp=ASM_SaveReg调用时的rsp-8 = 原始函数的rsp-16]
	ADD rsp,8h				;因为本函数CALL时又提升一次堆栈，所以再降低堆栈 [此时,rsp=ASM_SaveReg调用时的rsp   = 原始函数的rsp- 8]
	MOV rax, [rcx+0h]		;先恢复除了rdx、rcx、rsp、rfl外的所有寄存器的值
	MOV rbx, [rcx+8h]		;先恢复除了rdx、rcx、rsp、rfl外的所有寄存器的值
	MOV rsi, [rcx+20h]		;先恢复除了rdx、rcx、rsp、rfl外的所有寄存器的值
	MOV rdi, [rcx+28h]		;先恢复除了rdx、rcx、rsp、rfl外的所有寄存器的值
	MOV rbp, [rcx+38h]		;先恢复除了rdx、rcx、rsp、rfl外的所有寄存器的值
	MOV  r8, [rcx+40h]		;先恢复除了rdx、rcx、rsp、rfl外的所有寄存器的值
	MOV  r9, [rcx+48h]		;先恢复除了rdx、rcx、rsp、rfl外的所有寄存器的值
	MOV r10, [rcx+50h]		;先恢复除了rdx、rcx、rsp、rfl外的所有寄存器的值
	MOV r11, [rcx+58h]		;先恢复除了rdx、rcx、rsp、rfl外的所有寄存器的值
	MOV r12, [rcx+60h]		;先恢复除了rdx、rcx、rsp、rfl外的所有寄存器的值
	MOV r13, [rcx+68h]		;先恢复除了rdx、rcx、rsp、rfl外的所有寄存器的值
	MOV r14, [rcx+70h]		;先恢复除了rdx、rcx、rsp、rfl外的所有寄存器的值
	MOV r15, [rcx+78h]		;先恢复除了rdx、rcx、rsp、rfl外的所有寄存器的值
	MOV [rsp],rax			;覆盖当前函数回调地址为rax值
	PUSH rax				;提升1次堆栈，压入rax		栈顶-8
	ADD rsp,6h				;为了平衡POPF				栈顶+6
	PUSH [rcx+80h]			;rfl入栈					栈顶-8		
	POPF					;rfl出栈					栈顶+2
	POP rax					;降低1次堆栈，rax还原		栈顶+8	[至此，当前函数堆栈平衡]
	POP rax					;降低2次堆栈，rax还原		栈顶+8  [至此，原始函数堆栈平衡]
	PUSH rdx				;把要跳转的地址值入栈				[至此，第1个参数使用完毕]
	MOV rdx, [rcx+18h]		;恢复rdx							[至此，第2个参数使用完毕]
	MOV rcx, [rcx+10h]		;恢复rcx							[至此，原始函数寄存器已恢复]
	RET						;以ret跳转至原始函数				[至此，原始函数堆栈已平衡]
ASM_RecoverReg ENDP 


;**
 ;* 直接结束原函数
 ;* 参数1 rcx 全局变量结构体的地址
;**
ASM_EndOrigin PROC
	ADD rsp,140h ;降低由ASM_SaveReg函数提升的堆栈
	ADD rsp,8h	 ;降低由本函数调用提升的堆栈 ，此时rsp=ASM_SaveReg调用时的rsp=原始函数的rsp-8
	MOV rax, [rcx+0h]		
	MOV rbx, [rcx+8h]		
	MOV rdx, [rcx+18h]
	MOV rsi, [rcx+20h]		
	MOV rdi, [rcx+28h]		
	MOV rbp, [rcx+38h]		
	MOV  r8, [rcx+40h]		
	MOV  r9, [rcx+48h]		
	MOV r10, [rcx+50h]		
	MOV r11, [rcx+58h]		
	MOV r12, [rcx+60h]		
	MOV r13, [rcx+68h]		
	MOV r14, [rcx+70h]		
	MOV r15, [rcx+78h]		
	MOV [rsp],rax			
	PUSH rax				
	ADD rsp,6h				
	PUSH [rcx+80h]				
	POPF					
	POP rax					
	POP rax					
	MOV rcx, [rcx+10h]		
	ret
ASM_EndOrigin ENDP

END
