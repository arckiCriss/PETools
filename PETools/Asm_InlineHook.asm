.CODE

;masn����16����Ҫ�ú�׺h������ǰ׺0x
;rcx�ǵ�1������ �洢��ȫ�ֱ����ṹ��ĵ�ַ
;[ջ��-8]������͵͵�����rcx��ԭʼֵ�������򴫲�ʱʹ��rcx����ʧrcx��ԭֵ
ASM_SaveReg PROC
	MOV qword ptr[rcx-0h],rax		;��rax����ȫ�ֱ����ṹ��ĵ� 1����Ա
	MOV qword ptr[rcx+8h],rbx		;��rbx����ȫ�ֱ����ṹ��ĵ� 2����Ա
	MOV qword ptr[rcx+18h],rdx		;��rdx����ȫ�ֱ����ṹ��ĵ� 4����Ա
	MOV qword ptr[rcx+20h],rsi		;��rsi����ȫ�ֱ����ṹ��ĵ� 5����Ա
	MOV qword ptr[rcx+28h],rdi		;��rdi����ȫ�ֱ����ṹ��ĵ� 6����Ա
	MOV qword ptr[rcx+38h],rbp		;��rbp����ȫ�ֱ����ṹ��ĵ� 8����Ա
	MOV qword ptr[rcx+40h],r8		;��r8 ����ȫ�ֱ����ṹ��ĵ� 9����Ա
	MOV qword ptr[rcx+48h],r9		;��r9 ����ȫ�ֱ����ṹ��ĵ�10����Ա
	MOV qword ptr[rcx+50h],r10		;��r10����ȫ�ֱ����ṹ��ĵ�11����Ա
	MOV qword ptr[rcx+58h],r11		;��r11����ȫ�ֱ����ṹ��ĵ�12����Ա
	MOV qword ptr[rcx+60h],r12		;��r12����ȫ�ֱ����ṹ��ĵ�13����Ա
	MOV qword ptr[rcx+68h],r13		;��r13����ȫ�ֱ����ṹ��ĵ�14����Ա
	MOV qword ptr[rcx+70h],r14		;��r14����ȫ�ֱ����ṹ��ĵ�15����Ա
	MOV qword ptr[rcx+78h],r15		;��r15����ȫ�ֱ����ṹ��ĵ�16����Ա [���ˣ����ϼĴ������Ա�����ʹ��]
	POP rax							;���������ص���ַ����rax    [rsp+8����ʱ��rsp=ԭʼ������ԭrsp]	 
	MOV qword ptr[rcx+30h],rsp		;����ԭʼ������rsp
	PUSH rax						;���»ָ��������Ļص���ַ	[rsp-8����ʱ��rsp=��ǰ��������ʱ��rsp]
	MOV rbx	,[rsp-8]				;��ԭʼ����rcx��ֵȡ��
	MOV qword ptr[rcx+10h],rbx		;��ԭʼ����rcx��ֵ����				 [���ˣ�ջ��+8��͵͵��ŵ�ԭrcxֵʹ�����] 
	PUSHF							;����16λ�ı�־�Ĵ�����ջ��ջ��ָ��+2
	POP word ptr[rcx+80h]			;��־�Ĵ�����ջ������ṹ��ĵ�16����Ա (��word��ջ�����ֶ�ջƽ��)
									;[���ˣ��ѱ�������ԭ������Ϣ]
	SUB rsp,140h					;>>>������ջ>>>
										;1.ȷ��λ��[ջ��+8]����ԭ�����ص���ַ���ᱻ�Ժ���õĺ����ƻ���rsp-140h 
										;2.ȷ������������ʱrsp��ֵ��16�ֽڶ��루��0x10����������,�������һ���к���ִ��movapָ��ͻ��쳣��
	PUSH rax						;���������ص���ַ��ջ��rsp-8
	RET								;���أ�rsp+8
ASM_SaveReg ENDP 


;masn����16����Ҫ�ú�׺h������ǰ׺0x
;rcx�ǵ�1������ �洢��ȫ�ֱ����ṹ��ĵ�ַ
;rdx�ǵ�2������ �洢��ԭʼ���������Ǵ����ճ��λ��
ASM_RecoverReg PROC
	ADD rsp,140h			;>>>��ջ>>>������ASM_SaveReg()�����Ķ�ջ		[��ʱ,rsp=ASM_SaveReg����ʱ��rsp-8 = ԭʼ������rsp-16]
	ADD rsp,8h				;��Ϊ������CALLʱ������һ�ζ�ջ�������ٽ��Ͷ�ջ [��ʱ,rsp=ASM_SaveReg����ʱ��rsp   = ԭʼ������rsp- 8]
	MOV rax, [rcx+0h]		;�Ȼָ�����rdx��rcx��rsp��rfl������мĴ�����ֵ
	MOV rbx, [rcx+8h]		;�Ȼָ�����rdx��rcx��rsp��rfl������мĴ�����ֵ
	MOV rsi, [rcx+20h]		;�Ȼָ�����rdx��rcx��rsp��rfl������мĴ�����ֵ
	MOV rdi, [rcx+28h]		;�Ȼָ�����rdx��rcx��rsp��rfl������мĴ�����ֵ
	MOV rbp, [rcx+38h]		;�Ȼָ�����rdx��rcx��rsp��rfl������мĴ�����ֵ
	MOV  r8, [rcx+40h]		;�Ȼָ�����rdx��rcx��rsp��rfl������мĴ�����ֵ
	MOV  r9, [rcx+48h]		;�Ȼָ�����rdx��rcx��rsp��rfl������мĴ�����ֵ
	MOV r10, [rcx+50h]		;�Ȼָ�����rdx��rcx��rsp��rfl������мĴ�����ֵ
	MOV r11, [rcx+58h]		;�Ȼָ�����rdx��rcx��rsp��rfl������мĴ�����ֵ
	MOV r12, [rcx+60h]		;�Ȼָ�����rdx��rcx��rsp��rfl������мĴ�����ֵ
	MOV r13, [rcx+68h]		;�Ȼָ�����rdx��rcx��rsp��rfl������мĴ�����ֵ
	MOV r14, [rcx+70h]		;�Ȼָ�����rdx��rcx��rsp��rfl������мĴ�����ֵ
	MOV r15, [rcx+78h]		;�Ȼָ�����rdx��rcx��rsp��rfl������мĴ�����ֵ
	MOV [rsp],rax			;���ǵ�ǰ�����ص���ַΪraxֵ
	PUSH rax				;����1�ζ�ջ��ѹ��rax		ջ��-8
	ADD rsp,6h				;Ϊ��ƽ��POPF				ջ��+6
	PUSH [rcx+80h]			;rfl��ջ					ջ��-8		
	POPF					;rfl��ջ					ջ��+2
	POP rax					;����1�ζ�ջ��rax��ԭ		ջ��+8	[���ˣ���ǰ������ջƽ��]
	POP rax					;����2�ζ�ջ��rax��ԭ		ջ��+8  [���ˣ�ԭʼ������ջƽ��]
	PUSH rdx				;��Ҫ��ת�ĵ�ֵַ��ջ				[���ˣ���1������ʹ�����]
	MOV rdx, [rcx+18h]		;�ָ�rdx							[���ˣ���2������ʹ�����]
	MOV rcx, [rcx+10h]		;�ָ�rcx							[���ˣ�ԭʼ�����Ĵ����ѻָ�]
	RET						;��ret��ת��ԭʼ����				[���ˣ�ԭʼ������ջ��ƽ��]
ASM_RecoverReg ENDP 


;**
 ;* ֱ�ӽ���ԭ����
 ;* ����1 rcx ȫ�ֱ����ṹ��ĵ�ַ
;**
ASM_EndOrigin PROC
	ADD rsp,140h ;������ASM_SaveReg���������Ķ�ջ
	ADD rsp,8h	 ;�����ɱ��������������Ķ�ջ ����ʱrsp=ASM_SaveReg����ʱ��rsp=ԭʼ������rsp-8
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
