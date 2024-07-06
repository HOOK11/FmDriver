extern halCounterQueryRoutine:DQ
extern keQueryPerformanceCounterHook:DQ
.code
checkLogger PROC
	push rcx
	mov rcx,rsp
	lea rax,keQueryPerformanceCounterHook
	call rax
	pop rax
	mov rax,halCounterQueryRoutine
	jmp rax
checkLogger ENDP
end
