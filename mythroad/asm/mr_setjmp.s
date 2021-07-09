
	IMPORT mr_setjmp_buf

	AREA MR_SETJMP, CODE, READONLY
	
	CODE32
	EXPORT mr_longjmp
mr_longjmp PROC
	ldr r1, =MR_REG
	ldr r1, [r1]
	ldmia r1, {r0-r14}
	
	mov r1, #1
	bx r14
	
	
	ENDP
	
	EXPORT mr_setjmp
mr_setjmp PROC
	
	ldr r1, =MR_REG
	ldr r1, [r1]
	stmia r1, {r0-r14}
	mov r1, #0
	bx r14
	
	ENDP
	
;AREA Strings, DATA, READWRITE
MR_REG
	DCD mr_setjmp_buf

	END

