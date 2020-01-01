 AREA FIXEDBYFRAC_S, CODE, READONLY
 
 CODE32
 EXPORT FixedByFrac
 EXPORT isLittleEndian
 
FixedByFrac PROC
	SMULL r2, r3,r0,r1;
	MOV r0, r2, LSR #16;
	ORR r0, r0, r3, LSL #16;
	bx lr
	ENDP
	
isLittleEndian PROC
        STMFD    sp!,{r3,lr}
        MOV      r0,#1
        STR      r0,[sp,#0]
        LDRB     r0,[sp,#0]
        LDMFD    sp!,{r3,pc}
        ENDP
        
        
	END
