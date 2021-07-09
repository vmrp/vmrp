
        @ gcc asm
	.arch armv5te
	.arm

	.global globalValue
globalValue:
        add r1,pc,#0x04 @r1存放数据的地址
        add r2,pc,#0x04
        mov pc,r2
        mov r0,r0 @数据，这条指令占用4字节内存用来当成全局变量用，但是在linux系统下，由于代码段是只读的，所以是无法运行的
        cmp r0,#0x00
        addne pc,pc,#0x4
        ldr r0,[r1] @如果传参数为null，则获取值
        bx lr
        str r0,[r1] @如果参数不为null，则存入值
        bx lr
