code:  0x80000 - 0x180000
    mr_table: 0x80000
    mr_c_function: 0x80004
stack: 0x280000 - 0x180000  向下生长
bridge: 0x280000 - 0x281000
    *mr_table:[0x280000]
    *mr_c_function:[0x280248]
    *mrc_extChunk:[0x28025c]
    endAddress:[0x280290]

heap:  0x281000 - 0x381000  向上生长

mr_helper函数： 0x80550

       8:	e92d4038 	push	{r3, r4, r5, lr}
       c:	e59f410c 	ldr	r4, [pc, #268]	; 0x120
      10:	e08f4004 	add	r4, pc, r4
      14:	e5141008 	ldr	r1, [r4, #-8] ; r1是mr_table地址
      18:	e3500001 	cmp	r0, #1
      1c:	e5912064 	ldr	r2, [r1, #100]	; 0x64 r2是_mr_c_function_new地址
      20:	e3a01014 	mov	r1, #20
      24:	1a00000f 	bne	0x68 ; 0x18处传了1此处不跳转
      28:	e59f00f4 	ldr	r0, [pc, #244]	; 0x124
      2c:	e08f0000 	add	r0, pc, r0 ; r0此时是mr_helper函数指针0x80550
      30:	e12fff32 	blx	r2 ; 跳转_mr_c_function_new
      34:	e3700001 	cmn	r0, #1
      38:	0a000036 	beq	0x118 ; _mr_c_function_new 返回0表示成功，此处不跳转
      3c:	e5141004 	ldr	r1, [r4, #-4] ; mr_c_function 地址
      40:	e3a00001 	mov	r0, #1
      44:	e5810008 	str	r0, [r1, #8] ; mr_c_function.ext_type = 1
      48:	e59f00d8 	ldr	r0, [pc, #216]	; 0x128
      4c:	e08f0000 	add	r0, pc, r0
      50:	e5141008 	ldr	r1, [r4, #-8]
      54:	e581007c 	str	r0, [r1, #124]	; 0x7c mr_table.g_mr_timerStart=0x8064c
      58:	e59f00cc 	ldr	r0, [pc, #204]	; 0x12c
      5c:	e08f0000 	add	r0, pc, r0
      60:	e5810080 	str	r0, [r1, #128]	; 0x80 mr_table.g_mr_timerStop=0x80680
      64:	ea000007 	b	0x88
      68:	e59f00c0 	ldr	r0, [pc, #192]	; 0x130
      6c:	e08f0000 	add	r0, pc, r0
      70:	e12fff32 	blx	r2
      74:	e3700001 	cmn	r0, #1
      78:	0a000026 	beq	0x118
      7c:	e5141004 	ldr	r1, [r4, #-4]
      80:	e3a00000 	mov	r0, #0
      84:	e5810008 	str	r0, [r1, #8]
      88:	eb000032 	bl	0x158
      8c:	e5141004 	ldr	r1, [r4, #-4]
      90:	e5810004 	str	r0, [r1, #4] ; mr_c_function.ER_RW_Length=0x104
      94:	eb0001df 	bl	0x818
      98:	e5141004 	ldr	r1, [r4, #-4]
      9c:	e3500000 	cmp	r0, #0
      a0:	e5810000 	str	r0, [r1] ; mr_c_function.start_of_ER_RW=0x281004(申请的内存地址+4)
      a4:	0a00001b 	beq	0x118 ; 不跳
      a8:	eb000032 	bl	0x178  ;直接看到ac就行了不用跟过去
      ac:	e1a05000 	mov	r5, r0 ; r5=4
      b0:	eb000033 	bl	0x184
      b4:	e0801004 	add	r1, r0, r4
      b8:	e5140004 	ldr	r0, [r4, #-4]
      bc:	e5142008 	ldr	r2, [r4, #-8]
      c0:	e5900000 	ldr	r0, [r0] ; r0=mr_c_function.start_of_ER_RW
      c4:	e592300c 	ldr	r3, [r2, #12]
      c8:	e1a02005 	mov	r2, r5
      cc:	e12fff33 	blx	r3 ; 调用memcpy(mr_c_function.start_of_ER_RW, 0x81130, 4) ;0x81130处4字节都是0
      d0:	eb000028 	bl	0x178 ; 178处的功能只是将r0=4
      d4:	e5141004 	ldr	r1, [r4, #-4]
      d8:	e5911004 	ldr	r1, [r1, #4] ; r1=mr_c_function.ER_RW_Length
      dc:	e0415000 	sub	r5, r1, r0 ;r5=0x100
      e0:	eb000024 	bl	0x178
      e4:	e5141004 	ldr	r1, [r4, #-4]
      e8:	e1a02005 	mov	r2, r5
      ec:	e5911000 	ldr	r1, [r1] ;r1=mr_c_function.start_of_ER_RW
      f0:	e0800001 	add	r0, r0, r1 ;r0=r1+4(0x281008)
      f4:	e5141008 	ldr	r1, [r4, #-8]
      f8:	e5913038 	ldr	r3, [r1, #56]	; 0x38 memset
      fc:	e3a01000 	mov	r1, #0
     100:	e12fff33 	blx	r3 ; memset(0x281008, 0, 0x100)
     104:	e5140004 	ldr	r0, [r4, #-4]
     108:	e5900000 	ldr	r0, [r0] ;r0=mr_c_function.start_of_ER_RW
     10c:	e3500000 	cmp	r0, #0
     110:	13a00000 	movne	r0, #0 ; r0=0
     114:	1a000000 	bne	0x11c ;跳转
     118:	e3e00000 	mvn	r0, #0
     11c:	e8bd8038 	pop	{r3, r4, r5, pc} ;完成mr_c_function_load()调用，即0x80000的完整调用
     120:	fffffff0 			; <UNDEFINED> instruction: 0xfffffff0
     124:	0000051c 	andeq	r0, r0, ip, lsl r5
     128:	000005f8 	strdeq	r0, [r0], -r8
     12c:	0000061c 	andeq	r0, r0, ip, lsl r6
     130:	0000021c 	andeq	r0, r0, ip, lsl r2
     134:	e0c32190 	smull	r2, r3, r0, r1  ; FixedByFrac函数
     138:	e1a00822 	lsr	r0, r2, #16
     13c:	e1800803 	orr	r0, r0, r3, lsl #16
     140:	e12fff1e 	bx	lr
     144:	e92d4008 	push	{r3, lr} ; isLittleEndian函数
     148:	e3a00001 	mov	r0, #1
     14c:	e58d0000 	str	r0, [sp]
     150:	e5dd0000 	ldrb	r0, [sp]
     154:	e8bd8008 	pop	{r3, pc}
     158:	e59f0008 	ldr	r0, [pc, #8]	; 0x168
     15c:	e59f1008 	ldr	r1, [pc, #8]	; 0x16c
     160:	e0800001 	add	r0, r0, r1
     164:	e12fff1e 	bx	lr
     168:	00000004 	andeq	r0, r0, r4
     16c:	00000100 	andeq	r0, r0, r0, lsl #2
     170:	e1a09000 	mov	r9, r0
     174:	e12fff1e 	bx	lr
     178:	e59f0000 	ldr	r0, [pc]	; 0x180
     17c:	e12fff1e 	bx	lr
     180:	00000004 	andeq	r0, r0, r4
     184:	e59f0000 	ldr	r0, [pc]	; 0x18c
     188:	e12fff1e 	bx	lr
     18c:	00001128 	andeq	r1, r0, r8, lsr #2
     190:	e92d4010 	push	{r4, lr}
     194:	eb0001ed 	bl	0x950
     198:	e59f40dc 	ldr	r4, [pc, #220]	; 0x27c
     19c:	e3a00001 	mov	r0, #1
     1a0:	e0844009 	add	r4, r4, r9
     1a4:	e5840018 	str	r0, [r4, #24]
     1a8:	e59f00d0 	ldr	r0, [pc, #208]	; 0x280
     1ac:	e08f0000 	add	r0, pc, r0
     1b0:	e5100008 	ldr	r0, [r0, #-8]
     1b4:	e59f20c8 	ldr	r2, [pc, #200]	; 0x284
     1b8:	e5901068 	ldr	r1, [r0, #104]	; 0x68
     1bc:	e0822009 	add	r2, r2, r9
     1c0:	e584102c 	str	r1, [r4, #44]	; 0x2c
     1c4:	e590100c 	ldr	r1, [r0, #12]
     1c8:	e5841030 	str	r1, [r4, #48]	; 0x30
     1cc:	e5901010 	ldr	r1, [r0, #16]
     1d0:	e5841034 	str	r1, [r4, #52]	; 0x34
     1d4:	e5901014 	ldr	r1, [r0, #20]
     1d8:	e5841038 	str	r1, [r4, #56]	; 0x38
     1dc:	e5901018 	ldr	r1, [r0, #24]
     1e0:	e584103c 	str	r1, [r4, #60]	; 0x3c
     1e4:	e590101c 	ldr	r1, [r0, #28]
     1e8:	e5841040 	str	r1, [r4, #64]	; 0x40
     1ec:	e5901020 	ldr	r1, [r0, #32]
     1f0:	e5841044 	str	r1, [r4, #68]	; 0x44
     1f4:	e5901024 	ldr	r1, [r0, #36]	; 0x24
     1f8:	e5841048 	str	r1, [r4, #72]	; 0x48
     1fc:	e5901028 	ldr	r1, [r0, #40]	; 0x28
     200:	e584104c 	str	r1, [r4, #76]	; 0x4c
     204:	e590102c 	ldr	r1, [r0, #44]	; 0x2c
     208:	e5841050 	str	r1, [r4, #80]	; 0x50
     20c:	e5901030 	ldr	r1, [r0, #48]	; 0x30
     210:	e5841054 	str	r1, [r4, #84]	; 0x54
     214:	e5901034 	ldr	r1, [r0, #52]	; 0x34
     218:	e5841058 	str	r1, [r4, #88]	; 0x58
     21c:	e5901038 	ldr	r1, [r0, #56]	; 0x38
     220:	e584105c 	str	r1, [r4, #92]	; 0x5c
     224:	e590103c 	ldr	r1, [r0, #60]	; 0x3c
     228:	e5841060 	str	r1, [r4, #96]	; 0x60
     22c:	e5901040 	ldr	r1, [r0, #64]	; 0x40
     230:	e5841064 	str	r1, [r4, #100]	; 0x64
     234:	e5901044 	ldr	r1, [r0, #68]	; 0x44
     238:	e5841068 	str	r1, [r4, #104]	; 0x68
     23c:	e5901048 	ldr	r1, [r0, #72]	; 0x48
     240:	e584106c 	str	r1, [r4, #108]	; 0x6c
     244:	e590104c 	ldr	r1, [r0, #76]	; 0x4c
     248:	e5841070 	str	r1, [r4, #112]	; 0x70
     24c:	e3a01000 	mov	r1, #0
     250:	e5821000 	str	r1, [r2]
     254:	e5903208 	ldr	r3, [r0, #520]	; 0x208 r3=_mr_TestCom
     258:	e3a00000 	mov	r0, #0
     25c:	e59f2024 	ldr	r2, [pc, #36]	; 0x288
     260:	e3a01007 	mov	r1, #7
     264:	e12fff33 	blx	r3 ; _mr_TestCom(0,7,0x270f)
     268:	e240cd9c 	sub	ip, r0, #156, 26	; 0x2700
     26c:	e25cc00f 	subs	ip, ip, #15
     270:	059f0014 	ldreq	r0, [pc, #20]	; 0x28c
     274:	05840028 	streq	r0, [r4, #40]	; 0x28
     278:	e8bd8010 	pop	{r4, pc}
     27c:	00000004 	andeq	r0, r0, r4
     280:	fffffe54 			; <UNDEFINED> instruction: 0xfffffe54
     284:	00000100 	andeq	r0, r0, r0, lsl #2
     288:	0000270f 	andeq	r2, r0, pc, lsl #14
     28c:	0000270d 	andeq	r2, r0, sp, lsl #14
     290:	e92d45fe 	push	{r1, r2, r3, r4, r5, r6, r7, r8, sl, lr}
     294:	e1a06000 	mov	r6, r0
     298:	e5900000 	ldr	r0, [r0]
     29c:	e1a0a009 	mov	sl, r9
     2a0:	e1a08003 	mov	r8, r3
     2a4:	e1a07001 	mov	r7, r1
     2a8:	e1a05002 	mov	r5, r2
     2ac:	e3a04000 	mov	r4, #0
     2b0:	ebffffae 	bl	0x170
     2b4:	e59f00f0 	ldr	r0, [pc, #240]	; 0x3ac
     2b8:	e3570009 	cmp	r7, #9
     2bc:	e0800009 	add	r0, r0, r9
     2c0:	908ff107 	addls	pc, pc, r7, lsl #2
     2c4:	ea000035 	b	0x3a0
     2c8:	ea000008 	b	0x2f0
     2cc:	ea000016 	b	0x32c
     2d0:	ea00001e 	b	0x350
     2d4:	ea000031 	b	0x3a0
     2d8:	ea00001e 	b	0x358
     2dc:	ea00001f 	b	0x360
     2e0:	ea000021 	b	0x36c
     2e4:	ea00002d 	b	0x3a0
     2e8:	ea000021 	b	0x374
     2ec:	ea000022 	b	0x37c
     2f0:	e596100c 	ldr	r1, [r6, #12]
     2f4:	e5801014 	str	r1, [r0, #20]
     2f8:	ebffffa4 	bl	0x190
     2fc:	eb0000f3 	bl	0x6d0
     300:	e1a04000 	mov	r4, r0
     304:	eb000169 	bl	0x8b0
     308:	e59f00a0 	ldr	r0, [pc, #160]	; 0x3b0
     30c:	e08f0000 	add	r0, pc, r0
     310:	e59f109c 	ldr	r1, [pc, #156]	; 0x3b4
     314:	e08f1001 	add	r1, pc, r1
     318:	e5111008 	ldr	r1, [r1, #-8]
     31c:	e591105c 	ldr	r1, [r1, #92]	; 0x5c
     320:	e5911010 	ldr	r1, [r1, #16]
     324:	e5810000 	str	r0, [r1]
     328:	ea00001c 	b	0x3a0
     32c:	e8950007 	ldm	r5, {r0, r1, r2}
     330:	eb00005b 	bl	0x4a4
     334:	e1a04000 	mov	r4, r0
     338:	e5950000 	ldr	r0, [r5]
     33c:	e3500008 	cmp	r0, #8
     340:	1a000007 	bne	0x364
     344:	eb00007f 	bl	0x548
     348:	e1a04000 	mov	r4, r0
     34c:	ea000004 	b	0x364
     350:	eb00023d 	bl	0xc4c
     354:	ea000002 	b	0x364
     358:	eb00013a 	bl	0x848
     35c:	ea000000 	b	0x364
     360:	eb000178 	bl	0x948
     364:	eb000151 	bl	0x8b0
     368:	ea00000c 	b	0x3a0
     36c:	e580801c 	str	r8, [r0, #28]
     370:	ea00000a 	b	0x3a0
     374:	e5805020 	str	r5, [r0, #32]
     378:	ea000008 	b	0x3a0
     37c:	e595c000 	ldr	ip, [r5]
     380:	e35c0000 	cmp	ip, #0
     384:	0a000005 	beq	0x3a0
     388:	e5952014 	ldr	r2, [r5, #20]
     38c:	e5953018 	ldr	r3, [r5, #24]
     390:	e88d000c 	stm	sp, {r2, r3}
     394:	e995000f 	ldmib	r5, {r0, r1, r2, r3}
     398:	e12fff3c 	blx	ip
     39c:	e1a04000 	mov	r4, r0
     3a0:	e1a0900a 	mov	r9, sl
     3a4:	e1a00004 	mov	r0, r4
     3a8:	e8bd85fe 	pop	{r1, r2, r3, r4, r5, r6, r7, r8, sl, pc}
     3ac:	00000004 	andeq	r0, r0, r4
     3b0:	00000bc4 	andeq	r0, r0, r4, asr #23
     3b4:	fffffcec 			; <UNDEFINED> instruction: 0xfffffcec
     3b8:	e92d400e 	push	{r1, r2, r3, lr}
     3bc:	e20230ff 	and	r3, r2, #255	; 0xff
     3c0:	e20120ff 	and	r2, r1, #255	; 0xff
     3c4:	e20010ff 	and	r1, r0, #255	; 0xff
     3c8:	e59f003c 	ldr	r0, [pc, #60]	; 0x40c
     3cc:	e08f0000 	add	r0, pc, r0
     3d0:	e88d000e 	stm	sp, {r1, r2, r3}
     3d4:	e5100008 	ldr	r0, [r0, #-8]
     3d8:	e5901174 	ldr	r1, [r0, #372]	; 0x174 r1=&mr_table.mr_screen_h
     3dc:	e5911000 	ldr	r1, [r1] ; r1=屏幕高度
     3e0:	e1a03801 	lsl	r3, r1, #16
     3e4:	e5901170 	ldr	r1, [r0, #368]	; 0x170 r1=&mr_table.mr_screen_w
     3e8:	e1a03843 	asr	r3, r3, #16
     3ec:	e5911000 	ldr	r1, [r1] ; r1=屏幕宽度
     3f0:	e590c1e8 	ldr	ip, [r0, #488]	; 0x1e8
     3f4:	e1a02801 	lsl	r2, r1, #16
     3f8:	e1a02842 	asr	r2, r2, #16
     3fc:	e3a01000 	mov	r1, #0
     400:	e3a00000 	mov	r0, #0
     404:	e12fff3c 	blx	ip
     408:	e8bd800e 	pop	{r1, r2, r3, pc}
     40c:	fffffc34 			; <UNDEFINED> instruction: 0xfffffc34
     410:	e92d403e 	push	{r1, r2, r3, r4, r5, lr}
     414:	e1a05003 	mov	r5, r3
     418:	e28d3018 	add	r3, sp, #24
     41c:	e1a0e001 	mov	lr, r1
     420:	e1a04002 	mov	r4, r2
     424:	e893000e 	ldm	r3, {r1, r2, r3}
     428:	e88d000e 	stm	sp, {r1, r2, r3}
     42c:	e59f101c 	ldr	r1, [pc, #28]	; 0x450
     430:	e08f1001 	add	r1, pc, r1
     434:	e5111008 	ldr	r1, [r1, #-8]
     438:	e1a03005 	mov	r3, r5
     43c:	e591c1e8 	ldr	ip, [r1, #488]	; 0x1e8
     440:	e1a0100e 	mov	r1, lr
     444:	e1a02004 	mov	r2, r4
     448:	e12fff3c 	blx	ip
     44c:	e8bd803e 	pop	{r1, r2, r3, r4, r5, pc}
     450:	fffffbd0 			; <UNDEFINED> instruction: 0xfffffbd0
     454:	e92d407f 	push	{r0, r1, r2, r3, r4, r5, r6, lr}
     458:	e1a06003 	mov	r6, r3
     45c:	e28d3020 	add	r3, sp, #32
     460:	e1a0e000 	mov	lr, r0
     464:	e1a05002 	mov	r5, r2
     468:	e1a04001 	mov	r4, r1
     46c:	e893000f 	ldm	r3, {r0, r1, r2, r3}
     470:	e88d000f 	stm	sp, {r0, r1, r2, r3}
     474:	e59f0024 	ldr	r0, [pc, #36]	; 0x4a0
     478:	e08f0000 	add	r0, pc, r0
     47c:	e5100008 	ldr	r0, [r0, #-8]
     480:	e1a03006 	mov	r3, r6
     484:	e590c1ec 	ldr	ip, [r0, #492]	; 0x1ec
     488:	e1a0000e 	mov	r0, lr
     48c:	e1a02005 	mov	r2, r5
     490:	e1a01004 	mov	r1, r4
     494:	e12fff3c 	blx	ip ; _DrawText(0x80E34,0,0,0xff,0xff,0xff,0,1);
     498:	e28dd010 	add	sp, sp, #16
     49c:	e8bd8070 	pop	{r4, r5, r6, pc}
     4a0:	fffffb88 			; <UNDEFINED> instruction: 0xfffffb88
     4a4:	e92d4010 	push	{r4, lr}
     4a8:	e24dd050 	sub	sp, sp, #80	; 0x50
     4ac:	e1a03001 	mov	r3, r1
     4b0:	e59f1088 	ldr	r1, [pc, #136]	; 0x540
     4b4:	e58d2000 	str	r2, [sp]
     4b8:	e1a02000 	mov	r2, r0
     4bc:	e08f1001 	add	r1, pc, r1
     4c0:	e59fc07c 	ldr	ip, [pc, #124]	; 0x544
     4c4:	e28d4010 	add	r4, sp, #16
     4c8:	e08cc009 	add	ip, ip, r9
     4cc:	e59cc000 	ldr	ip, [ip]
     4d0:	e1a00004 	mov	r0, r4
     4d4:	e12fff3c 	blx	ip
     4d8:	e3a020ff 	mov	r2, #255	; 0xff
     4dc:	e58d2000 	str	r2, [sp]
     4e0:	e3a030ff 	mov	r3, #255	; 0xff
     4e4:	e98d000c 	stmib	sp, {r2, r3}
     4e8:	e3a0301e 	mov	r3, #30
     4ec:	e3a020f0 	mov	r2, #240	; 0xf0
     4f0:	e3a01032 	mov	r1, #50	; 0x32
     4f4:	e3a00000 	mov	r0, #0
     4f8:	ebffffc4 	bl	0x410
     4fc:	e3a01000 	mov	r1, #0
     500:	e58d1000 	str	r1, [sp]
     504:	e3a03001 	mov	r3, #1
     508:	e3a02000 	mov	r2, #0
     50c:	e98d000e 	stmib	sp, {r1, r2, r3}
     510:	e3a030ff 	mov	r3, #255	; 0xff
     514:	e3a02032 	mov	r2, #50	; 0x32
     518:	e1a00004 	mov	r0, r4
     51c:	ebffffcc 	bl	0x454
     520:	e3a03f50 	mov	r3, #80, 30	; 0x140
     524:	e3a020f0 	mov	r2, #240	; 0xf0
     528:	e3a01000 	mov	r1, #0
     52c:	e3a00000 	mov	r0, #0
     530:	eb0000c6 	bl	0x850
     534:	e3a00000 	mov	r0, #0
     538:	e28dd050 	add	sp, sp, #80	; 0x50
     53c:	e8bd8010 	pop	{r4, pc}
     540:	000009d4 	ldrdeq	r0, [r0], -r4
     544:	0000006c 	andeq	r0, r0, ip, rrx
     548:	e3a00000 	mov	r0, #0
     54c:	e12fff1e 	bx	lr
     550:	e92d45fe 	push	{r1, r2, r3, r4, r5, r6, r7, r8, sl, lr} ; mr_init()函数
     554:	e1a05000 	mov	r5, r0
     558:	e5900000 	ldr	r0, [r0]
     55c:	e1a0a009 	mov	sl, r9
     560:	e1a08001 	mov	r8, r1
     564:	e1a07003 	mov	r7, r3
     568:	e1a06002 	mov	r6, r2
     56c:	e3a04000 	mov	r4, #0
     570:	ebfffefe 	bl	0x170 ; r9=r0
     574:	e59f00cc 	ldr	r0, [pc, #204]	; 0x648 r0=4
     578:	e358000a 	cmp	r8, #10
     57c:	e0800009 	add	r0, r0, r9
     580:	908ff108 	addls	pc, pc, r8, lsl #2
     584:	ea00002c 	b	0x63c
     588:	ea000009 	b	0x5b4
     58c:	ea00000d 	b	0x5c8
     590:	ea000014 	b	0x5e8
     594:	ea000015 	b	0x5f0
     598:	ea000016 	b	0x5f8
     59c:	ea000017 	b	0x600
     5a0:	ea000018 	b	0x608
     5a4:	ea000024 	b	0x63c
     5a8:	ea000018 	b	0x610
     5ac:	ea000019 	b	0x618
     5b0:	ea000021 	b	0x63c
     5b4:	e595100c 	ldr	r1, [r5, #12]
     5b8:	e5801014 	str	r1, [r0, #20]
     5bc:	ebfffef3 	bl	0x190
     5c0:	eb000042 	bl	0x6d0
     5c4:	ea00001b 	b	0x638
     5c8:	e8960007 	ldm	r6, {r0, r1, r2}
     5cc:	ebffffb4 	bl	0x4a4
     5d0:	e1a04000 	mov	r4, r0
     5d4:	e5960000 	ldr	r0, [r6]
     5d8:	e3500008 	cmp	r0, #8
     5dc:	1a000016 	bne	0x63c
     5e0:	ebffffd8 	bl	0x548
     5e4:	ea000013 	b	0x638
     5e8:	eb000197 	bl	0xc4c
     5ec:	ea000012 	b	0x63c
     5f0:	e585700c 	str	r7, [r5, #12]
     5f4:	ea000010 	b	0x63c
     5f8:	eb000092 	bl	0x848
     5fc:	ea00000e 	b	0x63c
     600:	eb0000d0 	bl	0x948
     604:	ea00000c 	b	0x63c
     608:	e580701c 	str	r7, [r0, #28]
     60c:	ea00000a 	b	0x63c
     610:	e5806020 	str	r6, [r0, #32]
     614:	ea000008 	b	0x63c
     618:	e596c000 	ldr	ip, [r6]
     61c:	e35c0000 	cmp	ip, #0
     620:	0a000005 	beq	0x63c
     624:	e5962014 	ldr	r2, [r6, #20]
     628:	e5963018 	ldr	r3, [r6, #24]
     62c:	e88d000c 	stm	sp, {r2, r3}
     630:	e996000f 	ldmib	r6, {r0, r1, r2, r3}
     634:	e12fff3c 	blx	ip
     638:	e1a04000 	mov	r4, r0
     63c:	e1a0900a 	mov	r9, sl
     640:	e1a00004 	mov	r0, r4
     644:	e8bd85fe 	pop	{r1, r2, r3, r4, r5, r6, r7, r8, sl, pc}
     648:	00000004 	andeq	r0, r0, r4
     64c:	e59f1028 	ldr	r1, [pc, #40]	; 0x67c
     650:	e92d4008 	push	{r3, lr}
     654:	e08f1001 	add	r1, pc, r1
     658:	e5111004 	ldr	r1, [r1, #-4]
     65c:	e58d0000 	str	r0, [sp]
     660:	e591100c 	ldr	r1, [r1, #12]
     664:	e3a00000 	mov	r0, #0
     668:	e5913024 	ldr	r3, [r1, #36]	; 0x24
     66c:	e591c028 	ldr	ip, [r1, #40]	; 0x28
     670:	e3a02000 	mov	r2, #0
     674:	e12fff3c 	blx	ip
     678:	e8bd8008 	pop	{r3, pc}
     67c:	fffff9ac 			; <UNDEFINED> instruction: 0xfffff9ac
     680:	e59f002c 	ldr	r0, [pc, #44]	; 0x6b4
     684:	e92d4008 	push	{r3, lr}
     688:	e08f0000 	add	r0, pc, r0
     68c:	e5100004 	ldr	r0, [r0, #-4]
     690:	e3a03000 	mov	r3, #0
     694:	e58d3000 	str	r3, [sp]
     698:	e590100c 	ldr	r1, [r0, #12]
     69c:	e3a00000 	mov	r0, #0
     6a0:	e5913024 	ldr	r3, [r1, #36]	; 0x24
     6a4:	e591c028 	ldr	ip, [r1, #40]	; 0x28
     6a8:	e3a02001 	mov	r2, #1
     6ac:	e12fff3c 	blx	ip
     6b0:	e8bd8008 	pop	{r3, pc}
     6b4:	fffff978 			; <UNDEFINED> instruction: 0xfffff978
     6b8:	e59f100c 	ldr	r1, [pc, #12]	; 0x6cc
     6bc:	e08f1001 	add	r1, pc, r1
     6c0:	e5111008 	ldr	r1, [r1, #-8]
     6c4:	e5911140 	ldr	r1, [r1, #320]	; 0x140
     6c8:	e12fff11 	bx	r1
     6cc:	fffff944 			; <UNDEFINED> instruction: 0xfffff944
     6d0:	e92d4010 	push	{r4, lr}
     6d4:	e24dd030 	sub	sp, sp, #48	; 0x30
     6d8:	e3a02000 	mov	r2, #0
     6dc:	e3a01000 	mov	r1, #0
     6e0:	e3a00000 	mov	r0, #0
     6e4:	ebffff33 	bl	0x3b8
     6e8:	ebfffe95 	bl	0x144
     6ec:	e3a010ff 	mov	r1, #255	; 0xff
     6f0:	e58d1000 	str	r1, [sp]
     6f4:	e3a03001 	mov	r3, #1
     6f8:	e3a02000 	mov	r2, #0
     6fc:	e98d000e 	stmib	sp, {r1, r2, r3}
     700:	e3a030ff 	mov	r3, #255	; 0xff
     704:	e3a01000 	mov	r1, #0
     708:	e3500000 	cmp	r0, #0
     70c:	0a000003 	beq	0x720
     710:	e59f00e4 	ldr	r0, [pc, #228]	; 0x7fc
     714:	e08f0000 	add	r0, pc, r0
     718:	ebffff4d 	bl	0x454
     71c:	ea000002 	b	0x72c
     720:	e59f00d8 	ldr	r0, [pc, #216]	; 0x800
     724:	e08f0000 	add	r0, pc, r0
     728:	ebffff49 	bl	0x454
     72c:	e59f40d0 	ldr	r4, [pc, #208]	; 0x804
     730:	e1a01004 	mov	r1, r4
     734:	e1a00004 	mov	r0, r4
     738:	ebfffe7d 	bl	0x134 ; FixedByFrac(65539,65539)
     73c:	e59f10c4 	ldr	r1, [pc, #196]	; 0x808
     740:	e1a03004 	mov	r3, r4
     744:	e1a02004 	mov	r2, r4
     748:	e08f1001 	add	r1, pc, r1
     74c:	e59fc0b8 	ldr	ip, [pc, #184]	; 0x80c
     750:	e58d0000 	str	r0, [sp]
     754:	e08cc009 	add	ip, ip, r9
     758:	e59cc000 	ldr	ip, [ip]
     75c:	e28d4010 	add	r4, sp, #16
     760:	e1a00004 	mov	r0, r4
     764:	e12fff3c 	blx	ip ; 调用sprintf()
     768:	e3a010ff 	mov	r1, #255	; 0xff
     76c:	e58d1000 	str	r1, [sp]
     770:	e3a03001 	mov	r3, #1
     774:	e3a02000 	mov	r2, #0
     778:	e98d000e 	stmib	sp, {r1, r2, r3}
     77c:	e3a030ff 	mov	r3, #255	; 0xff
     780:	e3a02016 	mov	r2, #22
     784:	e3a01000 	mov	r1, #0
     788:	e1a00004 	mov	r0, r4
     78c:	ebffff30 	bl	0x454
     790:	e3a00001 	mov	r0, #1
     794:	e58d002c 	str	r0, [sp, #44]	; 0x2c
     798:	e5dd002c 	ldrb	r0, [sp, #44]	; 0x2c
     79c:	e3a01000 	mov	r1, #0
     7a0:	e58d1000 	str	r1, [sp]
     7a4:	e3a03001 	mov	r3, #1
     7a8:	e3a02000 	mov	r2, #0
     7ac:	e98d000e 	stmib	sp, {r1, r2, r3}
     7b0:	e3a030ff 	mov	r3, #255	; 0xff
     7b4:	e3a02064 	mov	r2, #100	; 0x64
     7b8:	e3500000 	cmp	r0, #0
     7bc:	0a000003 	beq	0x7d0
     7c0:	e59f0048 	ldr	r0, [pc, #72]	; 0x810
     7c4:	e08f0000 	add	r0, pc, r0
     7c8:	ebffff21 	bl	0x454
     7cc:	ea000002 	b	0x7dc
     7d0:	e59f003c 	ldr	r0, [pc, #60]	; 0x814
     7d4:	e08f0000 	add	r0, pc, r0
     7d8:	ebffff1d 	bl	0x454
     7dc:	e3a03f50 	mov	r3, #80, 30	; 0x140
     7e0:	e3a020f0 	mov	r2, #240	; 0xf0
     7e4:	e3a01000 	mov	r1, #0
     7e8:	e3a00000 	mov	r0, #0
     7ec:	eb000017 	bl	0x850
     7f0:	e3a00000 	mov	r0, #0
     7f4:	e28dd030 	add	sp, sp, #48	; 0x30
     7f8:	e8bd8010 	pop	{r4, pc}
     7fc:	00000718 	andeq	r0, r0, r8, lsl r7
     800:	0000071c 	andeq	r0, r0, ip, lsl r7
     804:	00010003 	andeq	r0, r1, r3
     808:	0000070c 	andeq	r0, r0, ip, lsl #14
     80c:	0000006c 	andeq	r0, r0, ip, rrx
     810:	000006a0 	andeq	r0, r0, r0, lsr #13
     814:	000006a8 	andeq	r0, r0, r8, lsr #13
     818:	e92d4010 	push	{r4, lr}
     81c:	e1a04000 	mov	r4, r0
     820:	e59f001c 	ldr	r0, [pc, #28]	; 0x844
     824:	e08f0000 	add	r0, pc, r0
     828:	e5100008 	ldr	r0, [r0, #-8]
     82c:	e5901000 	ldr	r1, [r0]
     830:	e2840004 	add	r0, r4, #4
     834:	e12fff31 	blx	r1  ;调用 mr_malloc(0x108)返回0x281000内存地址
     838:	e3500000 	cmp	r0, #0
     83c:	14804004 	strne	r4, [r0], #4  ; 将0x104存入0x281000内存
     840:	e8bd8010 	pop	{r4, pc}
     844:	fffff7dc 			; <UNDEFINED> instruction: 0xfffff7dc
     848:	e3a00000 	mov	r0, #0
     84c:	e12fff1e 	bx	lr
     850:	e92d40f8 	push	{r3, r4, r5, r6, r7, lr}
     854:	e1a04000 	mov	r4, r0
     858:	e59f0048 	ldr	r0, [pc, #72]	; 0x8a8
     85c:	e1a07003 	mov	r7, r3
     860:	e0800009 	add	r0, r0, r9
     864:	e5900084 	ldr	r0, [r0, #132]	; 0x84
     868:	e1a06002 	mov	r6, r2
     86c:	e1a05001 	mov	r5, r1
     870:	e3500000 	cmp	r0, #0
     874:	112fff30 	blxne	r0
     878:	e59f002c 	ldr	r0, [pc, #44]	; 0x8ac
     87c:	e08f0000 	add	r0, pc, r0
     880:	e58d7000 	str	r7, [sp]
     884:	e5101008 	ldr	r1, [r0, #-8]
     888:	e1a03006 	mov	r3, r6
     88c:	e591016c 	ldr	r0, [r1, #364]	; 0x16c
     890:	e1a02005 	mov	r2, r5
     894:	e5900000 	ldr	r0, [r0]
     898:	e591c074 	ldr	ip, [r1, #116]	; 0x74
     89c:	e1a01004 	mov	r1, r4
     8a0:	e12fff3c 	blx	ip
     8a4:	e8bd80f8 	pop	{r3, r4, r5, r6, r7, pc}
     8a8:	00000004 	andeq	r0, r0, r4
     8ac:	fffff784 			; <UNDEFINED> instruction: 0xfffff784
     8b0:	e92d401f 	push	{r0, r1, r2, r3, r4, lr}
     8b4:	e59f4084 	ldr	r4, [pc, #132]	; 0x940
     8b8:	e0844009 	add	r4, r4, r9
     8bc:	e5940074 	ldr	r0, [r4, #116]	; 0x74
     8c0:	e3500000 	cmp	r0, #0
     8c4:	1a000007 	bne	0x8e8
     8c8:	e28d0004 	add	r0, sp, #4
     8cc:	ebffff79 	bl	0x6b8
     8d0:	e59d0004 	ldr	r0, [sp, #4]
     8d4:	e584007c 	str	r0, [r4, #124]	; 0x7c
     8d8:	e59d0008 	ldr	r0, [sp, #8]
     8dc:	e5840080 	str	r0, [r4, #128]	; 0x80
     8e0:	e3a00001 	mov	r0, #1
     8e4:	e5840074 	str	r0, [r4, #116]	; 0x74
     8e8:	e5940078 	ldr	r0, [r4, #120]	; 0x78
     8ec:	e3500001 	cmp	r0, #1
     8f0:	1a00000f 	bne	0x934
     8f4:	e5940080 	ldr	r0, [r4, #128]	; 0x80
     8f8:	e1a03800 	lsl	r3, r0, #16
     8fc:	e59f0040 	ldr	r0, [pc, #64]	; 0x944
     900:	e1a03823 	lsr	r3, r3, #16
     904:	e08f0000 	add	r0, pc, r0
     908:	e58d3000 	str	r3, [sp]
     90c:	e5101008 	ldr	r1, [r0, #-8]
     910:	e3a02000 	mov	r2, #0
     914:	e591016c 	ldr	r0, [r1, #364]	; 0x16c
     918:	e591c074 	ldr	ip, [r1, #116]	; 0x74
     91c:	e5900000 	ldr	r0, [r0]
     920:	e594107c 	ldr	r1, [r4, #124]	; 0x7c
     924:	e1a03801 	lsl	r3, r1, #16
     928:	e1a03823 	lsr	r3, r3, #16
     92c:	e3a01000 	mov	r1, #0
     930:	e12fff3c 	blx	ip
     934:	e3a00000 	mov	r0, #0
     938:	e5840078 	str	r0, [r4, #120]	; 0x78
     93c:	e8bd801f 	pop	{r0, r1, r2, r3, r4, pc}
     940:	00000004 	andeq	r0, r0, r4
     944:	fffff6fc 			; <UNDEFINED> instruction: 0xfffff6fc
     948:	e3a00000 	mov	r0, #0
     94c:	e12fff1e 	bx	lr
     950:	e59f1014 	ldr	r1, [pc, #20]	; 0x96c
     954:	e3a00000 	mov	r0, #0
     958:	e0811009 	add	r1, r1, r9
     95c:	e5810088 	str	r0, [r1, #136]	; 0x88
     960:	e5810090 	str	r0, [r1, #144]	; 0x90
     964:	e581008c 	str	r0, [r1, #140]	; 0x8c
     968:	e12fff1e 	bx	lr
     96c:	00000004 	andeq	r0, r0, r4
     970:	e92d4010 	push	{r4, lr}
     974:	e59f402c 	ldr	r4, [pc, #44]	; 0x9a8
     978:	e0844009 	add	r4, r4, r9
     97c:	e5940090 	ldr	r0, [r4, #144]	; 0x90
     980:	e3500000 	cmp	r0, #0
     984:	08bd8010 	popeq	{r4, pc}
     988:	e59f001c 	ldr	r0, [pc, #28]	; 0x9ac
     98c:	e08f0000 	add	r0, pc, r0
     990:	e5100008 	ldr	r0, [r0, #-8]
     994:	e5900084 	ldr	r0, [r0, #132]	; 0x84
     998:	e12fff30 	blx	r0
     99c:	e5941090 	ldr	r1, [r4, #144]	; 0x90
     9a0:	e0410000 	sub	r0, r1, r0
     9a4:	e8bd8010 	pop	{r4, pc}
     9a8:	00000004 	andeq	r0, r0, r4
     9ac:	fffff674 			; <UNDEFINED> instruction: 0xfffff674
     9b0:	e1b01000 	movs	r1, r0
     9b4:	012fff1e 	bxeq	lr
     9b8:	e59f3094 	ldr	r3, [pc, #148]	; 0xa54
     9bc:	e0833009 	add	r3, r3, r9
     9c0:	e5932088 	ldr	r2, [r3, #136]	; 0x88
     9c4:	e1520001 	cmp	r2, r1
     9c8:	05910018 	ldreq	r0, [r1, #24]
     9cc:	05830088 	streq	r0, [r3, #136]	; 0x88
     9d0:	0a00000c 	beq	0xa08
     9d4:	e3520000 	cmp	r2, #0
     9d8:	0a00000a 	beq	0xa08
     9dc:	e5920018 	ldr	r0, [r2, #24]
     9e0:	ea000006 	b	0xa00
     9e4:	e1500001 	cmp	r0, r1
     9e8:	11a02000 	movne	r2, r0
     9ec:	1a000002 	bne	0x9fc
     9f0:	e5900018 	ldr	r0, [r0, #24]
     9f4:	e5820018 	str	r0, [r2, #24]
     9f8:	ea000002 	b	0xa08
     9fc:	e5900018 	ldr	r0, [r0, #24]
     a00:	e3500000 	cmp	r0, #0
     a04:	1afffff6 	bne	0x9e4
     a08:	e593208c 	ldr	r2, [r3, #140]	; 0x8c
     a0c:	e3520000 	cmp	r2, #0
     a10:	012fff1e 	bxeq	lr
     a14:	e1520001 	cmp	r2, r1
     a18:	0592001c 	ldreq	r0, [r2, #28]
     a1c:	0583008c 	streq	r0, [r3, #140]	; 0x8c
     a20:	012fff1e 	bxeq	lr
     a24:	e592001c 	ldr	r0, [r2, #28]
     a28:	ea000006 	b	0xa48
     a2c:	e1500001 	cmp	r0, r1
     a30:	11a02000 	movne	r2, r0
     a34:	1a000002 	bne	0xa44
     a38:	e590001c 	ldr	r0, [r0, #28]
     a3c:	e582001c 	str	r0, [r2, #28]
     a40:	e12fff1e 	bx	lr
     a44:	e590001c 	ldr	r0, [r0, #28]
     a48:	e3500000 	cmp	r0, #0
     a4c:	1afffff6 	bne	0xa2c
     a50:	e12fff1e 	bx	lr
     a54:	00000004 	andeq	r0, r0, r4
     a58:	e92d41f0 	push	{r4, r5, r6, r7, r8, lr}
     a5c:	e1a08000 	mov	r8, r0
     a60:	e1b04000 	movs	r4, r0
     a64:	e59f0188 	ldr	r0, [pc, #392]	; 0xbf4
     a68:	e08f0000 	add	r0, pc, r0
     a6c:	e59fe184 	ldr	lr, [pc, #388]	; 0xbf8
     a70:	e08fe00e 	add	lr, pc, lr
     a74:	e59dc018 	ldr	ip, [sp, #24]
     a78:	e51ee008 	ldr	lr, [lr, #-8]
     a7c:	1a000003 	bne	0xa90
     a80:	e59e2068 	ldr	r2, [lr, #104]	; 0x68
     a84:	e3a01ffa 	mov	r1, #1000	; 0x3e8
     a88:	e12fff32 	blx	r2
     a8c:	ea000018 	b	0xaf4
     a90:	e59e505c 	ldr	r5, [lr, #92]	; 0x5c
     a94:	e5955008 	ldr	r5, [r5, #8]
     a98:	e5955000 	ldr	r5, [r5]
     a9c:	e3550003 	cmp	r5, #3
     aa0:	13550004 	cmpne	r5, #4
     aa4:	0a000012 	beq	0xaf4
     aa8:	e5945000 	ldr	r5, [r4]
     aac:	e59f6148 	ldr	r6, [pc, #328]	; 0xbfc
     ab0:	e1550006 	cmp	r5, r6
     ab4:	0a000003 	beq	0xac8
     ab8:	e59e2068 	ldr	r2, [lr, #104]	; 0x68
     abc:	e59f113c 	ldr	r1, [pc, #316]	; 0xc00
     ac0:	e12fff32 	blx	r2
     ac4:	ea00000a 	b	0xaf4
     ac8:	e3510000 	cmp	r1, #0
     acc:	15841004 	strne	r1, [r4, #4]
     ad0:	e5842010 	str	r2, [r4, #16]
     ad4:	e3a06000 	mov	r6, #0
     ad8:	e5846008 	str	r6, [r4, #8]
     adc:	e3530000 	cmp	r3, #0
     ae0:	1584300c 	strne	r3, [r4, #12]
     ae4:	e584c014 	str	ip, [r4, #20]
     ae8:	e5940004 	ldr	r0, [r4, #4]
     aec:	e3500000 	cmp	r0, #0
     af0:	ca000001 	bgt	0xafc
     af4:	e3e00000 	mvn	r0, #0
     af8:	e8bd81f0 	pop	{r4, r5, r6, r7, r8, pc}
     afc:	e350000a 	cmp	r0, #10
     b00:	b3a0000a 	movlt	r0, #10
     b04:	b5840004 	strlt	r0, [r4, #4]
     b08:	e5940004 	ldr	r0, [r4, #4]
     b0c:	e5840008 	str	r0, [r4, #8]
     b10:	ebffff96 	bl	0x970
     b14:	e59f70e8 	ldr	r7, [pc, #232]	; 0xc04
     b18:	e1a05000 	mov	r5, r0
     b1c:	e0877009 	add	r7, r7, r9
     b20:	e5970088 	ldr	r0, [r7, #136]	; 0x88
     b24:	e3500000 	cmp	r0, #0
     b28:	0a000005 	beq	0xb44
     b2c:	e5900004 	ldr	r0, [r0, #4]
     b30:	e3550000 	cmp	r5, #0
     b34:	b3a05000 	movlt	r5, #0
     b38:	e2801005 	add	r1, r0, #5
     b3c:	e1510005 	cmp	r1, r5
     b40:	b1a05000 	movlt	r5, r0
     b44:	e1a00008 	mov	r0, r8
     b48:	ebffff98 	bl	0x9b0
     b4c:	e5971088 	ldr	r1, [r7, #136]	; 0x88
     b50:	e3510000 	cmp	r1, #0
     b54:	0a000004 	beq	0xb6c
     b58:	e5940008 	ldr	r0, [r4, #8]
     b5c:	e1500005 	cmp	r0, r5
     b60:	a0400005 	subge	r0, r0, r5
     b64:	a5840008 	strge	r0, [r4, #8]
     b68:	aa000009 	bge	0xb94
     b6c:	e5940008 	ldr	r0, [r4, #8]
     b70:	e5846008 	str	r6, [r4, #8]
     b74:	e0452000 	sub	r2, r5, r0
     b78:	e3510000 	cmp	r1, #0
     b7c:	15913008 	ldrne	r3, [r1, #8]
     b80:	10833002 	addne	r3, r3, r2
     b84:	15813008 	strne	r3, [r1, #8]
     b88:	15911018 	ldrne	r1, [r1, #24]
     b8c:	1afffff9 	bne	0xb78
     b90:	eb00001c 	bl	0xc08
     b94:	e5970088 	ldr	r0, [r7, #136]	; 0x88
     b98:	e3500000 	cmp	r0, #0
     b9c:	05878088 	streq	r8, [r7, #136]	; 0x88
     ba0:	05886018 	streq	r6, [r8, #24]
     ba4:	0a000010 	beq	0xbec
     ba8:	e5981008 	ldr	r1, [r8, #8]
     bac:	e5902008 	ldr	r2, [r0, #8]
     bb0:	e1510002 	cmp	r1, r2
     bb4:	b5880018 	strlt	r0, [r8, #24]
     bb8:	b5878088 	strlt	r8, [r7, #136]	; 0x88
     bbc:	ba00000a 	blt	0xbec
     bc0:	e5902018 	ldr	r2, [r0, #24]
     bc4:	ea000001 	b	0xbd0
     bc8:	e1a00002 	mov	r0, r2
     bcc:	eafffffb 	b	0xbc0
     bd0:	e3520000 	cmp	r2, #0
     bd4:	0a000002 	beq	0xbe4
     bd8:	e5923008 	ldr	r3, [r2, #8]
     bdc:	e1510003 	cmp	r1, r3
     be0:	aafffff8 	bge	0xbc8
     be4:	e5808018 	str	r8, [r0, #24]
     be8:	e5882018 	str	r2, [r8, #24]
     bec:	e3a00000 	mov	r0, #0
     bf0:	e8bd81f0 	pop	{r4, r5, r6, r7, r8, pc}
     bf4:	00000458 	andeq	r0, r0, r8, asr r4
     bf8:	fffff590 			; <UNDEFINED> instruction: 0xfffff590
     bfc:	79abbccf 	stmibvc	fp!, {r0, r1, r2, r3, r6, r7, sl, fp, ip, sp, pc}
     c00:	000003e9 	andeq	r0, r0, r9, ror #7
     c04:	00000004 	andeq	r0, r0, r4
     c08:	e92d4010 	push	{r4, lr}
     c0c:	e1a04000 	mov	r4, r0
     c10:	e59f002c 	ldr	r0, [pc, #44]	; 0xc44
     c14:	e08f0000 	add	r0, pc, r0
     c18:	e5100008 	ldr	r0, [r0, #-8]
     c1c:	e5900084 	ldr	r0, [r0, #132]	; 0x84
     c20:	e12fff30 	blx	r0
     c24:	e0800004 	add	r0, r0, r4
     c28:	e59f1018 	ldr	r1, [pc, #24]	; 0xc48
     c2c:	e0811009 	add	r1, r1, r9
     c30:	e5810090 	str	r0, [r1, #144]	; 0x90
     c34:	eb000073 	bl	0xe08
     c38:	e1a00004 	mov	r0, r4
     c3c:	e8bd4010 	pop	{r4, lr}
     c40:	ea00005f 	b	0xdc4
     c44:	fffff3ec 			; <UNDEFINED> instruction: 0xfffff3ec
     c48:	00000004 	andeq	r0, r0, r4
     c4c:	e59f0164 	ldr	r0, [pc, #356]	; 0xdb8
     c50:	e92d407c 	push	{r2, r3, r4, r5, r6, lr}
     c54:	e08f0000 	add	r0, pc, r0
     c58:	e5100008 	ldr	r0, [r0, #-8]
     c5c:	e5900084 	ldr	r0, [r0, #132]	; 0x84
     c60:	e12fff30 	blx	r0
     c64:	e3a05000 	mov	r5, #0
     c68:	e59f614c 	ldr	r6, [pc, #332]	; 0xdbc
     c6c:	e0866009 	add	r6, r6, r9
     c70:	e5961090 	ldr	r1, [r6, #144]	; 0x90
     c74:	e5865090 	str	r5, [r6, #144]	; 0x90
     c78:	e0400001 	sub	r0, r0, r1
     c7c:	e5961088 	ldr	r1, [r6, #136]	; 0x88
     c80:	e1a02000 	mov	r2, r0
     c84:	e3510000 	cmp	r1, #0
     c88:	0a000049 	beq	0xdb4
     c8c:	e5913008 	ldr	r3, [r1, #8]
     c90:	e3530000 	cmp	r3, #0
     c94:	13a04000 	movne	r4, #0
     c98:	1a000019 	bne	0xd04
     c9c:	e3e0c000 	mvn	ip, #0
     ca0:	e581c008 	str	ip, [r1, #8]
     ca4:	e5913018 	ldr	r3, [r1, #24]
     ca8:	e3520032 	cmp	r2, #50	; 0x32
     cac:	b3a02032 	movlt	r2, #50	; 0x32
     cb0:	e1a04001 	mov	r4, r1
     cb4:	e5863088 	str	r3, [r6, #136]	; 0x88
     cb8:	ba000008 	blt	0xce0
     cbc:	e3520e7d 	cmp	r2, #2000	; 0x7d0
     cc0:	c3a02e7d 	movgt	r2, #2000	; 0x7d0
     cc4:	ea000005 	b	0xce0
     cc8:	e583c008 	str	ip, [r3, #8]
     ccc:	e5913018 	ldr	r3, [r1, #24]
     cd0:	e581301c 	str	r3, [r1, #28]
     cd4:	e5931018 	ldr	r1, [r3, #24]
     cd8:	e5861088 	str	r1, [r6, #136]	; 0x88
     cdc:	e1a01003 	mov	r1, r3
     ce0:	e5913018 	ldr	r3, [r1, #24]
     ce4:	e3530000 	cmp	r3, #0
     ce8:	1593e008 	ldrne	lr, [r3, #8]
     cec:	115e0002 	cmpne	lr, r2
     cf0:	bafffff4 	blt	0xcc8
     cf4:	e581501c 	str	r5, [r1, #28]
     cf8:	e5961088 	ldr	r1, [r6, #136]	; 0x88
     cfc:	e3510000 	cmp	r1, #0
     d00:	0a000026 	beq	0xda0
     d04:	e5961088 	ldr	r1, [r6, #136]	; 0x88
     d08:	e3500000 	cmp	r0, #0
     d0c:	e5912008 	ldr	r2, [r1, #8]
     d10:	b3a00000 	movlt	r0, #0
     d14:	e3520000 	cmp	r2, #0
     d18:	b3a02000 	movlt	r2, #0
     d1c:	b5815008 	strlt	r5, [r1, #8]
     d20:	ba000002 	blt	0xd30
     d24:	e252ccff 	subs	ip, r2, #65280	; 0xff00
     d28:	a25cc0ff 	subsge	ip, ip, #255	; 0xff
     d2c:	c59f208c 	ldrgt	r2, [pc, #140]	; 0xdc0
     d30:	e5913008 	ldr	r3, [r1, #8]
     d34:	e0433002 	sub	r3, r3, r2
     d38:	e5813008 	str	r3, [r1, #8]
     d3c:	e5911018 	ldr	r1, [r1, #24]
     d40:	e3510000 	cmp	r1, #0
     d44:	1afffff9 	bne	0xd30
     d48:	e0420000 	sub	r0, r2, r0
     d4c:	e3500000 	cmp	r0, #0
     d50:	d3a0000a 	movle	r0, #10
     d54:	ebffffab 	bl	0xc08
     d58:	ea000010 	b	0xda0
     d5c:	e5845008 	str	r5, [r4, #8]
     d60:	e594001c 	ldr	r0, [r4, #28]
     d64:	e586008c 	str	r0, [r6, #140]	; 0x8c
     d68:	e5940014 	ldr	r0, [r4, #20]
     d6c:	e3500000 	cmp	r0, #0
     d70:	0a000005 	beq	0xd8c
     d74:	e58d0000 	str	r0, [sp]
     d78:	e5942010 	ldr	r2, [r4, #16]
     d7c:	e1a00004 	mov	r0, r4
     d80:	e3a03000 	mov	r3, #0
     d84:	e3a01000 	mov	r1, #0
     d88:	ebffff32 	bl	0xa58
     d8c:	e594100c 	ldr	r1, [r4, #12]
     d90:	e3510000 	cmp	r1, #0
     d94:	15940010 	ldrne	r0, [r4, #16]
     d98:	112fff31 	blxne	r1
     d9c:	e596408c 	ldr	r4, [r6, #140]	; 0x8c
     da0:	e3540000 	cmp	r4, #0
     da4:	15940008 	ldrne	r0, [r4, #8]
     da8:	13500000 	cmpne	r0, #0
     dac:	baffffea 	blt	0xd5c
     db0:	e586508c 	str	r5, [r6, #140]	; 0x8c
     db4:	e8bd807c 	pop	{r2, r3, r4, r5, r6, pc}
     db8:	fffff3ac 			; <UNDEFINED> instruction: 0xfffff3ac
     dbc:	00000004 	andeq	r0, r0, r4
     dc0:	0000ffff 	strdeq	pc, [r0], -pc	; <UNPREDICTABLE>
     dc4:	e92d4010 	push	{r4, lr}
     dc8:	e59f4034 	ldr	r4, [pc, #52]	; 0xe04
     dcc:	e08f4004 	add	r4, pc, r4
     dd0:	e5141008 	ldr	r1, [r4, #-8]
     dd4:	e1a00800 	lsl	r0, r0, #16
     dd8:	e591107c 	ldr	r1, [r1, #124]	; 0x7c
     ddc:	e1a00820 	lsr	r0, r0, #16
     de0:	e12fff31 	blx	r1
     de4:	e3500000 	cmp	r0, #0
     de8:	05141008 	ldreq	r1, [r4, #-8]
     dec:	03a00001 	moveq	r0, #1
     df0:	0591105c 	ldreq	r1, [r1, #92]	; 0x5c
     df4:	05911014 	ldreq	r1, [r1, #20]
     df8:	05810000 	streq	r0, [r1]
     dfc:	03a00000 	moveq	r0, #0
     e00:	e8bd8010 	pop	{r4, pc}
     e04:	fffff234 			; <UNDEFINED> instruction: 0xfffff234
     e08:	e59f2020 	ldr	r2, [pc, #32]	; 0xe30
     e0c:	e3a00000 	mov	r0, #0
     e10:	e08f2002 	add	r2, pc, r2
     e14:	e5121008 	ldr	r1, [r2, #-8]
     e18:	e591105c 	ldr	r1, [r1, #92]	; 0x5c
     e1c:	e5911014 	ldr	r1, [r1, #20]
     e20:	e5810000 	str	r0, [r1]
     e24:	e5120008 	ldr	r0, [r2, #-8]
     e28:	e5900080 	ldr	r0, [r0, #128]	; 0x80
     e2c:	e12fff10 	bx	r0
     e30:	fffff1f0 			; <UNDEFINED> instruction: 0xfffff1f0
     e34:	6c6c6568 	cfstr64vs	mvdx6, [ip], #-416	; 0xfffffe60
     e38:	694c206f 	stmdbvs	ip, {r0, r1, r2, r3, r5, r6, sp}^
     e3c:	656c7474 	strbvs	r7, [ip, #-1140]!	; 0xfffffb8c
     e40:	69646e45 	stmdbvs	r4!, {r0, r2, r6, r9, sl, fp, sp, lr}^
     e44:	00216e61 	eoreq	r6, r1, r1, ror #28
     e48:	6c6c6568 	cfstr64vs	mvdx6, [ip], #-416	; 0xfffffe60
     e4c:	6942206f 	stmdbvs	r2, {r0, r1, r2, r3, r5, r6, sp}^
     e50:	646e4567 	strbtvs	r4, [lr], #-1383	; 0xfffffa99
     e54:	216e6169 	cmncs	lr, r9, ror #2
     e58:	00000000 	andeq	r0, r0, r0
     e5c:	2a206425 	bcs	0x819ef8
     e60:	20642520 	rsbcs	r2, r4, r0, lsr #10
     e64:	6425203d 	strtvs	r2, [r5], #-61	; 0xffffffc3
     e68:	00000000 	andeq	r0, r0, r0
     e6c:	6c6c6568 	cfstr64vs	mvdx6, [ip], #-416	; 0xfffffe60
     e70:	4c63206f 	stclmi	0, cr2, [r3], #-444	; 0xfffffe44
     e74:	6c747469 	cfldrdvs	mvd7, [r4], #-420	; 0xfffffe5c
     e78:	646e4565 	strbtvs	r4, [lr], #-1381	; 0xfffffa9b
     e7c:	216e6169 	cmncs	lr, r9, ror #2
     e80:	00000000 	andeq	r0, r0, r0
     e84:	6c6c6568 	cfstr64vs	mvdx6, [ip], #-416	; 0xfffffe60
     e88:	4263206f 	rsbmi	r2, r3, #111	; 0x6f
     e8c:	6e456769 	cdpvs	7, 4, cr6, cr5, cr9, {3}
     e90:	6e616964 	vnmulvs.f16	s13, s2, s9	; <UNPREDICTABLE>
     e94:	00000021 	andeq	r0, r0, r1, lsr #32
     e98:	65646f63 	strbvs	r6, [r4, #-3939]!	; 0xfffff09d
     e9c:	2c64253d 	cfstr64cs	mvdx2, [r4], #-244	; 0xffffff0c
     ea0:	3d307020 	ldccc	0, cr7, [r0, #-128]!	; 0xffffff80
     ea4:	202c6425 	eorcs	r6, ip, r5, lsr #8
     ea8:	253d3170 	ldrcs	r3, [sp, #-368]!	; 0xfffffe90
     eac:	00000064 	andeq	r0, r0, r4, rrx
     eb0:	4750524d 	ldrbmi	r5, [r0, -sp, asr #4]
     eb4:	00000004 	andeq	r0, r0, r4
     eb8:	00000000 	andeq	r0, r0, r0
     ebc:	00000004 	andeq	r0, r0, r4
     ec0:	00636261 	rsbeq	r6, r3, r1, ror #4
     ec4:	00000000 	andeq	r0, r0, r0
     ec8:	656d6974 	strbvs	r6, [sp, #-2420]!	; 0xfffff68c
     ecc:	72652072 	rsbvc	r2, r5, #114	; 0x72
     ed0:	64253a72 	strtvs	r3, [r5], #-2674	; 0xfffff58e
     ed4:	00000000 	andeq	r0, r0, r0
     ed8:	6c616564 	cfstr64vs	mvdx6, [r1], #-400	; 0xfffffe70
     edc:	656d6974 	strbvs	r6, [sp, #-2420]!	; 0xfffff68c
     ee0:	00000072 	andeq	r0, r0, r2, ror r0
     ee4:	3a6c6156 	bcc	0x1b19444
     ee8:	78257830 	stmdavc	r5!, {r4, r5, fp, ip, sp, lr}
     eec:	00000000 	andeq	r0, r0, r0
     ef0:	656d6974 	strbvs	r6, [sp, #-2420]!	; 0xfffff68c
     ef4:	65724372 	ldrbvs	r4, [r2, #-882]!	; 0xfffffc8e
     ef8:	20657461 	rsbcs	r7, r5, r1, ror #8
     efc:	20727265 	rsbscs	r7, r2, r5, ror #4
     f00:	00003130 	andeq	r3, r0, r0, lsr r1
     f04:	20747865 	rsbscs	r7, r4, r5, ror #16
     f08:	3a727265 	bcc	0x1c9d8a4
     f0c:	00006425 	andeq	r6, r0, r5, lsr #8
     f10:	3a753263 	bcc	0x1d4d8a4
     f14:	20727265 	rsbscs	r7, r2, r5, ror #4
     f18:	00312020 	eorseq	r2, r1, r0, lsr #32
     f1c:	3a753263 	bcc	0x1d4d8b0
     f20:	20727265 	rsbscs	r7, r2, r5, ror #4
     f24:	00322020 	eorseq	r2, r2, r0, lsr #32
     f28:	74736572 	ldrbtvc	r6, [r3], #-1394	; 0xfffffa8e
     f2c:	00747261 	rsbseq	r7, r4, r1, ror #4
     f30:	3a727265 	bcc	0x1c9d8cc
     f34:	00006425 	andeq	r6, r0, r5, lsr #8
     f38:	64616572 	strbtvs	r6, [r1], #-1394	; 0xfffffa8e
     f3c:	73252220 			; <UNDEFINED> instruction: 0x73252220
     f40:	72662022 	rsbvc	r2, r6, #34	; 0x22
     f44:	6d206d6f 	stcvs	13, cr6, [r0, #-444]!	; 0xfffffe44
     f48:	65207072 	strvs	r7, [r0, #-114]!	; 0xffffff8e
     f4c:	632c7272 			; <UNDEFINED> instruction: 0x632c7272
     f50:	3d65646f 	cfstrdcc	mvd6, [r5, #-444]!	; 0xfffffe44
     f54:	00006425 	andeq	r6, r0, r5, lsr #8
     f58:	20637263 	rsbcs	r7, r3, r3, ror #4
     f5c:	21727265 	cmncs	r2, r5, ror #4
     f60:	00000000 	andeq	r0, r0, r0
     f64:	676e656c 	strbvs	r6, [lr, -ip, ror #10]!
     f68:	65206874 	strvs	r6, [r0, #-2164]!	; 0xfffff78c
     f6c:	00217272 	eoreq	r7, r1, r2, ror r2
     f70:	00008b1f 	andeq	r8, r0, pc, lsl fp
     f74:	00009e1f 	andeq	r9, r0, pc, lsl lr
     f78:	00636261 	rsbeq	r6, r3, r1, ror #4
     f7c:	00000024 	andeq	r0, r0, r4, lsr #32
     f80:	656d6954 	strbvs	r6, [sp, #-2388]!	; 0xfffff6ac
     f84:	61745372 	cmnvs	r4, r2, ror r3
     f88:	3d206574 	cfstr32cc	mvfx6, [r0, #-464]!	; 0xfffffe30
     f8c:	00642520 	rsbeq	r2, r4, r0, lsr #10
     f90:	77204243 	strvc	r4, [r0, -r3, asr #4]!
     f94:	206e6568 	rsbcs	r6, lr, r8, ror #10
     f98:	73756170 	cmnvc	r5, #112, 2
     f9c:	00002165 	andeq	r2, r0, r5, ror #2
     fa0:	68636163 	stmdavs	r3!, {r0, r1, r5, r6, r8, sp, lr}^
     fa4:	00000065 	andeq	r0, r0, r5, rrx
     fa8:	68636163 	stmdavs	r3!, {r0, r1, r5, r6, r8, sp, lr}^
     fac:	78652f65 	stmdavc	r5!, {r0, r2, r5, r6, r8, r9, sl, fp, sp}^
     fb0:	2e746564 	cdpcs	5, 7, cr6, cr4, cr4, {3}
     fb4:	00746164 	rsbseq	r6, r4, r4, ror #2
     fb8:	61527865 	cmpvs	r2, r5, ror #16
     fbc:	6163536d 	cmnvs	r3, sp, ror #6
     fc0:	65443a6e 	strbvs	r3, [r4, #-2670]	; 0xfffff592
     fc4:	74636574 	strbtvc	r6, [r3], #-1396	; 0xfffffa8c
     fc8:	656c6946 	strbvs	r6, [ip, #-2374]!	; 0xfffff6ba
     fcc:	45746f4e 	ldrbmi	r6, [r4, #-3918]!	; 0xfffff0b2
     fd0:	74736978 	ldrbtvc	r6, [r3], #-2424	; 0xfffff688
     fd4:	00000000 	andeq	r0, r0, r0
     fd8:	61527865 	cmpvs	r2, r5, ror #16
     fdc:	31543a6d 	cmpcc	r4, sp, ror #20
     fe0:	28667542 	stmdacs	r6!, {r1, r6, r8, sl, ip, sp, lr}^
     fe4:	2c296425 	cfstrscs	mvf6, [r9], #-148	; 0xffffff6c
     fe8:	72646461 	rsbvc	r6, r4, #1627389952	; 0x61000000
     fec:	2578303a 	ldrbcs	r3, [r8, #-58]!	; 0xffffffc6
     ff0:	69732c78 	ldmdbvs	r3!, {r3, r4, r5, r6, sl, fp, sp}^
     ff4:	253a657a 	ldrcs	r6, [sl, #-1402]!	; 0xfffffa86
     ff8:	00002e64 	andeq	r2, r0, r4, ror #28
     ffc:	68636163 	stmdavs	r3!, {r0, r1, r5, r6, r8, sp, lr}^
    1000:	78652f65 	stmdavc	r5!, {r0, r2, r5, r6, r8, r9, sl, fp, sp}^
    1004:	61732e72 	cmnvs	r3, r2, ror lr
    1008:	00000076 	andeq	r0, r0, r6, ror r0
    100c:	61527865 	cmpvs	r2, r5, ror #16
    1010:	6163536d 	cmnvs	r3, sp, ror #6
    1014:	32543a6e 	subscc	r3, r4, #450560	; 0x6e000
    1018:	3a667542 	bcc	0x199e528
    101c:	72646461 	rsbvc	r6, r4, #1627389952	; 0x61000000
    1020:	2578303a 	ldrbcs	r3, [r8, #-58]!	; 0xffffffc6
    1024:	656c2c78 	strbvs	r2, [ip, #-3192]!	; 0xfffff388
    1028:	64253a6e 	strtvs	r3, [r5], #-2670	; 0xfffff592
    102c:	00000000 	andeq	r0, r0, r0
    1030:	61527865 	cmpvs	r2, r5, ror #16
    1034:	6c413a6d 	mcrrvs	10, 6, r3, r1, cr13
    1038:	3a636f6c 	bcc	0x18dcdf0
    103c:	72646461 	rsbvc	r6, r4, #1627389952	; 0x61000000
    1040:	2578303a 	ldrbcs	r3, [r8, #-58]!	; 0xffffffc6
    1044:	656c2c78 	strbvs	r2, [ip, #-3192]!	; 0xfffff388
    1048:	64253a6e 	strtvs	r3, [r5], #-2670	; 0xfffff592
    104c:	00000000 	andeq	r0, r0, r0
    1050:	61527865 	cmpvs	r2, r5, ror #16
    1054:	64253a6d 	strtvs	r3, [r5], #-2669	; 0xfffff593
    1058:	65722042 	ldrbvs	r2, [r2, #-66]!	; 0xffffffbe
    105c:	72697571 	rsbvc	r7, r9, #473956352	; 0x1c400000
    1060:	002e6465 	eoreq	r6, lr, r5, ror #8
    1064:	61527865 	cmpvs	r2, r5, ror #16
    1068:	63733a6d 	cmnvs	r3, #446464	; 0x6d000
    106c:	73206e61 			; <UNDEFINED> instruction: 0x73206e61
    1070:	7070696b 	rsbsvc	r6, r0, fp, ror #18
    1074:	00216465 	eoreq	r6, r1, r5, ror #8
    1078:	61527865 	cmpvs	r2, r5, ror #16
    107c:	7465446d 	strbtvc	r4, [r5], #-1133	; 0xfffffb93
    1080:	3a746365 	bcc	0x1d19e1c
    1084:	72617473 	rsbvc	r7, r1, #1929379840	; 0x73000000
    1088:	78303a74 	ldmdavc	r0!, {r2, r4, r5, r6, r9, fp, ip, sp}
    108c:	202c7825 	eorcs	r7, ip, r5, lsr #16
    1090:	3a646e65 	bcc	0x191ca2c
    1094:	78257830 	stmdavc	r5!, {r4, r5, fp, ip, sp, lr}
    1098:	00000000 	andeq	r0, r0, r0
    109c:	61527865 	cmpvs	r2, r5, ror #16
    10a0:	7465446d 	strbtvc	r4, [r5], #-1133	; 0xfffffb93
    10a4:	3a746365 	bcc	0x1d19e40
    10a8:	55423154 	strbpl	r3, [r2, #-340]	; 0xfffffeac
    10ac:	78303a46 	ldmdavc	r0!, {r1, r2, r6, r9, fp, ip, sp}
    10b0:	00007825 	andeq	r7, r0, r5, lsr #16
    10b4:	61527865 	cmpvs	r2, r5, ror #16
    10b8:	7465446d 	strbtvc	r4, [r5], #-1133	; 0xfffffb93
    10bc:	3a746365 	bcc	0x1d19e58
    10c0:	55423254 	strbpl	r3, [r2, #-596]	; 0xfffffdac
    10c4:	78303a46 	ldmdavc	r0!, {r1, r2, r6, r9, fp, ip, sp}
    10c8:	00007825 	andeq	r7, r0, r5, lsr #16
    10cc:	68636163 	stmdavs	r3!, {r0, r1, r5, r6, r8, sp, lr}^
    10d0:	78652f65 	stmdavc	r5!, {r0, r2, r5, r6, r8, r9, sl, fp, sp}^
    10d4:	61632e72 	smcvs	13026	; 0x32e2
    10d8:	00000063 	andeq	r0, r0, r3, rrx
    10dc:	65737361 	ldrbvs	r7, [r3, #-865]!	; 0xfffffc9f
    10e0:	663a7472 			; <UNDEFINED> instruction: 0x663a7472
    10e4:	3a656c69 	bcc	0x195c290
    10e8:	6c2c7325 	stcvs	3, cr7, [ip], #-148	; 0xffffff6c
    10ec:	3a656e69 	bcc	0x195ca98
    10f0:	00006425 	andeq	r6, r0, r5, lsr #8
    10f4:	0000005c 	andeq	r0, r0, ip, asr r0
    10f8:	5f63726d 	svcpl	0x0063726d
    10fc:	65666173 	strbvs	r6, [r6, #-371]!	; 0xfffffe8d
    1100:	726f7453 	rsbvc	r7, pc, #1392508928	; 0x53000000
    1104:	5f656761 	svcpl	0x00656761
    1108:	74697277 	strbtvc	r7, [r9], #-631	; 0xfffffd89
    110c:	00000065 	andeq	r0, r0, r5, rrx
    1110:	5f63726d 	svcpl	0x0063726d
    1114:	65666173 	strbvs	r6, [r6, #-371]!	; 0xfffffe8d
    1118:	726f7453 	rsbvc	r7, pc, #1392508928	; 0x53000000
    111c:	5f656761 	svcpl	0x00656761
    1120:	64616572 	strbtvs	r6, [r1], #-1394	; 0xfffffa8e
    1124:	63757320 	cmnvs	r5, #32, 6	; 0x80000000
    1128:	73736563 	cmnvc	r3, #415236096	; 0x18c00000
    112c:	0000002e 	andeq	r0, r0, lr, lsr #32
    1130:	00000000 	andeq	r0, r0, r0
