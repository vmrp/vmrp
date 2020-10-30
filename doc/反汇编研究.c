// struct mr_c_function_P{
//     0x0,  start_of_ER_RW
//     0x4,  ER_RW_Length
//     0x8,  ext_type
//     0xC,  mrc_extChunk
//     0x10,  stack
// }

// sizeof(mr_c_function_P) = 0x14

int mr_c_function_load(int code) {
    if (code == 1) {  // ext启动（插件模式）
        if (mr_table._mr_c_function_new(mr_extHelper, sizeof(mr_c_function_P)) == -1) {
            return -1;
        }
        mr_c_function_P.ext_type = 1;
        mr_table.mr_timerStart = mrc_extTimerStart;
        mr_table.mr_timerStop = mrc_extTimerStop;

    } else {
        if (mr_table._mr_c_function_new(mr_helper, sizeof(mr_c_function_P)) == -1) {
            return -1;
        }
        mr_c_function_P.ext_type = 0;
    }
    mr_c_function_P.ER_RW_Length = mr_helper_get_rw_len();
    mr_c_function_P.start_of_ER_RW = mrc_malloc(mr_c_function_P.ER_RW_Length);
    if (mr_c_function_P.start_of_ER_RW) {
        mr_table.memcpy(
            mr_c_function_P.start_of_ER_RW,
            mr_helper_get_ro_len() + mr_load_c_function,
            mr_helper_get_rw_lenOnly());
        mr_table.memset(
            mr_c_function_P.start_of_ER_RW + mr_helper_get_rw_lenOnly(),
            0,
            mr_c_function_P.ER_RW_Length - mr_helper_get_rw_lenOnly());
        return 0;
    }
    return -1;
}

void *mrc_malloc(uint32 len) {
    uint32 *p = mr_table.mr_malloc(len + sizeof(uint32));
    if (p) {
        *p = len;
        return p + 1;
    }
    return p;
}

void mrc_free(void *param_1) {
    if (param_1 == 0) {
        return;
    }
    param_1 = (uint32 *)param_1 - 1;
    mr_table.mr_free(param_1, *param_1 + sizeof(uint32));
    return;
}

//RW：程序中已经初始化的变量所占空间
//ZI：未初始化的static变量和全局变量以及堆栈所占的空间
unsigned int mr_helper_get_rw_len() {
    return Image$$ER_RW$$Length + Image$$ER_ZI$$ZI$$Length;
}
unsigned int mr_helper_get_rw_lenOnly() {
    return Image$$ER_RW$$Length;
}
unsigned int mr_helper_get_ro_len() {
    return Image$$ER_RO$$Length;
}

typedef struct {
    int32 id;
    int32 ver;
    char *sidName;
    int32 ram;
} mrc_appInfoSt_st;

void mr_helper_set_sb(v) {
    r9 = v;
}

void _mr_init_c_helper_function(void) {
    mrc_timerInit();
    *(undefined4 *)(unaff_r9 + 0x1c) = 1;
    *(undefined4 *)(unaff_r9 + 0x30) = mr_table.mr_printf;
    *(undefined4 *)(unaff_r9 + 0x34) = mr_table.memcpy;
    *(undefined4 *)(unaff_r9 + 0x38) = mr_table.memmove;
    *(undefined4 *)(unaff_r9 + 0x3c) = mr_table.strcpy;
    *(undefined4 *)(unaff_r9 + 0x40) = mr_table.strncpy;
    *(undefined4 *)(unaff_r9 + 0x44) = mr_table.strcat;
    *(undefined4 *)(unaff_r9 + 0x48) = mr_table.strncat;
    *(undefined4 *)(unaff_r9 + 0x4c) = mr_table.memcmp;
    *(undefined4 *)(unaff_r9 + 0x50) = mr_table.strcmp;
    *(undefined4 *)(unaff_r9 + 0x54) = mr_table.strncmp;
    *(undefined4 *)(unaff_r9 + 0x58) = mr_table.strcoll;
    *(undefined4 *)(unaff_r9 + 0x5c) = mr_table.memchr;
    *(undefined4 *)(unaff_r9 + 0x60) = mr_table.memset;
    *(undefined4 *)(unaff_r9 + 0x64) = mr_table.strlen;
    *(undefined4 *)(unaff_r9 + 0x68) = mr_table.strstr;
    *(undefined4 *)(unaff_r9 + 0x6c) = mr_table.sprintf;
    *(undefined4 *)(unaff_r9 + 0x70) = mr_table.atoi;
    *(undefined4 *)(unaff_r9 + 0x74) = mr_table.strtoul;
    *(undefined4 *)(unaff_r9 + 0x100) = 0;
    if (mr_table._mr_TestCom(0, 7, 9999) == 9999) {
        *(undefined4 *)(unaff_r9 + 0x2c) = 0x270d;
    }
}

typedef void (*mrc_timerCB)(int32 data);

typedef struct mrc_timerSt {        /* TIMER CONTROL BLOCK      */
    /* 0x00 */ int32 check;         /* check this value,is the timer valid?             */
    /* 0x04 */ int32 time;          /* timeout time             */
    /* 0x08 */ int32 left;          /* time left before timeout */
    /* 0x0c */ mrc_timerCB handler; /* event handler            */
    /* 0x10 */ int32 data;
    /* 0x14 */ int32 loop;
    /* 0x18 */ struct mrc_timerSt *next;  /* next in active chain     */
    /* 0x1c */ struct mrc_timerSt *next2; /* next in timeout chain     */
} mrc_timerSt;

// 0x4 + r9 + 0x88
mrc_timerSt *timerChain;
// 0x4 + r9 + 0x8c
mrc_timerSt *timeoutChain;
uint32 stopTime;

void mrc_timerInit(void) {
    timerChain = NULL;
    stopTime = 0;
    timeoutChain = NULL;
}

int32 mrc_timerCreate(void) {
    mrc_timerSt *puVar1 = mrc_malloc(sizeof(mrc_timerSt));
    if (puVar1 == NULL) {
        mr_table.mr_printf("timerCreate err 01");
        return 0;
    } else {
        puVar1.check = 0x79abbccf;
        puVar1.handler = NULL;
        puVar1.time = 0;
        puVar1.data = 0;
        puVar1.next = NULL;
        puVar1.next2 = NULL;
        puVar1.left = 0;
    }
    return puVar1;
}

int mrc_vmTimerStart(uint param_1) {
    int iVar1 = mr_table.mr_timerStart(param_1 & 0xffff);
    if (iVar1 == 0) {
        mr_table._mr_c_internal_table.mr_timer_state = MR_TIMER_STATE_RUNNING;
    }
    return iVar1;
}

void mrc_vmTimerStop(void) {
    mr_table._mr_c_internal_table.mr_timer_state = MR_TIMER_STATE_IDLE;
    return mr_table.mr_timerStop();
}

void mrc_timerStartEx(int param_1) {
    stopTime = mr_table.mr_getTime() + param_1;
    mrc_vmTimerStop();
    return mrc_vmTimerStart(param_1);
}

int mrc_timerLeft(void) {
    if (stopTime == 0) {
        return 0;
    }
    return stopTime - mr_table.mr_getTime();
}

int32 mrc_timerStart(mrc_timerSt *t, int time, int data, int cb, int loop) {
    if (t == NULL) {
        mr_table.mr_printf("timer err:%d", 1000);
        return -1;
    }

    state = mr_table._mr_c_internal_table.mr_state;
    if (state == MR_STATE_RESTART || state == MR_STATE_STOP) {
        return -1;
    }
    if (t->check != 0x79abbccf) {
        mr_table.mr_printf("timer err:%d", 1001);
        return -1;
    }

    if (time != 0) {
        t->time = time;
    }
    t->data = data;
    t->left = 0;
    if (cb != NULL) {
        t->handler = cb;
    }
    t->loop = loop;
    if (t->time <= 0) {
        return -1;
    }
    if (t->time < 10) {
        t->time = 10;
    }
    t->left = t->time;
    iVar3 = mrc_timerLeft();
    if (timerChain != NULL) {
        iVar1 = timerChain->time;
        if (iVar3 < 0) {
            iVar3 = 0;
        }
        if (iVar1 + 5 < iVar3) {
            iVar3 = iVar1;
        }
    }
    mrc_timerRemove(t);

    r1 = timerChain;
    if ((r1 == NULL) || (t->left < iVar3) {
        r0 = t->left;
        t->left = 0;
        while (r1 != NULL) {
            r1->left += (iVar3 - r0);
            r1 = r1->next;
        }
        mrc_timerStartEx(r0);
    } else {
        t->left = t->left - iVar3;
    }

    if (timerChain == NULL) {
        timerChain = t;
        t->next = 0;
        return 0;
    }

    iVar3 = timerChain;
    if (t->left < iVar3->left) {
        t->next = iVar3;
        timerChain = t;
        return 0;
    }

    do {
        iVar1 = iVar3;
        iVar3 = iVar3->next;
        if (iVar3 == 0) break;
    } while (iVar3->left <= t->left);
    iVar1->next = t;
    t->next = iVar3;
    return 0;
}

void mrc_timerRemove(mrc_timerSt *param_1) {
    if (param_1 == 0) {
        return;
    }
    iVar2 = timerChain;
    if (iVar2 == param_1) {
        timerChain = param_1->next;
    } else if (iVar2 != NULL) {
        iVar1 = iVar2->next;
        while (iVar1 != NULL) {
            if (iVar1 == param_1) {
                iVar2->next = iVar1->next;
                break;
            }
            iVar2 = iVar1;
            iVar1 = iVar1->next;
        }
    }

    iVar2 = timeoutChain;
    if (iVar2 == NULL) {
        return;
    }
    if (iVar2 == param_1) {
        timeoutChain = iVar2->next2;
        return;
    }
    iVar1 = iVar2->next2;
    while (iVar1 != NULL) {
        if (iVar1 == param_1) {
            iVar2->next2 = iVar1->next2;
            return;
        } else {
            iVar2 = iVar1;
            iVar1 = iVar1->next2;
        }
    }
}

typedef struct
{
    uint32 width;   //屏幕宽
    uint32 height;  //屏幕高
    uint32 bit;     //屏幕象素深度，单位bit
} mr_screeninfo;

int32 mrc_getScreenInfo(mr_screeninfo *s) {
    return mr_table.mr_getScreenInfo(s);
}

void mrc_timerTimeout(void) {
    r0 = mr_table.mr_getTime() - stopTime;

    r4 = NULL;
    stopTime = 0;
    if (timerChain == NULL) {
        return;
    }
    if (timerChain.left == 0) {
        r2 = r0;
        if (r2 < 50) {
            r2 = 50;
        } else if (r2 > 2000) {
            r2 = 2000;
        }
        r4 = timerChain;

        timerChain.left = -1;
        r1 = timerChain;
        timerChain = timerChain.next;
        while ((timerChain != NULL) && (timerChain.left < r2)) {
            timerChain.left = -1;
            r1.next2 = timerChain;
            r1 = timerChain;
            timerChain = timerChain.next;
        }
        r1.next2 = 0;
    }
    if (timerChain != NULL) {
        r1 = timerChain;
        r2 = r1.left;
        if (r2 < 0) {
            r2 = 0;
            r1.left = 0;
        } else if (r2 > 0xffff) {
            r2 = 0xffff;
        }
        do {
            r1.left = r1.left - r2;
            r1 = r1.next;
        } while (r1 != 0);
        if (r0 < 0) {
            r0 = 0;
        }
        r0 = r2 - r0;
        if (r0 <= 0) {
            r0 = 10;
        }
        mrc_timerStartEx(r0);
    }

    while ((r4 != NULL) && (r4.left < 0)) {
        r4.left = 0;
        timeoutChain = r4.next2;
        if (r4.loop != 0) {
            mrc_timerStart(r4, 0, r4.data, NULL, r4.loop);
        }
        if (r4.handler != NULL) {
            r4.handler(r4.data);
        }
        r4 = timeoutChain;
    }
    timeoutChain = NULL;
}

typedef int32 (*mrc_extMainSendAppMsg_t)(int32 extCode, int32 app, int32 code, int32 param0, int32 param1);

typedef struct _mrc_extChunk_st {
    /* 0x00 */ int32 check;                     //0x7FD854EB 标志
    /* 0x04 */ MR_LOAD_C_FUNCTION init_func;    //mr_c_function_load 函数指针
    /* 0x08 */ MR_C_FUNCTION event;             //mr_helper 函数指针
    /* 0x0c */ uint8 *code_buf;                 //ext内存地址
    /* 0x10 */ int32 code_len;                  //ext长度
    /* 0x14 */ uint8 *var_buf;                  //RW段地址
    /* 0x18 */ int32 var_len;                   //RW段长度
    /* 0x1c */ mr_c_function_st *global_p_buf;  //mr_c_function_st 表地址
    /* 0x20 */ int32 global_p_len;              //mr_c_function_st 表长度
    /* 0x24 */ int32 timer;
    /* 0x28 */ mrc_extMainSendAppMsg_t sendAppEvent;
    /* 0x2c */ mr_table *extMrTable;  // mr_table函数表。
    MR_C_FUNCTION_EX eventEx;
    int32 isPause; /*1: pause 状态0:正常状态*/
} mrc_extChunk_st;

void mrc_extTimerStart(undefined4 param1) {
    r1 = mr_c_function_P->mrc_extChunk;
    r1->sendAppEvent(0, r1, 0, r1->timer, param1);
}

void mrc_extTimerStop(void) {
    r1 = mr_c_function_P->mrc_extChunk;
    r1->sendAppEvent(0, r1, 1, r1->timer, 0);
}

mrc_refreshScreenReal() {
    if (*(int *)(unaff_r9 + 0x78) == 0) {
        mrc_getScreenInfo(&local_14);
        *(undefined4 *)(unaff_r9 + 0x80) = local_14;  // w
        *(undefined4 *)(unaff_r9 + 0x84) = local_10;  // h
        *(undefined4 *)(unaff_r9 + 0x78) = 1;
    }

    if (*(int *)(unaff_r9 + 0x7c) == 1) {
        h = (unaff_r9 + 0x84) & 0xffff;
        w = (unaff_r9 + 0x80) & 0xffff;
        mr_table.mr_drawBitmap(mr_table.mr_screenBuf, 0, 0, w, h);
    }
    *(undefined4 *)(unaff_r9 + 0x7c) = 0;
    return 0;
}

typedef int32 (*MR_C_FUNCTION)(void *P, int32 code, uint8 *input, int32 input_len, uint8 **output, int32 *output_len);

typedef struct _mini_mr_c_event_st {
    int32 code;
    int32 param0;
    int32 param1;
    int32 param2;
    int32 param3;
} mini_mr_c_event_st;

mrc_extHelper(P, code, input, input_len) {
    r5 = r0;
    r8 = r1;
    r6 = r2;
    r7 = r3;

    r4 = 0;
    r10 = r9;
    mr_helper_set_sb(*P);
    switch (code) {
        case 0:
            (unaff_r9 + 0x18) = P.mrc_extChunk;
            _mr_init_c_helper_function();
            r4 = mrc_init();
            break;
        case (code *)0x1:
            r4 = mrc_event(input.code, input.param0, input.param1);
            if (input.code == 0x8) {
                r4 = mrc_exitApp();
            }
            break;
        case (code *)0x2:
            mrc_timerTimeout();
            break;
        case (code *)0x3:
            P.mrc_extChunk = input_len;
            break;
        case (code *)0x4:
            mrc_pause();
            break;
        case (code *)0x5:
            mrc_resume();
            break;
        case (code *)0x6:  //MR_VERSION
            (unaff_r9 + 0x20) = input_len;
            break;
        case (code *)0x8:  // (char*)&mrc_appInfo_st
            (unaff_r9 + 0x24) = input;
            break;
        case (code *)0x9:
            if (input[0] != 0) {
                r4 = input[0](input[0], input[1], input[2], input[3], input[5], input[6]);
            }
            break;
    }
    r9 = r10;
    r0 = r4;
    return;
}

mr_helper(P, code, input, input_len) {
    r6 = r0;  //p
    r8 = r3;  //input_len
    r7 = r1;  //code
    r5 = r2;  //input

    r10 = r9;
    r4 = 0;
    mr_helper_set_sb(*P);
    switch (code) {
        case 0:
            (unaff_r9 + 0x18) = P.mrc_extChunk;
            _mr_init_c_helper_function();
            r4 = mrc_init();
            mrc_refreshScreenReal();
            mr_table._mr_c_internal_table.mr_timer_p = "dealtimer";
            break;
        case (code *)0x1:
            r4 = mrc_event(input.code, input.param0, input.param1);
            if (input.code == 0x8) {
                r4 = mrc_exitApp();
            }
            goto LAB_00080338;
        case (code *)0x2:
            mrc_timerTimeout();
            goto LAB_00080338;
        case (code *)0x4:
            mrc_pause();
            goto LAB_00080338;
        case (code *)0x5:
            mrc_resume();
        LAB_00080338:
            mrc_refreshScreenReal();
            break;
        case (code *)0x6:  //MR_VERSION
            (unaff_r9 + 0x20) = input_len;
            break;
        case (code *)0x8:  // (char*)&mrc_appInfo_st
            (unaff_r9 + 0x24) = input;
            break;
        case (code *)0x9:
            if (input[0] != 0) {
                r4 = input[0](input[0], input[1], input[2], input[3], input[5], input[6]);
            }
    }
    r9 = r10;
    r0 = r4;
    return;
}

void mrc_timerStop(t) {
    mrc_timerRemove(t);
}

int32 mrc_timerSetTimeEx(mrc_timerSt *t, int32 time) {
    if ((t != NULL) && (t->check == 0X79ABBCCF)) {
        t->time = time;
        return 0;
    }
    return -1;
}

void mrc_timerDelete(mrc_timerSt *t) {
    mrc_timerRemove(t);
    t->check = 0;
    mrc_free(t);
}

// 以上所有定时器函数在手册中可见的函数只有以下五个
int32 mrc_timerCreate(void);
void mrc_timerDelete(int32 t);
void mrc_timerStop(int32 t);
int32 mrc_timerStart(int32 t, int32 time, int32 data, mrc_timerCB f, int32 loop);
int32 mrc_timerSetTimeEx(int32 t, int32 time);

// [PC:0x2B195A  nZCv   adds r1, r5, #0   THUMB  mem:0x2B195A]> 0x002AEF38
// ==> read memory addr: 0x2aef38=0x0  ....

// 2b0ee4 解压的game.ext
// 2b0f10 写入的r0
// 2b1996 r0参数

// 002b3d1a
// R6=0x002B5388
// 0x002B5388+8 = 0x002B5390()

// dump,game.ext,0x0034B36C,0x1cfa4
// [PC:0x2B1120  nzcv   str r5, [r0]   THUMB  mem:0x2B1120]> dump,abc.mrp,0x002C2470,0x000106D2
