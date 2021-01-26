#include "./header/bridge.h"

#include <ctype.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "./header/dsm.h"
#include "./header/fileLib.h"
#include "./header/gb2unicode.h"
#include "./header/memory.h"
#include "./header/tsf_font.h"
#include "./header/vmrp.h"
#include "./header/network.h"

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#endif
//////////////////////////////////////////////////////////////////////////////////////////
#ifdef LOG
#undef LOG
#endif

#ifdef DEBUG
#define LOG(format, ...) printf("   -> bridge: " format, ##__VA_ARGS__)
#else
#define LOG(format, ...)
#endif

#define SET_RET_V(ret)                        \
    {                                         \
        uint32_t _v = ret;                    \
        uc_reg_write(uc, UC_ARM_REG_R0, &_v); \
    }

typedef struct _mr_c_event_st {
    int32 code;
    int32 param0;
    int32 param1;
    int32 param2;
    int32 param3;
} _mr_c_event_st;

static _mr_c_event_st *mr_c_event;  // 用于mrc_event参数传递的内存

static uint32_t mr_helper_addr;  //mrc_extHelper()函数的地址
static uint32_t baseLib_cfunction_ext_mem;

// data ////////////////////////////////////////////////////////////////////////////////////////

static void br_mr_screen_h_init(BridgeMap *o, uc_engine *uc, uint32_t addr) {
    LOG("br_%s_init() 0x%X[%u]\n", o->name, addr, addr);
    uint32_t *mr_screen_h = my_mallocExt(4);
    *mr_screen_h = SCREEN_HEIGHT;
    uint32_t *p = getMrpMemPtr(addr);
    *p = toMrpMemAddr(mr_screen_h);
}

static void br_mr_screen_w_init(BridgeMap *o, uc_engine *uc, uint32_t addr) {
    LOG("br_%s_init() 0x%X[%u]\n", o->name, addr, addr);
    uint32_t *mr_screen_w = my_mallocExt(4);
    *mr_screen_w = SCREEN_WIDTH;
    uint32_t *p = getMrpMemPtr(addr);
    *p = toMrpMemAddr(mr_screen_w);
}

static void br_mr_screenBuf_init(BridgeMap *o, uc_engine *uc, uint32_t addr) {
    LOG("br_%s_init() 0x%X[%u]\n", o->name, addr, addr);
    uint32_t *mr_screenBuf = my_mallocExt(4);
    *mr_screenBuf = SCREEN_BUF_ADDRESS;
    uint32_t *p = getMrpMemPtr(addr);
    *p = toMrpMemAddr(mr_screenBuf);
}
// func ////////////////////////////////////////////////////////////////////////////////////////

static void br__mr_c_function_new(BridgeMap *o, uc_engine *uc) {
    // typedef int32 (*T__mr_c_function_new)(MR_C_FUNCTION f, int32 len);
    uint32_t p_f, p_len;
    uc_reg_read(uc, UC_ARM_REG_R0, &p_f);
    uc_reg_read(uc, UC_ARM_REG_R1, &p_len);
    printf("ext call %s(0x%X[%u], 0x%X[%u])\n", o->name, p_f, p_f, p_len, p_len);
    dumpREG(uc);
    mr_helper_addr = p_f;
    printf("mrc_extHelper() addr:0x%X\n", mr_helper_addr);
    SET_RET_V(MR_SUCCESS);
}

static void br_mr_malloc(BridgeMap *o, uc_engine *uc) {
    // typedef void* (*T_mr_malloc)(uint32 len);
    uint32_t len;
    uc_reg_read(uc, UC_ARM_REG_R0, &len);
    void *p = my_mallocExt(len);
    if (p) {
        uint32_t ret = toMrpMemAddr(p);
        LOG("ext call %s(0x%X[%u]) ret=0x%X[%u]\n", o->name, len, len, ret, ret);
        SET_RET_V(ret);
        return;
    }
    SET_RET_V((uint32_t)NULL);
}

static void br_mr_free(BridgeMap *o, uc_engine *uc) {
    // typedef void  (*T_mr_free)(void* p, uint32 len);
    uint32_t p, len;
    uc_reg_read(uc, UC_ARM_REG_R0, &p);
    uc_reg_read(uc, UC_ARM_REG_R1, &len);

    LOG("ext call %s(0x%X[%u], 0x%X[%u])\n", o->name, p, p, len, len);
    my_freeExt(getMrpMemPtr(p));
}

static void br__mr_TestCom(BridgeMap *o, uc_engine *uc) {
    // typedef int32 (*T__mr_TestCom)(int32 L, int input0, int input1);
    uint32_t L, input0, input1;

    uc_reg_read(uc, UC_ARM_REG_R0, &L);
    uc_reg_read(uc, UC_ARM_REG_R1, &input0);
    uc_reg_read(uc, UC_ARM_REG_R2, &input1);

    LOG("ext call %s(0x%X[%u], 0x%X[%u], 0x%X[%u])\n", o->name, L, L, input0, input0, input1, input1);
    SET_RET_V(MR_SUCCESS);
}

static inline void setPixel(int32_t x, int32_t y, uint16_t color, void *userData) {
    if (x < 0 || y < 0 || x >= SCREEN_WIDTH || y >= SCREEN_HEIGHT) {
        return;
    }
    *(screenBuf + (x + SCREEN_WIDTH * y)) = color;
}

static void br__DrawPoint(BridgeMap *o, uc_engine *uc) {
    // typedef  void (*T__DrawPoint)(int16 x, int16 y, uint16 nativecolor);
    uint32_t x, y, nativecolor;

    uc_reg_read(uc, UC_ARM_REG_R0, &x);
    uc_reg_read(uc, UC_ARM_REG_R1, &y);
    uc_reg_read(uc, UC_ARM_REG_R2, &nativecolor);

    LOG("ext call %s(0x%X, 0x%X, 0x%X)\n", o->name, x, y, nativecolor);
    LOG("ext call %s([%u], [%u], [%u])\n", o->name, x, y, nativecolor);
    setPixel(x, y, nativecolor, uc);
}

// 实际上mrc_clearScreen()也是调用的这个方法
static void br_DrawRect(BridgeMap *o, uc_engine *uc) {
    // typedef  void (*T_DrawRect)(int16 x, int16 y, int16 w, int16 h, uint8 r, uint8 g, uint8 b);
    uint32_t x, y, w, h, r, g, b;
    // 前四个参数是通过寄存器传递
    uc_reg_read(uc, UC_ARM_REG_R0, &x);
    uc_reg_read(uc, UC_ARM_REG_R1, &y);
    uc_reg_read(uc, UC_ARM_REG_R2, &w);
    uc_reg_read(uc, UC_ARM_REG_R3, &h);

    // 后面的参数通过栈传递（注意内存对齐遵循ATPCS）
    uint32_t sp;
    uc_reg_read(uc, UC_ARM_REG_SP, &sp);
    uc_mem_read(uc, sp, &r, 4);
    uc_mem_read(uc, sp + 4, &g, 4);
    uc_mem_read(uc, sp + 8, &b, 4);

    LOG("ext call %s(%d, %d, %d, %d, %u, %u, %u)\n", o->name, x, y, w, h, r, g, b);
    uint16_t color = MAKERGB565(r, g, b);

    for (uint32_t i = 0; i < w; i++) {
        for (uint32_t j = 0; j < h; j++) {
            setPixel(x + i, y + j, color, uc);
        }
    }
}

static void br__DrawText(BridgeMap *o, uc_engine *uc) {
    // typedef  int32 (*T__DrawText)(char* pcText, int16 x, int16 y, uint8 r, uint8 g, uint8 b, int is_unicode, uint16 font);
    uint32_t pcText, x, y, r, g, b, is_unicode, font;

    uc_reg_read(uc, UC_ARM_REG_R0, &pcText);
    uc_reg_read(uc, UC_ARM_REG_R1, &x);
    uc_reg_read(uc, UC_ARM_REG_R2, &y);
    uc_reg_read(uc, UC_ARM_REG_R3, &r);

    uint32_t sp;
    uc_reg_read(uc, UC_ARM_REG_SP, &sp);
    uc_mem_read(uc, sp, &g, 4);
    uc_mem_read(uc, sp + 4, &b, 4);
    uc_mem_read(uc, sp + 8, &is_unicode, 4);
    uc_mem_read(uc, sp + 12, &font, 4);

    char *str = getMrpMemPtr(pcText);
    LOG("ext call %s(0x%X[\"%s\"], %d, %d, %u, %u, %u, %d, %u)\n", o->name, pcText, str, x, y, r, g, b, is_unicode, font);
    if (is_unicode) {
        tsf_drawText((uint8_t *)str, x, y, MAKERGB565(r, g, b), uc);
    } else {
        uint8_t *out = (uint8_t *)gbToUCS2BE((uint8_t *)str, NULL);
        tsf_drawText(out, x, y, MAKERGB565(r, g, b), uc);
        free(out);
    }
    SET_RET_V(MR_SUCCESS);
}

// 实际上mrc_refreshScreen()是调用的这个方法
static void br_mr_drawBitmap(BridgeMap *o, uc_engine *uc) {
    // typedef void (*T_mr_drawBitmap)(uint16* bmp, int16 x, int16 y, uint16 w, uint16 h);
    uint32_t bmp, x, y, w, h;

    uc_reg_read(uc, UC_ARM_REG_R0, &bmp);
    uc_reg_read(uc, UC_ARM_REG_R1, &x);
    uc_reg_read(uc, UC_ARM_REG_R2, &y);
    uc_reg_read(uc, UC_ARM_REG_R3, &w);

    uint32_t sp;
    uc_reg_read(uc, UC_ARM_REG_SP, &sp);
    uc_mem_read(uc, sp, &h, 4);

    LOG("ext call %s(0x%X, %d, %d, %u, %u)\n", o->name, bmp, x, y, w, h);
    guiDrawBitmap(getMrpMemPtr(bmp), x, y, w, h);
}

static void br_mr_open(BridgeMap *o, uc_engine *uc) {
    // typedef int32 (*T_mr_open)(const char* filename,  uint32 mode);
    uint32_t filename, mode;
    uc_reg_read(uc, UC_ARM_REG_R0, &filename);
    uc_reg_read(uc, UC_ARM_REG_R1, &mode);
    char *filenameStr = getMrpMemPtr(filename);
    int32_t ret = my_open(filenameStr, mode);
    LOG("ext call %s(0x%X[%s], 0x%X): %d\n", o->name, filename, filenameStr, mode, ret);
    SET_RET_V(ret);
}

static void br_mr_close(BridgeMap *o, uc_engine *uc) {
    // typedef int32 (*T_mr_close)(int32 f);
    uint32_t f, ret;
    uc_reg_read(uc, UC_ARM_REG_R0, &f);
    ret = my_close(f);
    LOG("ext call %s(%d): %d\n", o->name, f, ret);
    SET_RET_V(ret);
}

static void br_mr_write(BridgeMap *o, uc_engine *uc) {
    // typedef int32 (*T_mr_write)(int32 f,void *p,uint32 l);
    uint32_t f, p, l, ret;

    uc_reg_read(uc, UC_ARM_REG_R0, &f);
    uc_reg_read(uc, UC_ARM_REG_R1, &p);
    uc_reg_read(uc, UC_ARM_REG_R2, &l);

    LOG("ext call %s(0x%X, 0x%X, 0x%X)\n", o->name, f, p, l);
    LOG("ext call %s([%u], [%u], [%u])\n", o->name, f, p, l);

    char *buf = malloc(l);
    uc_mem_read(uc, p, buf, l);
    ret = my_write(f, buf, l);
    free(buf);

    SET_RET_V(ret);
}

static void br_mr_read(BridgeMap *o, uc_engine *uc) {
    // typedef int32 (*T_mr_read)(int32 f,void *p,uint32 l);
    uint32_t f, p, l, ret;
    uc_reg_read(uc, UC_ARM_REG_R0, &f);
    uc_reg_read(uc, UC_ARM_REG_R1, &p);
    uc_reg_read(uc, UC_ARM_REG_R2, &l);
    char *buf = getMrpMemPtr(p);
    ret = my_read(f, buf, l);
    LOG("ext call %s(%d, 0x%X, %u): %d\n", o->name, f, p, l, ret);
    SET_RET_V(ret);
}

static void br_mr_seek(BridgeMap *o, uc_engine *uc) {
    // typedef int32 (*T_mr_seek)(int32 f, int32 pos, int method);
    uint32_t f, pos, method, ret;
    uc_reg_read(uc, UC_ARM_REG_R0, &f);
    uc_reg_read(uc, UC_ARM_REG_R1, &pos);
    uc_reg_read(uc, UC_ARM_REG_R2, &method);
    ret = my_seek(f, pos, method);
    LOG("ext call %s(%d, %d, 0x%X): %d\n", o->name, f, pos, method, ret);
    SET_RET_V(ret);
}

static void br_mr_getLen(BridgeMap *o, uc_engine *uc) {
    // typedef int32 (*T_mr_getLen)(const char* filename);
    uint32_t filename;
    uc_reg_read(uc, UC_ARM_REG_R0, &filename);
    char *filenameStr = getMrpMemPtr(filename);
    LOG("ext call %s(%s)\n", o->name, filenameStr);
    SET_RET_V(my_getLen(filenameStr));
}

static void br_mr_remove(BridgeMap *o, uc_engine *uc) {
    // typedef int32 (*T_mr_remove)(const char* filename);
    uint32_t filename;
    uc_reg_read(uc, UC_ARM_REG_R0, &filename);
    char *filenameStr = getMrpMemPtr(filename);
    LOG("ext call %s(%s)\n", o->name, filenameStr);
    SET_RET_V(my_remove(filenameStr));
}

static void br_mr_rename(BridgeMap *o, uc_engine *uc) {
    // typedef int32 (*T_mr_rename)(const char* oldname, const char* newname);
    uint32_t oldname, newname;
    uc_reg_read(uc, UC_ARM_REG_R0, &oldname);
    uc_reg_read(uc, UC_ARM_REG_R1, &newname);
    char *oldnameStr = getMrpMemPtr(oldname);
    char *newnameStr = getMrpMemPtr(newname);
    LOG("ext call %s(%s, %s)\n", o->name, oldnameStr, newnameStr);
    SET_RET_V(my_rename(oldnameStr, newnameStr));
}

static void br_mr_mkDir(BridgeMap *o, uc_engine *uc) {
    // typedef int32 (*T_mr_mkDir)(const char* name);
    uint32_t name;
    uc_reg_read(uc, UC_ARM_REG_R0, &name);
    char *nameStr = getMrpMemPtr(name);
    LOG("ext call %s(%s)\n", o->name, nameStr);
    SET_RET_V(my_mkDir(nameStr));
}

static void br_mr_rmDir(BridgeMap *o, uc_engine *uc) {
    // typedef int32 (*T_mr_rmDir)(const char* name);
    uint32_t name;
    uc_reg_read(uc, UC_ARM_REG_R0, &name);
    char *nameStr = getMrpMemPtr(name);
    LOG("ext call %s(%s)\n", o->name, nameStr);
    SET_RET_V(my_rmDir(nameStr));
}

static void br_atoi(BridgeMap *o, uc_engine *uc) {
    // typedef int (*T_atoi)(const char * nptr);
    uint32_t nptr;
    uc_reg_read(uc, UC_ARM_REG_R0, &nptr);
    char *str = getMrpMemPtr(nptr);
    LOG("ext call %s(0x%X[%s])\n", o->name, nptr, str);
    SET_RET_V(atoi(str));
}

static void br_mr_exit(BridgeMap *o, uc_engine *uc) {
    // typedef int32 (*T_mr_exit)(void);
    LOG("##### ext call %s()\n", o->name);
    SET_RET_V(MR_SUCCESS);
}

static void br_mr_getScreenInfo(BridgeMap *o, uc_engine *uc) {
    // int32 mr_getScreenInfo(mr_screeninfo * s) ;
    LOG("##### ext call %s()\n", o->name);

    uint32_t addr;
    uc_reg_read(uc, UC_ARM_REG_R0, &addr);

    struct {
        uint32 width;
        uint32 height;
        uint32 bit;
    } *s = getMrpMemPtr(addr);

    if (s) {
        s->width = SCREEN_WIDTH;
        s->height = SCREEN_HEIGHT;
        s->bit = 16;
    }
    SET_RET_V(MR_SUCCESS);
}

//////////////////////////////////////////////////////////////////////////////////////////
static void br_baseLib_init(BridgeMap *o, uc_engine *uc, uint32_t addr) {
    uint32_t v = o->extraData + baseLib_cfunction_ext_mem + 8;  // ext文件+8才是mr_c_function_load的地址，所有函数偏移量都是基于这个地址
    LOG("br_baseLib_%s_init() addr:0x%X[%u] v:0x%X[%u]\n", o->name, addr, addr, v, v);
    uc_mem_write(uc, addr, &v, 4);
}
//////////////////////////////////////////////////////////////////////////////////////////

static uint64_t uptime_ms;
static void br_get_uptime_ms_init(BridgeMap *o, uc_engine *uc, uint32_t addr) {
    LOG("br_%s_init() 0x%X[%u]\n", o->name, addr, addr);
    uptime_ms = (uint64_t)get_uptime_ms();
    uc_mem_write(uc, addr, &addr, 4);
}

static void br_get_uptime_ms(BridgeMap *o, uc_engine *uc) {
    // uint32 (*get_uptime_ms)(void);
    uint32_t ret = (uint32_t)((uint64_t)get_uptime_ms() - uptime_ms);
    LOG("ext call %s(): 0x%X[%u]\n", o->name, ret, ret);
    SET_RET_V(ret);
}

static void br_log(BridgeMap *o, uc_engine *uc) {
    // void (*log)(char *msg);
    uint32_t msg;
    uc_reg_read(uc, UC_ARM_REG_R0, &msg);

    char *str = (char *)getMrpMemPtr(msg);
    // LOG("ext call %s('%s')\n", o->name, str);
    puts(str);
    // dumpREG(uc);
}

static void br_mem_get(BridgeMap *o, uc_engine *uc) {
    // int32 (*mem_get)(char **mem_base, uint32 *mem_len);
    uint32_t mem_base, mem_len;
    uc_reg_read(uc, UC_ARM_REG_R0, &mem_base);
    uc_reg_read(uc, UC_ARM_REG_R1, &mem_len);

    LOG("ext call %s()\n", o->name);

    uint32_t len = 1024 * 1024 * 2;
    uint32_t buffer = toMrpMemAddr(my_mallocExt(len));

    printf("br_mem_get base=0x%X len=%d(%d kb) =================\n", buffer, len, len / 1024);

    // *mem_base = buffer;
    uc_mem_write(uc, mem_base, &buffer, 4);
    // *mem_len = len;
    uc_mem_write(uc, mem_len, &len, 4);

    SET_RET_V(MR_SUCCESS);
}

static void br_mem_free(BridgeMap *o, uc_engine *uc) {
    // int32 (*mem_free)(char *mem, uint32 mem_len);
    uint32_t mem, mem_len;
    uc_reg_read(uc, UC_ARM_REG_R0, &mem);
    uc_reg_read(uc, UC_ARM_REG_R1, &mem_len);

    LOG("ext call %s(0x%X, 0x%X)\n", o->name, mem, mem_len);
    my_freeExt(getMrpMemPtr(mem));
    SET_RET_V(MR_SUCCESS);
}

static void br_timerStop(BridgeMap *o, uc_engine *uc) {
    // int32 (*timerStop)(void);
    LOG("ext call %s()\n", o->name);
    SET_RET_V(timerStop());
}

static void br_timerStart(BridgeMap *o, uc_engine *uc) {
    // int32 (*timerStart)(uint16 t);
    LOG("ext call %s()\n", o->name);
    int32_t t;
    uc_reg_read(uc, UC_ARM_REG_R0, &t);
    SET_RET_V(timerStart(t));
}

static void br_test(BridgeMap *o, uc_engine *uc) {
    // void (*test)(void);
    LOG("ext call %s()\n", o->name);
}

static void br_exit(BridgeMap *o, uc_engine *uc) {
    // void (*exit)(void);
    LOG("ext call %s()\n", o->name);
    puts("mythroad exit.\n");
    exit(0);
}

static void br_srand(BridgeMap *o, uc_engine *uc) {
    // void (*srand)(uint32 seed);
    LOG("ext call %s()\n", o->name);
    uint32_t seed;
    uc_reg_read(uc, UC_ARM_REG_R0, &seed);
    srand(seed);
}

static void br_rand(BridgeMap *o, uc_engine *uc) {
    // int32 (*rand)(void);
    LOG("ext call %s()\n", o->name);
    SET_RET_V(rand());
}

static void br_sleep(BridgeMap *o, uc_engine *uc) {
    // int32 (*sleep)(uint32 ms);
    uint32_t ms;
    uc_reg_read(uc, UC_ARM_REG_R0, &ms);
    LOG("ext call %s(%d)\n", o->name, ms);
    usleep(ms * 1000);  //注意 usleep 传的是 微秒 ，所以要 *1000
    SET_RET_V(MR_SUCCESS);
}

static void br_info(BridgeMap *o, uc_engine *uc) {
    // int32 (*info)(const char *filename);
    LOG("ext call %s()\n", o->name);
    uint32_t filename;
    uc_reg_read(uc, UC_ARM_REG_R0, &filename);
    SET_RET_V(my_info(getMrpMemPtr(filename)))
}

static void br_opendir(BridgeMap *o, uc_engine *uc) {
    // int32 (*opendir)(const char *name);
    LOG("ext call %s()\n", o->name);
    uint32_t name;
    uc_reg_read(uc, UC_ARM_REG_R0, &name);
    SET_RET_V(my_opendir(getMrpMemPtr(name)))
}

#define READDIR_SHARED_MEM_SIZE 128
static char *readdirSharedMem;  // 文件名的共享内存
static void br_readdir_init(BridgeMap *o, uc_engine *uc, uint32_t addr) {
    LOG("br_%s_init() 0x%X[%u]\n", o->name, addr, addr);
    readdirSharedMem = (char *)my_mallocExt(READDIR_SHARED_MEM_SIZE);
    readdirSharedMem[READDIR_SHARED_MEM_SIZE - 1] = '\0';
    uc_mem_write(uc, addr, &addr, 4);
}

static void br_readdir(BridgeMap *o, uc_engine *uc) {
    // char *(*readdir)(int32 f);
    LOG("ext call %s()\n", o->name);
    int32_t f;
    uc_reg_read(uc, UC_ARM_REG_R0, &f);

    char *r = my_readdir(f);
    if (r != NULL) {
        strncpy(readdirSharedMem, r, READDIR_SHARED_MEM_SIZE - 1);
        SET_RET_V(toMrpMemAddr(readdirSharedMem));
    } else {
        SET_RET_V((uint32_t)NULL);
    }
}

static void br_closedir(BridgeMap *o, uc_engine *uc) {
    // int32 (*closedir)(int32 f);
    LOG("ext call %s()\n", o->name);
    int32_t f;
    uc_reg_read(uc, UC_ARM_REG_R0, &f);
    SET_RET_V(my_closedir(f));
}

static void br_getDatetime(BridgeMap *o, uc_engine *uc) {
    // int32 (*getDatetime)(mr_datetime *datetime);
    LOG("ext call %s()\n", o->name);
    uint32_t datetime;
    uc_reg_read(uc, UC_ARM_REG_R0, &datetime);
    SET_RET_V(getDatetime(getMrpMemPtr(datetime)));
}

static void br_mr_initNetwork(BridgeMap *o, uc_engine *uc) {
    // int32 (*mr_initNetwork)(MR_INIT_NETWORK_CB cb, const char *mode);
    LOG("ext call %s()\n", o->name);
    SET_RET_V(my_initNetwork(NULL, NULL));
}

static void br_mr_socket(BridgeMap *o, uc_engine *uc) {
    // int32 (*mr_socket)(int32 type, int32 protocol);
    int32_t type, protocol;
    uc_reg_read(uc, UC_ARM_REG_R0, &type);
    uc_reg_read(uc, UC_ARM_REG_R1, &protocol);
    int32_t ret = my_socket(type, protocol);
    LOG("ext call %s(): %d \n", o->name, ret);
    SET_RET_V(ret);
}

static void br_mr_connect(BridgeMap *o, uc_engine *uc) {
    // int32 (*mr_connect)(int32 s, int32 ip, uint16 port, int32 type);
    LOG("ext call %s()\n", o->name);
    int32_t s, ip, port, type;
    uc_reg_read(uc, UC_ARM_REG_R0, &s);
    uc_reg_read(uc, UC_ARM_REG_R1, &ip);
    uc_reg_read(uc, UC_ARM_REG_R2, &port);
    uc_reg_read(uc, UC_ARM_REG_R3, &type);
    SET_RET_V(my_connect(s, ip, (uint16)port, type));
}

static void br_mr_closeSocket(BridgeMap *o, uc_engine *uc) {
    // int32 (*mr_closeSocket)(int32 s);
    LOG("ext call %s()\n", o->name);
    int32_t s;
    uc_reg_read(uc, UC_ARM_REG_R0, &s);
    SET_RET_V(my_closeSocket(s));
}

static void br_mr_closeNetwork(BridgeMap *o, uc_engine *uc) {
    // int32 (*mr_closeNetwork)();
    LOG("ext call %s()\n", o->name);
    SET_RET_V(my_closeNetwork());
}

static void br_mr_getHostByName(BridgeMap *o, uc_engine *uc) {
    // int32 (*mr_getHostByName)(const char *ptr, MR_GET_HOST_CB cb);
    LOG("ext call %s()\n", o->name);
    uint32_t name, cb;
    uc_reg_read(uc, UC_ARM_REG_R0, &name);
    uc_reg_read(uc, UC_ARM_REG_R1, &cb);
    SET_RET_V(my_getHostByName(getMrpMemPtr(name), NULL));
}

static void br_mr_send(BridgeMap *o, uc_engine *uc) {
    // int32 (*mr_send)(int32 s, const char *buf, int len);
    LOG("ext call %s()\n", o->name);
    int32_t s, buf, len;
    uc_reg_read(uc, UC_ARM_REG_R0, &s);
    uc_reg_read(uc, UC_ARM_REG_R1, &buf);
    uc_reg_read(uc, UC_ARM_REG_R2, &len);
    SET_RET_V(my_send(s, getMrpMemPtr(buf), len));
}

static void br_mr_recv(BridgeMap *o, uc_engine *uc) {
    // int32 (*mr_recv)(int32 s, char *buf, int len);
    LOG("ext call %s()\n", o->name);
    int32_t s, buf, len;
    uc_reg_read(uc, UC_ARM_REG_R0, &s);
    uc_reg_read(uc, UC_ARM_REG_R1, &buf);
    uc_reg_read(uc, UC_ARM_REG_R2, &len);
    SET_RET_V(my_recv(s, getMrpMemPtr(buf), len));
}

/*
获取socket connect 状态（主要用于TCP的异步连接） 
Syntax
int32 mrc_getSocketState(int32 s); 
Parameters
s
   [IN] 打开的socket句柄，由mrc_socket创建

Return Value
   MR_SUCCESS ： 连接成功
   MR_FAILED ： 连接失败
   MR_WAITING ： 连接中
   MR_IGNORE ： 不支持该功能
*/
static void br_mr_getSocketState(BridgeMap *o, uc_engine *uc) {
    // int32 (*mr_getSocketState)(int32 s);
    int32_t s;
    uc_reg_read(uc, UC_ARM_REG_R0, &s);
    LOG("ext call %s(%d)\n", o->name, s);
    SET_RET_V(MR_IGNORE);
}

enum {
    MR_SOUND_MIDI,
    MR_SOUND_WAV,
    MR_SOUND_MP3,
    MR_SOUND_AMR,
    MR_SOUND_PCM  // 8K 16bit PCM
} MR_SOUND_TYPE;

/*
播放声音数据
type [IN] 声音数据类型，见MR_SOUND_TYPE定义，此函数支持MR_SOUND_MIDI MR_SOUND_WAV MR_SOUND_MP3 
data [IN] 声音数据指针
datalen [IN] 声音数据长度
loop [IN] 0:单次播放, 1:循环播放
Return Value MR_SUCCESS 成功 MR_FAILED 失败 
*/
#ifdef __EMSCRIPTEN__
EM_JS(int32, js_mr_playSound, (int type, const void *data, uint32 dataLen, int32 loop), {
    return js_playSound(type, data, dataLen, loop);
});
#endif

static void br_mr_playSound(BridgeMap *o, uc_engine *uc) {
    // int32 (*mr_playSound)(int type, const void *data, uint32 dataLen, int32 loop);
    int32_t type, data, dataLen, loop;
    uc_reg_read(uc, UC_ARM_REG_R0, &type);
    uc_reg_read(uc, UC_ARM_REG_R1, &data);
    uc_reg_read(uc, UC_ARM_REG_R2, &dataLen);
    uc_reg_read(uc, UC_ARM_REG_R3, &loop);
    LOG("ext call %s(%d, 0x%x, %d, %d)\n", o->name, type, data, dataLen, loop);
#ifdef __EMSCRIPTEN__
    SET_RET_V(js_mr_playSound(type, getMrpMemPtr(data), dataLen, loop));
#else
    SET_RET_V(MR_SUCCESS);
#endif
}

/*
停止播放声音数据
type [IN] 声音数据类型，见MR_SOUND_TYPE定义，此函数支持MR_SOUND_MIDI MR_SOUND_WAV MR_SOUND_MP3  
Return Value MR_SUCCESS 成功 MR_FAILED 失败 
*/
#ifdef __EMSCRIPTEN__
EM_JS(int32, js_mr_stopSound, (int type), {
    return js_stopSound(type);
});
#endif

static void br_mr_stopSound(BridgeMap *o, uc_engine *uc) {
    // int32 (*mr_stopSound)(int type);
    int32_t type;
    uc_reg_read(uc, UC_ARM_REG_R0, &type);
    LOG("ext call %s(%d)\n", o->name, type);

#ifdef __EMSCRIPTEN__
    SET_RET_V(js_mr_stopSound(type));
#else
    SET_RET_V(MR_SUCCESS);
#endif
}

#ifdef __EMSCRIPTEN__
EM_JS(int32, js_mr_startShake, (int32 ms), {
    return js_startShake(ms);
});
#endif

static void br_mr_startShake(BridgeMap *o, uc_engine *uc) {
    // int32 (*mr_startShake)(int32 ms);
    int32_t ms;
    uc_reg_read(uc, UC_ARM_REG_R0, &ms);
    LOG("ext call %s()\n", o->name);
#ifdef __EMSCRIPTEN__
    SET_RET_V(js_mr_startShake(ms));
#else
    SET_RET_V(MR_SUCCESS);
#endif
}

#ifdef __EMSCRIPTEN__
EM_JS(int32, js_mr_stopShake, (), {
    return js_stopShake();
});
#endif

static void br_mr_stopShake(BridgeMap *o, uc_engine *uc) {
    // int32 (*mr_stopShake)();
    LOG("ext call %s()\n", o->name);
#ifdef __EMSCRIPTEN__
    SET_RET_V(js_mr_stopShake());
#else
    SET_RET_V(MR_SUCCESS);
#endif
}

enum {
    MR_DIALOG_KEY_OK,     // 对话框/文本框等的"确定"键被点击(选择);
    MR_DIALOG_KEY_CANCEL  // 对话框/文本框等的"取消"("返回")键被点击(选择);
};

enum {
    MR_DIALOG_OK,         // 对话框有"确定"键;
    MR_DIALOG_OK_CANCEL,  // 对话框有"确定" "取消"键;
    MR_DIALOG_CANCEL      // 对话框有"返回"键
};

/*
创建一个对话框，并返回对话框句柄。当对话框显示时，如果用户按了对话框上的某个键，系统将构造Mythroad应用消息，通过mrc_event函数传送给Mythroad应用，
消息类型为MR_DIALOG_EVENT，参数为该按键的ID。"确定"键ID为：MR_DIALOG_KEY_OK；"取消"键ID为：MR_DIALOG_KEY_CANCEL。
title [IN]对话框的标题，unicode编码，网络字节序
text [IN]对话框内容，unicode编码，网络字节序
type [IN]对话框类型：MR_DIALOG_OK MR_DIALOG_OK_CANCEL MR_DIALOG_CANCEL

Return Value 正整数 对话框句柄 MR_FAILED 失败 
*/
#ifdef __EMSCRIPTEN__
EM_JS(int32, js_mr_dialogCreate, (const char *title, const char *text, int32 type), {
    return js_dialogCreate(title, text, type);
});
#endif

static void br_mr_dialogCreate(BridgeMap *o, uc_engine *uc) {
    // int32 (*mr_dialogCreate)(const char *title, const char *text, int32 type);
    uint32_t title, text;
    int32_t type;
    uc_reg_read(uc, UC_ARM_REG_R0, &title);
    uc_reg_read(uc, UC_ARM_REG_R1, &text);
    uc_reg_read(uc, UC_ARM_REG_R2, &type);
    LOG("ext call %s()\n", o->name);
#ifdef __EMSCRIPTEN__
    SET_RET_V(js_mr_dialogCreate(getMrpMemPtr(title), getMrpMemPtr(text), type));
#else
    SET_RET_V(MR_FAILED);
#endif
}

#ifdef __EMSCRIPTEN__
EM_JS(int32, js_mr_dialogRelease, (int32 dialog), {
    return js_dialogRelease(dialog);
});
#endif

static void br_mr_dialogRelease(BridgeMap *o, uc_engine *uc) {
    // int32 (*mr_dialogRelease)(int32 dialog);
    int32_t dialog;
    uc_reg_read(uc, UC_ARM_REG_R0, &dialog);
    LOG("ext call %s()\n", o->name);
#ifdef __EMSCRIPTEN__
    SET_RET_V(js_mr_dialogRelease(dialog));
#else
    SET_RET_V(MR_FAILED);
#endif
}

/*
刷新对话框的显示。
dialog [IN]对话框的句柄
title [IN]对话框的标题，unicode编码，网络字节序
text [IN]对话框内容，unicode编码，网络字节序
type [IN]若type为-1，表示type不变,见定义MR_DIALOG_OK MR_DIALOG_OK_CANCEL MR_DIALOG_CANCEL 
Return Value MR_SUCCESS 成功 MR_FAILED 失败 
*/
#ifdef __EMSCRIPTEN__
EM_JS(int32, js_mr_dialogRefresh, (int32 dialog, const char *title, const char *text, int32 type), {
    return js_dialogRefresh(dialog, title, text, type);
});
#endif

static void br_mr_dialogRefresh(BridgeMap *o, uc_engine *uc) {
    // int32 (*mr_dialogRefresh)(int32 dialog, const char *title, const char *text, int32 type);
    LOG("ext call %s()\n", o->name);
    int32_t dialog, type;
    uint32_t title, text;
    uc_reg_read(uc, UC_ARM_REG_R0, &dialog);
    uc_reg_read(uc, UC_ARM_REG_R1, &title);
    uc_reg_read(uc, UC_ARM_REG_R2, &text);
    uc_reg_read(uc, UC_ARM_REG_R3, &type);
#ifdef __EMSCRIPTEN__
    SET_RET_V(js_mr_dialogRefresh(dialog, getMrpMemPtr(title), getMrpMemPtr(text), type));
#else
    SET_RET_V(MR_FAILED);
#endif
}

/*
创建一个文本框，并返回文本框句柄
title [IN]文本框的标题，unicode编码，网络字节序
text [IN]文本框内容，unicode编码，网络字节序
type [IN]文本框按键类型,见定义MR_DIALOG_OK MR_DIALOG_OK_CANCEL MR_DIALOG_CANCEL 
Return Value 正整数 文本框句柄 MR_FAILED 失败 
Remarks
   文本框用来显示只读的文字信息。文本框和对话框并没有本质的区别，仅仅是显示方式上的不同，在使用上它们的主要区别是：对话框的内容一般较短，文本框的内容一般较长，
   对话框一般实现为弹出式的窗口，文本框一般实现为全屏式的窗口。也可能在手机上对话框和文本框使用了相同的方式实现。文本框和对话框的消息参数是一样的。当文本框显示时，
   如果用户选择了文本框上的某个键，系统将构造Mythroad应用消息，通过mrc_event函数传送给Mythroad 平台，消息类型为MR_DIALOG_EVENT，参数为该按键的ID。
   "确定"键ID为：MR_DIALOG_KEY_OK；"取消"键ID为：MR_DIALOG_KEY_CANCEL。 
*/
#ifdef __EMSCRIPTEN__
EM_JS(int32, js_mr_textCreate, (const char *title, const char *text, int32 type), {
    return js_textCreate(title, text, type);
});
#endif

static void br_mr_textCreate(BridgeMap *o, uc_engine *uc) {
    // int32 (*mr_textCreate)(const char *title, const char *text, int32 type);
    uint32_t title, text;
    int32_t type;
    uc_reg_read(uc, UC_ARM_REG_R0, &title);
    uc_reg_read(uc, UC_ARM_REG_R1, &text);
    uc_reg_read(uc, UC_ARM_REG_R2, &type);
    LOG("ext call %s()\n", o->name);
#ifdef __EMSCRIPTEN__
    SET_RET_V(js_mr_textCreate(getMrpMemPtr(title), getMrpMemPtr(text), type));
#else
    SET_RET_V(MR_FAILED);
#endif
}

#ifdef __EMSCRIPTEN__
EM_JS(int32, js_mr_textRelease, (int32 handle), {
    return js_textRelease(handle);
});
#endif

static void br_mr_textRelease(BridgeMap *o, uc_engine *uc) {
    // int32 (*mr_textRelease)(int32 handle);
    int32_t handle;
    uc_reg_read(uc, UC_ARM_REG_R0, &handle);
    LOG("ext call %s()\n", o->name);
#ifdef __EMSCRIPTEN__
    SET_RET_V(js_mr_textRelease(handle));
#else
    SET_RET_V(MR_FAILED);
#endif
}

#ifdef __EMSCRIPTEN__
EM_JS(int32, js_mr_textRefresh, (int32 handle, const char *title, const char *text), {
    return js_textRefresh(handle, title, text);
});
#endif

static void br_mr_textRefresh(BridgeMap *o, uc_engine *uc) {
    // int32 (*mr_textRefresh)(int32 handle, const char *title, const char *text);
    LOG("ext call %s()\n", o->name);
    int32_t handle;
    uint32_t title, text;
    uc_reg_read(uc, UC_ARM_REG_R0, &handle);
    uc_reg_read(uc, UC_ARM_REG_R1, &title);
    uc_reg_read(uc, UC_ARM_REG_R2, &text);
#ifdef __EMSCRIPTEN__
    SET_RET_V(js_mr_textRefresh(handle, getMrpMemPtr(title), getMrpMemPtr(text)));
#else
    SET_RET_V(MR_FAILED);
#endif
}

enum {
    MR_EDIT_ANY,
    MR_EDIT_NUMERIC,
    MR_EDIT_PASSWORD
};

/*
创建一个编辑框，并返回编辑框句柄。 
title [IN]文本框的标题，unicode编码，网络字节序
text [IN]文本框内容，unicode编码，网络字节序
type [IN]见MR_EDIT_ANY;MR_EDIT_NUMERIC;MR_EDIT_PASSWORD定义
max_size [IN]最多可以输入的字符（unicode）个数，这里每一个中文、字母、数字、符号都算一个字符 
Return Value 正整数 编辑框句柄 MR_FAILED 失败 
Remarks
   编辑框用来显示并提供用户编辑文字信息。text是编辑框显示的初始内容。当编辑框显示时，
如果用户选择了编辑框上的某个键，系统将构造Mythroad应用消息，通过mrc_event函数传送给
Mythroad应用，消息类型为MR_DIALOG_EVENT，参数为该按键的ID;"确定"键ID为：MR_DIALOG_KEY_OK；
"取消"键ID为：MR_DIALOG_KEY_CANCEL。 
*/
#ifdef __EMSCRIPTEN__
EM_JS(int32, js_mr_editCreate, (const char *title, const char *text, int32 type, int32 max_size), {
    return js_editCreate(title, text, type, max_size);
});
#endif

static void br_mr_editCreate(BridgeMap *o, uc_engine *uc) {
    // int32 (*mr_editCreate)(const char *title, const char *text, int32 type, int32 max_size);
    LOG("ext call %s()\n", o->name);
    int32_t type, max_size;
    uint32_t title, text;
    uc_reg_read(uc, UC_ARM_REG_R0, &title);
    uc_reg_read(uc, UC_ARM_REG_R1, &text);
    uc_reg_read(uc, UC_ARM_REG_R2, &type);
    uc_reg_read(uc, UC_ARM_REG_R3, &max_size);
#ifdef __EMSCRIPTEN__
    SET_RET_V(js_mr_editCreate(getMrpMemPtr(title), getMrpMemPtr(text), type, max_size));
#else
    SET_RET_V(MR_FAILED);
#endif
}

#ifdef __EMSCRIPTEN__
EM_JS(int32, js_mr_editRelease, (int32 edit), {
    return js_editRelease(edit);
});
#endif

static void br_mr_editRelease(BridgeMap *o, uc_engine *uc) {
    // int32 (*mr_editRelease)(int32 edit);
    LOG("ext call %s()\n", o->name);
    int32_t edit;
    uc_reg_read(uc, UC_ARM_REG_R0, &edit);
#ifdef __EMSCRIPTEN__
    SET_RET_V(js_mr_editRelease(edit));
#else
    SET_RET_V(MR_FAILED);
#endif
}

/*
获取编辑框内容，unicode编码。调用者若需在编辑框释放后仍然使用编辑框的内容，需要自行保存该内容。该函数需要在编辑框释放之前调用。 
Return Value 非NULL 编辑框的内容指针，unicode编码, NULL 失败 
*/
#ifdef __EMSCRIPTEN__
EM_JS(const char *, js_mr_editGetText, (int32 edit), {
    return js_editGetText(edit);
});
#endif

static void br_mr_editGetText(BridgeMap *o, uc_engine *uc) {
    // const char *(*mr_editGetText)(int32 edit);
    LOG("ext call %s()\n", o->name);
    int32_t edit;
    uc_reg_read(uc, UC_ARM_REG_R0, &edit);
#ifdef __EMSCRIPTEN__
    char *str = (char *)js_mr_editGetText(edit);
    SET_RET_V(toMrpMemAddr(str));
#else
    SET_RET_V((uint32_t)NULL);
#endif
}

// 偏移量由./mrc/[x]_offsets.c直接从mrp中导出
#define MR_TABLE_SIZE (4 * 146)
static BridgeMap mr_table_funcMap[146] = {
    BRIDGE_FUNC_MAP(0x0, MAP_FUNC, mr_malloc, NULL, br_mr_malloc, 0),  // 0x280000
    BRIDGE_FUNC_MAP(0x4, MAP_FUNC, mr_free, NULL, br_mr_free, 0),
    BRIDGE_FUNC_MAP(0x8, MAP_FUNC, mr_realloc, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0xC, MAP_FUNC, memcpy, br_baseLib_init, NULL, 0x1b90),
    BRIDGE_FUNC_MAP(0x10, MAP_FUNC, memmove, br_baseLib_init, NULL, 0x1bb0),
    BRIDGE_FUNC_MAP(0x14, MAP_FUNC, strcpy, br_baseLib_init, NULL, 0x2eac),
    BRIDGE_FUNC_MAP(0x18, MAP_FUNC, strncpy, br_baseLib_init, NULL, 0x2f7c),
    BRIDGE_FUNC_MAP(0x1C, MAP_FUNC, strcat, br_baseLib_init, NULL, 0x2e48),
    BRIDGE_FUNC_MAP(0x20, MAP_FUNC, strncat, br_baseLib_init, NULL, 0x2ee4),
    BRIDGE_FUNC_MAP(0x24, MAP_FUNC, memcmp, br_baseLib_init, NULL, 0x1b5c),
    BRIDGE_FUNC_MAP(0x28, MAP_FUNC, strcmp, br_baseLib_init, NULL, 0x2e7c),
    BRIDGE_FUNC_MAP(0x2C, MAP_FUNC, strncmp, br_baseLib_init, NULL, 0x2f40),
    BRIDGE_FUNC_MAP(0x30, MAP_FUNC, strcoll, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x34, MAP_FUNC, memchr, br_baseLib_init, NULL, 0x1b30),
    BRIDGE_FUNC_MAP(0x38, MAP_FUNC, memset, br_baseLib_init, NULL, 0x1c00),
    BRIDGE_FUNC_MAP(0x3C, MAP_FUNC, strlen, br_baseLib_init, NULL, 0x2ec8),
    BRIDGE_FUNC_MAP(0x40, MAP_FUNC, strstr, br_baseLib_init, NULL, 0x2fa8),
    BRIDGE_FUNC_MAP(0x44, MAP_FUNC, sprintf, br_baseLib_init, NULL, 0x2e08),
    BRIDGE_FUNC_MAP(0x48, MAP_FUNC, atoi, NULL, br_atoi, 0),
    BRIDGE_FUNC_MAP(0x4C, MAP_FUNC, strtoul, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x50, MAP_FUNC, rand, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x54, MAP_DATA, reserve0, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x58, MAP_DATA, reserve1, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x5C, MAP_DATA, _mr_c_internal_table, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x60, MAP_DATA, _mr_c_port_table, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x64, MAP_FUNC, _mr_c_function_new, NULL, br__mr_c_function_new, 0),
    BRIDGE_FUNC_MAP(0x68, MAP_FUNC, mr_printf, br_baseLib_init, NULL, 0x2db4),
    BRIDGE_FUNC_MAP(0x6C, MAP_FUNC, mr_mem_get, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x70, MAP_FUNC, mr_mem_free, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x74, MAP_FUNC, mr_drawBitmap, NULL, br_mr_drawBitmap, 0),
    BRIDGE_FUNC_MAP(0x78, MAP_FUNC, mr_getCharBitmap, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x7C, MAP_FUNC, mr_timerStart, NULL, NULL, 0),  // todo 在mrp初始化时会修改这个值（修改为mrp内的mrc_extTimerStart函数地址），目前没有实现对mrp读写的hook
    BRIDGE_FUNC_MAP(0x80, MAP_FUNC, mr_timerStop, NULL, NULL, 0),   // todo 在mrp初始化时会修改这个值（修改为mrp内的mrc_extTimerStop函数地址），目前没有实现对mrp读写的hook
    BRIDGE_FUNC_MAP(0x84, MAP_FUNC, mr_getTime, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x88, MAP_FUNC, mr_getDatetime, NULL, br_getDatetime, 0),
    BRIDGE_FUNC_MAP(0x8C, MAP_FUNC, mr_getUserInfo, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x90, MAP_FUNC, mr_sleep, NULL, br_sleep, 0),
    BRIDGE_FUNC_MAP(0x94, MAP_FUNC, mr_plat, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x98, MAP_FUNC, mr_platEx, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x9C, MAP_FUNC, mr_ferrno, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0xA0, MAP_FUNC, mr_open, NULL, br_mr_open, 0),
    BRIDGE_FUNC_MAP(0xA4, MAP_FUNC, mr_close, NULL, br_mr_close, 0),
    BRIDGE_FUNC_MAP(0xA8, MAP_FUNC, mr_info, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0xAC, MAP_FUNC, mr_write, NULL, br_mr_write, 0),
    BRIDGE_FUNC_MAP(0xB0, MAP_FUNC, mr_read, NULL, br_mr_read, 0),
    BRIDGE_FUNC_MAP(0xB4, MAP_FUNC, mr_seek, NULL, br_mr_seek, 0),
    BRIDGE_FUNC_MAP(0xB8, MAP_FUNC, mr_getLen, NULL, br_mr_getLen, 0),
    BRIDGE_FUNC_MAP(0xBC, MAP_FUNC, mr_remove, NULL, br_mr_remove, 0),
    BRIDGE_FUNC_MAP(0xC0, MAP_FUNC, mr_rename, NULL, br_mr_rename, 0),
    BRIDGE_FUNC_MAP(0xC4, MAP_FUNC, mr_mkDir, NULL, br_mr_mkDir, 0),
    BRIDGE_FUNC_MAP(0xC8, MAP_FUNC, mr_rmDir, NULL, br_mr_rmDir, 0),
    BRIDGE_FUNC_MAP(0xCC, MAP_FUNC, mr_findStart, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0xD0, MAP_FUNC, mr_findGetNext, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0xD4, MAP_FUNC, mr_findStop, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0xD8, MAP_FUNC, mr_exit, NULL, br_mr_exit, 0),
    BRIDGE_FUNC_MAP(0xDC, MAP_FUNC, mr_startShake, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0xE0, MAP_FUNC, mr_stopShake, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0xE4, MAP_FUNC, mr_playSound, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0xE8, MAP_FUNC, mr_stopSound, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0xEC, MAP_FUNC, mr_sendSms, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0xF0, MAP_FUNC, mr_call, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0xF4, MAP_FUNC, mr_getNetworkID, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0xF8, MAP_FUNC, mr_connectWAP, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0xFC, MAP_FUNC, mr_menuCreate, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x100, MAP_FUNC, mr_menuSetItem, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x104, MAP_FUNC, mr_menuShow, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x108, MAP_DATA, reserve, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x10C, MAP_FUNC, mr_menuRelease, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x110, MAP_FUNC, mr_menuRefresh, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x114, MAP_FUNC, mr_dialogCreate, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x118, MAP_FUNC, mr_dialogRelease, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x11C, MAP_FUNC, mr_dialogRefresh, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x120, MAP_FUNC, mr_textCreate, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x124, MAP_FUNC, mr_textRelease, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x128, MAP_FUNC, mr_textRefresh, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x12C, MAP_FUNC, mr_editCreate, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x130, MAP_FUNC, mr_editRelease, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x134, MAP_FUNC, mr_editGetText, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x138, MAP_FUNC, mr_winCreate, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x13C, MAP_FUNC, mr_winRelease, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x140, MAP_FUNC, mr_getScreenInfo, NULL, br_mr_getScreenInfo, 0),
    BRIDGE_FUNC_MAP(0x144, MAP_FUNC, mr_initNetwork, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x148, MAP_FUNC, mr_closeNetwork, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x14C, MAP_FUNC, mr_getHostByName, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x150, MAP_FUNC, mr_socket, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x154, MAP_FUNC, mr_connect, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x158, MAP_FUNC, mr_closeSocket, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x15C, MAP_FUNC, mr_recv, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x160, MAP_FUNC, mr_recvfrom, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x164, MAP_FUNC, mr_send, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x168, MAP_FUNC, mr_sendto, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x16C, MAP_DATA, mr_screenBuf, br_mr_screenBuf_init, NULL, 0),
    BRIDGE_FUNC_MAP(0x170, MAP_DATA, mr_screen_w, br_mr_screen_w_init, NULL, 0),
    BRIDGE_FUNC_MAP(0x174, MAP_DATA, mr_screen_h, br_mr_screen_h_init, NULL, 0),
    BRIDGE_FUNC_MAP(0x178, MAP_DATA, mr_screen_bit, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x17C, MAP_DATA, mr_bitmap, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x180, MAP_DATA, mr_tile, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x184, MAP_DATA, mr_map, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x188, MAP_DATA, mr_sound, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x18C, MAP_DATA, mr_sprite, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x190, MAP_DATA, pack_filename, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x194, MAP_DATA, start_filename, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x198, MAP_DATA, old_pack_filename, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x19C, MAP_DATA, old_start_filename, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x1A0, MAP_DATA, mr_ram_file, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x1A4, MAP_DATA, mr_ram_file_len, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x1A8, MAP_DATA, mr_soundOn, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x1AC, MAP_DATA, mr_shakeOn, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x1B0, MAP_DATA, LG_mem_base, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x1B4, MAP_DATA, LG_mem_len, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x1B8, MAP_DATA, LG_mem_end, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x1BC, MAP_DATA, LG_mem_left, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x1C0, MAP_DATA, mr_sms_cfg_buf, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x1C4, MAP_FUNC, mr_md5_init, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x1C8, MAP_FUNC, mr_md5_append, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x1CC, MAP_FUNC, mr_md5_finish, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x1D0, MAP_FUNC, _mr_load_sms_cfg, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x1D4, MAP_FUNC, _mr_save_sms_cfg, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x1D8, MAP_FUNC, _DispUpEx, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x1DC, MAP_FUNC, _DrawPoint, NULL, br__DrawPoint, 0),
    BRIDGE_FUNC_MAP(0x1E0, MAP_FUNC, _DrawBitmap, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x1E4, MAP_FUNC, _DrawBitmapEx, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x1E8, MAP_FUNC, DrawRect, NULL, br_DrawRect, 0),
    BRIDGE_FUNC_MAP(0x1EC, MAP_FUNC, _DrawText, NULL, br__DrawText, 0),
    BRIDGE_FUNC_MAP(0x1F0, MAP_FUNC, _BitmapCheck, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x1F4, MAP_FUNC, _mr_readFile, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x1F8, MAP_FUNC, mr_wstrlen, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x1FC, MAP_FUNC, mr_registerAPP, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x200, MAP_FUNC, _DrawTextEx, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x204, MAP_FUNC, _mr_EffSetCon, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x208, MAP_FUNC, _mr_TestCom, NULL, br__mr_TestCom, 0),
    BRIDGE_FUNC_MAP(0x20C, MAP_FUNC, _mr_TestCom1, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x210, MAP_FUNC, c2u, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x214, MAP_FUNC, _mr_div, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x218, MAP_FUNC, _mr_mod, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x21C, MAP_DATA, LG_mem_min, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x220, MAP_DATA, LG_mem_top, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x224, MAP_DATA, mr_updcrc, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x228, MAP_DATA, start_fileparameter, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x22C, MAP_DATA, mr_sms_return_flag, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x230, MAP_DATA, mr_sms_return_val, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x234, MAP_DATA, mr_unzip, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x238, MAP_DATA, mr_exit_cb, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x23C, MAP_DATA, mr_exit_cb_data, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x240, MAP_DATA, mr_entry, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x244, MAP_FUNC, mr_platDrawChar, NULL, NULL, 0),
};

#define MR_C_FUNCTION_SIZE (4 * 5)
static BridgeMap mr_c_function_funcMap[5] = {
    BRIDGE_FUNC_MAP(0x0, MAP_DATA, start_of_ER_RW, NULL, NULL, 0),  // 地址0x280248，值0x285880
    BRIDGE_FUNC_MAP(0x4, MAP_DATA, ER_RW_Length, NULL, NULL, 0),    // 调用ext内的mrc_malloc()时会加4
    BRIDGE_FUNC_MAP(0x8, MAP_DATA, ext_type, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0xC, MAP_DATA, mrc_extChunk, NULL, NULL, 0),  // 0x280254
    BRIDGE_FUNC_MAP(0x10, MAP_DATA, stack, NULL, NULL, 0),
};

#define DSM_REQUIRE_FUNCS_SIZE (4 * 51)
static BridgeMap dsm_require_funcs_funcMap[51] = {
    BRIDGE_FUNC_MAP(0x0, MAP_FUNC, test, NULL, br_test, 0),  // 0x28025C
    BRIDGE_FUNC_MAP(0x4, MAP_FUNC, log, NULL, br_log, 0),
    BRIDGE_FUNC_MAP(0x8, MAP_FUNC, exit, NULL, br_exit, 0),
    BRIDGE_FUNC_MAP(0xc, MAP_FUNC, srand, NULL, br_srand, 0),
    BRIDGE_FUNC_MAP(0x10, MAP_FUNC, rand, NULL, br_rand, 0),
    BRIDGE_FUNC_MAP(0x14, MAP_FUNC, mem_get, NULL, br_mem_get, 0),
    BRIDGE_FUNC_MAP(0x18, MAP_FUNC, mem_free, NULL, br_mem_free, 0),
    BRIDGE_FUNC_MAP(0x1c, MAP_FUNC, timerStart, NULL, br_timerStart, 0),
    BRIDGE_FUNC_MAP(0x20, MAP_FUNC, timerStop, NULL, br_timerStop, 0),
    BRIDGE_FUNC_MAP(0x24, MAP_FUNC, get_uptime_ms, br_get_uptime_ms_init, br_get_uptime_ms, 0),
    BRIDGE_FUNC_MAP(0x28, MAP_FUNC, getDatetime, NULL, br_getDatetime, 0),
    BRIDGE_FUNC_MAP(0x2c, MAP_FUNC, sleep, NULL, br_sleep, 0),
    BRIDGE_FUNC_MAP(0x30, MAP_FUNC, open, NULL, br_mr_open, 0),
    BRIDGE_FUNC_MAP(0x34, MAP_FUNC, close, NULL, br_mr_close, 0),
    BRIDGE_FUNC_MAP(0x38, MAP_FUNC, read, NULL, br_mr_read, 0),
    BRIDGE_FUNC_MAP(0x3c, MAP_FUNC, write, NULL, br_mr_write, 0),
    BRIDGE_FUNC_MAP(0x40, MAP_FUNC, seek, NULL, br_mr_seek, 0),
    BRIDGE_FUNC_MAP(0x44, MAP_FUNC, info, NULL, br_info, 0),
    BRIDGE_FUNC_MAP(0x48, MAP_FUNC, remove, NULL, br_mr_remove, 0),
    BRIDGE_FUNC_MAP(0x4c, MAP_FUNC, rename, NULL, br_mr_rename, 0),
    BRIDGE_FUNC_MAP(0x50, MAP_FUNC, mkDir, NULL, br_mr_mkDir, 0),
    BRIDGE_FUNC_MAP(0x54, MAP_FUNC, rmDir, NULL, br_mr_rmDir, 0),
    BRIDGE_FUNC_MAP(0x58, MAP_FUNC, opendir, NULL, br_opendir, 0),
    BRIDGE_FUNC_MAP(0x5c, MAP_FUNC, readdir, br_readdir_init, br_readdir, 0),
    BRIDGE_FUNC_MAP(0x60, MAP_FUNC, closedir, NULL, br_closedir, 0),
    BRIDGE_FUNC_MAP(0x64, MAP_FUNC, getLen, NULL, br_mr_getLen, 0),
    BRIDGE_FUNC_MAP(0x68, MAP_FUNC, drawBitmap, NULL, br_mr_drawBitmap, 0),
    BRIDGE_FUNC_MAP(0x6c, MAP_FUNC, mr_initNetwork, NULL, br_mr_initNetwork, 0),
    BRIDGE_FUNC_MAP(0x70, MAP_FUNC, mr_closeNetwork, NULL, br_mr_closeNetwork, 0),
    BRIDGE_FUNC_MAP(0x74, MAP_FUNC, mr_getHostByName, NULL, br_mr_getHostByName, 0),
    BRIDGE_FUNC_MAP(0x78, MAP_FUNC, mr_socket, NULL, br_mr_socket, 0),
    BRIDGE_FUNC_MAP(0x7c, MAP_FUNC, mr_connect, NULL, br_mr_connect, 0),
    BRIDGE_FUNC_MAP(0x80, MAP_FUNC, mr_getSocketState, NULL, br_mr_getSocketState, 0),
    BRIDGE_FUNC_MAP(0x84, MAP_FUNC, mr_closeSocket, NULL, br_mr_closeSocket, 0),
    BRIDGE_FUNC_MAP(0x88, MAP_FUNC, mr_recv, NULL, br_mr_recv, 0),
    BRIDGE_FUNC_MAP(0x8c, MAP_FUNC, mr_send, NULL, br_mr_send, 0),
    BRIDGE_FUNC_MAP(0x90, MAP_FUNC, mr_recvfrom, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x94, MAP_FUNC, mr_sendto, NULL, NULL, 0),
    BRIDGE_FUNC_MAP(0x98, MAP_FUNC, mr_startShake, NULL, br_mr_startShake, 0),
    BRIDGE_FUNC_MAP(0x9c, MAP_FUNC, mr_stopShake, NULL, br_mr_stopShake, 0),
    BRIDGE_FUNC_MAP(0xa0, MAP_FUNC, mr_playSound, NULL, br_mr_playSound, 0),
    BRIDGE_FUNC_MAP(0xa4, MAP_FUNC, mr_stopSound, NULL, br_mr_stopSound, 0),
    BRIDGE_FUNC_MAP(0xa8, MAP_FUNC, mr_dialogCreate, NULL, br_mr_dialogCreate, 0),
    BRIDGE_FUNC_MAP(0xac, MAP_FUNC, mr_dialogRelease, NULL, br_mr_dialogRelease, 0),
    BRIDGE_FUNC_MAP(0xb0, MAP_FUNC, mr_dialogRefresh, NULL, br_mr_dialogRefresh, 0),
    BRIDGE_FUNC_MAP(0xb4, MAP_FUNC, mr_textCreate, NULL, br_mr_textCreate, 0),
    BRIDGE_FUNC_MAP(0xb8, MAP_FUNC, mr_textRelease, NULL, br_mr_textRelease, 0),
    BRIDGE_FUNC_MAP(0xbc, MAP_FUNC, mr_textRefresh, NULL, br_mr_textRefresh, 0),
    BRIDGE_FUNC_MAP(0xc0, MAP_FUNC, mr_editCreate, NULL, br_mr_editCreate, 0),
    BRIDGE_FUNC_MAP(0xc4, MAP_FUNC, mr_editRelease, NULL, br_mr_editRelease, 0),
    BRIDGE_FUNC_MAP(0xc8, MAP_FUNC, mr_editGetText, NULL, br_mr_editGetText, 0),
    // BRIDGE_FUNC_MAP(0x98, MAP_FUNC, drawBitmap, NULL, NULL, 0),
};
//////////////////////////////////////////////////////////////////////////////////////////

static struct rb_root root = RB_ROOT;

void bridge(uc_engine *uc, uc_mem_type type, uint64_t address) {
    uIntMap *mobj = uIntMap_search(&root, address);
    if (mobj) {
        BridgeMap *obj = mobj->data;
        if (obj->type == MAP_FUNC) {
            if (obj->fn == NULL) {
                printf("!!! %s() Not yet implemented function !!! \n", obj->name);
                exit(1);
                return;
            }
            obj->fn(obj, uc);

            uint32_t _lr;
            uc_reg_read(uc, UC_ARM_REG_LR, &_lr);
            uc_reg_write(uc, UC_ARM_REG_PC, &_lr);
            return;
        }
        printf("!!! unregister function at 0x%" PRIX64 " !!! \n", address);
    }
}

static int hooks_init(uc_engine *uc, BridgeMap *map, uint32_t mapCount, uint32_t startAddress) {
    BridgeMap *obj;
    uIntMap *mobj;
    uint32_t addr;

    for (int i = 0; i < mapCount; i++) {
        obj = &map[i];
        addr = startAddress + obj->pos;
        if (obj->initFn != NULL) {
            obj->initFn(obj, uc, addr);
        } else {
            if (obj->type == MAP_FUNC) {
                // 默认的函数初始化，初始化为地址值，当PC寄存器执行到该地址时拦截下来进入我们的回调函数
                uc_mem_write(uc, addr, &addr, 4);
            }
        }
        mobj = malloc(sizeof(uIntMap));
        mobj->key = addr;
        mobj->data = obj;
        if (uIntMap_insert(&root, mobj)) {
            printf("uIntMap_insert() failed %d exists.\n", addr);
            exit(1);
            return -1;
        }
    }
    return 0;
}

// 必需是在BRIDGE_TABLE_ADDRESS开始，长度为BRIDGE_TABLE_SIZE的内存中分配地址
// clang-format off
#define MR_TABLE_ADDRESS            BRIDGE_TABLE_ADDRESS
#define MR_C_FUNCTION_ADDRESS       (MR_TABLE_ADDRESS + MR_TABLE_SIZE)
#define DSM_REQUIRE_FUNCS_ADDRESS   (MR_C_FUNCTION_ADDRESS + MR_C_FUNCTION_SIZE)
#define END_ADDRESS                 (DSM_REQUIRE_FUNCS_ADDRESS + DSM_REQUIRE_FUNCS_SIZE)
// clang-format on

uc_err bridge_init(uc_engine *uc) {
    uc_err err;
    uint32_t size = END_ADDRESS - BRIDGE_TABLE_ADDRESS;

    printf("[bridge_init]startAddr: 0x%X, endAddr: 0x%X, size: 0x%X\n", BRIDGE_TABLE_ADDRESS, END_ADDRESS, size);
    printf("[bridge_init]MR_TABLE_ADDRESS: 0x%X\n", MR_TABLE_ADDRESS);
    printf("[bridge_init]MR_C_FUNCTION_ADDRESS: 0x%X\n", MR_C_FUNCTION_ADDRESS);
    printf("[bridge_init]DSM_REQUIRE_FUNCS_ADDRESS: 0x%X\n", DSM_REQUIRE_FUNCS_ADDRESS);
    if (size > BRIDGE_TABLE_SIZE) {
        printf("error: size[%d] > BRIDGE_TABLE_SIZE[%d]\n", size, BRIDGE_TABLE_SIZE);
        exit(1);
    }

    // 加载预编译的包含有纯C语言实现函数的机器码指令数据，由mrc/baseLib项目生成的mrp中提取
    extern unsigned char baseLib_cfunction_ext[18524];
    baseLib_cfunction_ext_mem = toMrpMemAddr(my_mallocExt(sizeof(baseLib_cfunction_ext)));
    err = uc_mem_write(uc, baseLib_cfunction_ext_mem, baseLib_cfunction_ext, sizeof(baseLib_cfunction_ext));
    if (err) return err;

    uint32_t v = MR_TABLE_ADDRESS;
    hooks_init(uc, mr_table_funcMap, countof(mr_table_funcMap), MR_TABLE_ADDRESS);
    err = uc_mem_write(uc, CODE_ADDRESS, &v, 4);
    if (err) return err;

    v = MR_C_FUNCTION_ADDRESS;
    hooks_init(uc, mr_c_function_funcMap, countof(mr_c_function_funcMap), MR_C_FUNCTION_ADDRESS);
    err = uc_mem_write(uc, CODE_ADDRESS + 4, &v, 4);
    if (err) return err;

    hooks_init(uc, dsm_require_funcs_funcMap, countof(dsm_require_funcs_funcMap), DSM_REQUIRE_FUNCS_ADDRESS);

    mr_c_event = my_mallocExt(sizeof(_mr_c_event_st));
    tsf_init(SCREEN_WIDTH, SCREEN_HEIGHT, setPixel);

    return UC_ERR_OK;
}

static int32_t bridge_mr_helper(uc_engine *uc, uint32_t code, uint32_t input, uint32_t input_len) {
    // typedef int32 (*MR_C_FUNCTION)(void* P, int32 code, uint8* input, int32 input_len, uint8** output, int32* output_len);

    uint32_t v = MR_C_FUNCTION_ADDRESS;
    uc_reg_write(uc, UC_ARM_REG_R0, &v);          // p
    uc_reg_write(uc, UC_ARM_REG_R1, &code);       // code
    uc_reg_write(uc, UC_ARM_REG_R2, &input);      // input
    uc_reg_write(uc, UC_ARM_REG_R3, &input_len);  // input_len

    uint32_t sp, addr;
    uc_reg_read(uc, UC_ARM_REG_SP, &sp);

    // mr_c_function.start_of_ER_RW 会被写入r9(SB)，指向的内存是用来存放全局变量的
    v = *(uint32_t *)getMrpMemPtr(MR_C_FUNCTION_ADDRESS);
    printf("bridge_mr_helper() sp: 0x%X[%u], sb(r9):0x%X\n", sp, sp, v);

    addr = sp;
    v = 0;  // 相当于传递 NULL

    addr -= 4;
    uc_mem_write(uc, addr, &v, 4);  // output_len
    addr -= 4;
    uc_mem_write(uc, addr, &v, 4);  // output
    uc_reg_write(uc, UC_ARM_REG_SP, &addr);

    runCode(uc, mr_helper_addr, CODE_ADDRESS, false);

    uc_reg_write(uc, UC_ARM_REG_SP, &sp);

    int32_t ret;
    uc_reg_read(uc, UC_ARM_REG_R0, &ret);
    return ret;
}

// 暂停应用
int32_t bridge_mr_pauseApp(uc_engine *uc) {
    LOG("bridge_mr_pauseApp() ------------------------------------------------ \n");
    // return mr_helper(&cfunction_table, 4, NULL, 0, NULL, NULL);
    int32_t ret = bridge_mr_helper(uc, 4, 0, 0);
    LOG("bridge_mr_pauseApp() done.\n");
    return ret;
}

// 恢复应用
int32_t bridge_mr_resumeApp(uc_engine *uc) {
    LOG("bridge_mr_resumeApp() ------------------------------------------------ \n");
    // return mr_helper(&cfunction_table, 5, NULL, 0, NULL, NULL);
    int32_t ret = bridge_mr_helper(uc, 5, 0, 0);
    LOG("bridge_mr_resumeApp() done.\n");
    return ret;
}

// 事件进行处理
int32_t bridge_mr_event(uc_engine *uc, int32_t code, int32_t param0, int32_t param1) {
    // return mr_helper(&cfunction_table, 1, (uint8 *)input, sizeof(input), NULL, NULL);
    LOG("bridge_mr_event() ------------------------------------------------ \n");
    mr_c_event->code = code;
    mr_c_event->param0 = param0;
    mr_c_event->param1 = param1;
    int32_t ret = bridge_mr_helper(uc, 1, toMrpMemAddr(mr_c_event), sizeof(_mr_c_event_st));
    LOG("bridge_mr_event() done.\n");
    return ret;
}

int32_t bridge_mr_init(uc_engine *uc) {
    LOG("bridge_mr_init() ------------------------------------------------ \n");
    // mr_helper(&cfunction_table, 0, NULL, 0, NULL, NULL);
    int32_t ret = bridge_mr_helper(uc, 0, 0, 0);
    LOG("bridge_mr_init() done.\n");
    return ret;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////

/*
// 以下是三个在ext中的函数实现原理，是在mr_helper_s.o反汇编得到，但是我没有在c源码中获得实际的值，可能是用法不对
extern unsigned int Image$$ER_RW$$Length;
extern unsigned int Image$$ER_ZI$$ZI$$Length;
extern unsigned int Image$$ER_RO$$Length;
unsigned int mr_helper_get_rw_len() {
    return Image$$ER_RW$$Length + Image$$ER_ZI$$ZI$$Length;
}
unsigned int mr_helper_get_rw_lenOnly() {
    return Image$$ER_RW$$Length;
}
unsigned int mr_helper_get_ro_len() {
    return Image$$ER_RO$$Length;
}
*/
static pthread_mutex_t mutex;
static uint32_t dsm_export_funcs;

static int32_t bridge_dsm_version(uc_engine *uc) {
    //     int32 version; // 0x00
    return *(int32_t *)getMrpMemPtr(dsm_export_funcs + 0x00);
}

int32_t bridge_dsm_mr_start_dsm(uc_engine *uc, char *filename, char *ext, char *entry) {
    if (pthread_mutex_lock(&mutex) != 0) {
        perror("mutex lock fail");
        exit(EXIT_FAILURE);
    }
    // int32 (*mr_start_dsm)(char *filename, char *ext, char *entry); // 0x04
    uint32_t addr = *(uint32_t *)getMrpMemPtr(dsm_export_funcs + 0x04);
    uint32_t p0, p1, p2 = 0;

    printf("dsm_mr_start_dsm addr:0x%X ('%s','%s','%s')\n", addr, filename, ext, entry);
    p0 = copyStrToMrp(filename);
    uc_reg_write(uc, UC_ARM_REG_R0, &p0);

    p1 = copyStrToMrp(ext);
    uc_reg_write(uc, UC_ARM_REG_R1, &p1);

    if (entry) {
        p2 = copyStrToMrp(entry);
    }
    uc_reg_write(uc, UC_ARM_REG_R2, &p2);

    runCode(uc, addr, CODE_ADDRESS, false);
    my_freeExt(getMrpMemPtr(p0));
    my_freeExt(getMrpMemPtr(p1));
    if (entry) {
        my_freeExt(getMrpMemPtr(p2));
    }

    uint32_t v;
    uc_reg_read(uc, UC_ARM_REG_R0, &v);
    if (pthread_mutex_unlock(&mutex) != 0) {
        perror("mutex unlock fail");
        exit(EXIT_FAILURE);
    }
    return (int32_t)v;
}

int32_t bridge_dsm_mr_pauseApp(uc_engine *uc) {
    if (pthread_mutex_lock(&mutex) != 0) {
        perror("mutex lock fail");
        exit(EXIT_FAILURE);
    }
    //     int32 (*mr_pauseApp)(void); // 0x08
    uint32_t addr = *(uint32_t *)getMrpMemPtr(dsm_export_funcs + 0x08);
    runCode(uc, addr, CODE_ADDRESS, false);
    uint32_t v;
    uc_reg_read(uc, UC_ARM_REG_R0, &v);
    if (pthread_mutex_unlock(&mutex) != 0) {
        perror("mutex unlock fail");
        exit(EXIT_FAILURE);
    }
    return (int32_t)v;
}

int32_t bridge_dsm_mr_resumeApp(uc_engine *uc) {
    if (pthread_mutex_lock(&mutex) != 0) {
        perror("mutex lock fail");
        exit(EXIT_FAILURE);
    }
    //     int32 (*mr_resumeApp)(void); // 0x0c
    uint32_t addr = *(uint32_t *)getMrpMemPtr(dsm_export_funcs + 0x0c);
    runCode(uc, addr, CODE_ADDRESS, false);
    uint32_t v;
    uc_reg_read(uc, UC_ARM_REG_R0, &v);
    if (pthread_mutex_unlock(&mutex) != 0) {
        perror("mutex unlock fail");
        exit(EXIT_FAILURE);
    }
    return (int32_t)v;
}

int32_t bridge_dsm_mr_timer(uc_engine *uc) {
    if (pthread_mutex_lock(&mutex) != 0) {
        perror("mutex lock fail");
        exit(EXIT_FAILURE);
    }
    //     int32 (*mr_timer)(void); // 0x10
    uint32_t addr = *(uint32_t *)getMrpMemPtr(dsm_export_funcs + 0x10);
    runCode(uc, addr, CODE_ADDRESS, false);
    uint32_t v;
    uc_reg_read(uc, UC_ARM_REG_R0, &v);
    if (pthread_mutex_unlock(&mutex) != 0) {
        perror("mutex unlock fail");
        exit(EXIT_FAILURE);
    }
    return (int32_t)v;
}

int32_t bridge_dsm_mr_event(uc_engine *uc, int32_t code, int32_t p1, int32_t p2) {
    if (pthread_mutex_lock(&mutex) != 0) {
        perror("mutex lock fail");
        exit(EXIT_FAILURE);
    }
    //     int32 (*mr_event)(int16 type, int32 param1, int32 param2); // 0x14
    uint32_t addr = *(uint32_t *)getMrpMemPtr(dsm_export_funcs + 0x14);
    uc_reg_write(uc, UC_ARM_REG_R0, &code);
    uc_reg_write(uc, UC_ARM_REG_R1, &p1);
    uc_reg_write(uc, UC_ARM_REG_R2, &p2);

    runCode(uc, addr, CODE_ADDRESS, false);
    uint32_t v;
    uc_reg_read(uc, UC_ARM_REG_R0, &v);
    if (pthread_mutex_unlock(&mutex) != 0) {
        perror("mutex unlock fail");
        exit(EXIT_FAILURE);
    }
    return (int32_t)v;
}

int32_t bridge_dsm_init(uc_engine *uc, uint32_t addr) {
    if (pthread_mutex_init(&mutex, NULL) != 0) {
        perror("mutex init fail");
        exit(EXIT_FAILURE);
    }
    if (pthread_mutex_lock(&mutex) != 0) {
        perror("mutex lock fail");
        exit(EXIT_FAILURE);
    }

    uint32_t v = DSM_REQUIRE_FUNCS_ADDRESS;
    uc_reg_write(uc, UC_ARM_REG_R0, &v);

    // mr_c_function.start_of_ER_RW 写入r9(SB)，指向的内存是用来存放全局变量的
    v = *(uint32_t *)getMrpMemPtr(MR_C_FUNCTION_ADDRESS);
    uc_reg_write(uc, UC_ARM_REG_SB, &v);
    printf("vmrp start_of_ER_RW:0x%X\n", v);

    runCode(uc, addr, CODE_ADDRESS, false);

    // 返回值，DSM_EXPORT_FUNCS指针
    uc_reg_read(uc, UC_ARM_REG_R0, &dsm_export_funcs);

    v = bridge_dsm_version(uc);

    if (pthread_mutex_unlock(&mutex) != 0) {
        perror("mutex unlock fail");
        exit(EXIT_FAILURE);
    }
    if (v == VMRP_VER) {
        return MR_SUCCESS;
    } else {
        printf("warning: bridge_dsm_version:%d != %d\n", v, VMRP_VER);
    }
    return MR_FAILED;
}
