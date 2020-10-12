#include "./header/bridge.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "./header/dsm.h"
#include "./header/fileLib.h"
#include "./header/gb2unicode.h"
#include "./header/memory.h"
#include "./header/tsf_font.h"
#include "./header/vmrp.h"

//////////////////////////////////////////////////////////////////////////////////////////
#ifdef LOG
#undef LOG
#endif

#ifdef DEBUG
#define LOG(format, ...) printf("   -> bridge: " format, ##__VA_ARGS__)
#else
#define LOG(format, ...)
#endif

#define RET()                                 \
    {                                         \
        uint32_t lr;                          \
        uc_reg_read(uc, UC_ARM_REG_LR, &lr);  \
        uc_reg_write(uc, UC_ARM_REG_PC, &lr); \
    }

#define SET_RET_V(ret)                       \
    {                                        \
        uint32_t v = ret;                    \
        uc_reg_write(uc, UC_ARM_REG_R0, &v); \
    }
static uint32_t mr_helper_addr;     //mrc_extHelper()函数的地址
static uint32_t mr_c_event_st_mem;  // 用于mrc_event参数传递的内存
static uint32_t baseLib_cfunction_ext_mem;

// data ////////////////////////////////////////////////////////////////////////////////////////
static uint32_t mr_screen_h;   // 只是一个地址值
static uint32_t mr_screen_w;   // 只是一个地址值
static uint32_t mr_screenBuf;  // 只是一个地址值

static void br_mr_screen_h_init(BridgeMap *o, uc_engine *uc, uint32_t addr) {
    LOG("br_%s_init() 0x%X[%u]\n", o->name, addr, addr);
    uint32_t h = SCREEN_HEIGHT;
    mr_screen_h = allocMem(4);                // 获取一块模拟器中的内存，返回一个地址
    uc_mem_write(uc, addr, &mr_screen_h, 4);  // 往mr_table中写入指针值
    uc_mem_write(uc, mr_screen_h, &h, 4);     // 写入实际的数据
}

static void br_mr_screen_w_init(BridgeMap *o, uc_engine *uc, uint32_t addr) {
    LOG("br_%s_init() 0x%X[%u]\n", o->name, addr, addr);
    uint32_t w = SCREEN_WIDTH;
    mr_screen_w = allocMem(4);
    uc_mem_write(uc, addr, &mr_screen_w, 4);
    uc_mem_write(uc, mr_screen_w, &w, 4);
}

static void br_mr_screenBuf_init(BridgeMap *o, uc_engine *uc, uint32_t addr) {
    LOG("br_%s_init() 0x%X[%u]\n", o->name, addr, addr);
    mr_screenBuf = allocMem(4);                // 获取一个指针变量的内存
    uc_mem_write(uc, addr, &mr_screenBuf, 4);  // 往mr_table中写入指针值

    addr = SCREEN_BUF_ADDRESS;
    uc_mem_write(uc, mr_screenBuf, &addr, 4);  // 指针变量存入缓存的地址
    LOG("screenBuf: 0x%X[%u]\n", addr, addr);
}
// func ////////////////////////////////////////////////////////////////////////////////////////

static void br__mr_c_function_new(BridgeMap *o, uc_engine *uc) {
    // typedef int32 (*T__mr_c_function_new)(MR_C_FUNCTION f, int32 len);
    uint32_t p_f, p_len;
    uc_reg_read(uc, UC_ARM_REG_R0, &p_f);
    uc_reg_read(uc, UC_ARM_REG_R1, &p_len);
    LOG("ext call %s(0x%X[%u], 0x%X[%u])\n", o->name, p_f, p_f, p_len, p_len);
    dumpREG(uc);
    mr_helper_addr = p_f;
    printf("mrc_extHelper() addr:0x%X\n", mr_helper_addr);
    SET_RET_V(MR_SUCCESS);
    RET();
}

static void br_mr_malloc(BridgeMap *o, uc_engine *uc) {
    // typedef void* (*T_mr_malloc)(uint32 len);
    uint32_t p_len, ret;
    uc_reg_read(uc, UC_ARM_REG_R0, &p_len);

    LOG("ext call %s(0x%X[%u])\n", o->name, p_len, p_len);

    ret = (uint32_t)allocMem((size_t)p_len);
    LOG("ext call %s(0x%X[%u]) ret=0x%X[%u]\n", o->name, p_len, p_len, ret, ret);
    SET_RET_V(ret);
    RET();
}

static void br_mr_free(BridgeMap *o, uc_engine *uc) {
    // typedef void  (*T_mr_free)(void* p, uint32 len);
    uint32_t p, len;
    uc_reg_read(uc, UC_ARM_REG_R0, &p);
    uc_reg_read(uc, UC_ARM_REG_R1, &len);

    LOG("ext call %s(0x%X[%u], 0x%X[%u])\n", o->name, p, p, len, len);

    freeMem((size_t)p);
    RET();
}

static void br__mr_TestCom(BridgeMap *o, uc_engine *uc) {
    // typedef int32 (*T__mr_TestCom)(int32 L, int input0, int input1);
    uint32_t L, input0, input1;

    uc_reg_read(uc, UC_ARM_REG_R0, &L);
    uc_reg_read(uc, UC_ARM_REG_R1, &input0);
    uc_reg_read(uc, UC_ARM_REG_R2, &input1);

    LOG("ext call %s(0x%X[%u], 0x%X[%u], 0x%X[%u])\n", o->name, L, L, input0, input0, input1, input1);

    SET_RET_V(MR_SUCCESS);
    RET();
}

static inline void setPixel(int32_t x, int32_t y, uint16_t color, void *userData) {
    if (x < 0 || y < 0 || x >= SCREEN_WIDTH || y >= SCREEN_HEIGHT) {
        return;
    }
    // uc_mem_write(userData, SCREEN_BUF_ADDRESS + (x + SCREEN_WIDTH * y) * 2, &color, 2);
    // 直接操作屏幕缓存提高效率
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
    RET();
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

    LOG("ext call %s(0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X)\n", o->name, x, y, w, h, r, g, b);
    LOG("ext call %s([%u], [%u], [%u], [%u], [%u], [%u], [%u])\n", o->name, x, y, w, h, r, g, b);
    uint16_t color = MAKERGB565(r, g, b);

    for (uint32_t i = 0; i < w; i++) {
        for (uint32_t j = 0; j < h; j++) {
            setPixel(x + i, y + j, color, uc);
        }
    }

    RET();
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

    char *str = getStrFromUc(uc, pcText);

    LOG("ext call %s(0x%X[\"%s\"], 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X)\n", o->name, pcText, str, x, y, r, g, b, is_unicode, font);
    LOG("ext call %s([%u][\"%s\"], [%u], [%u], [%u], [%u], [%u], [%u], [%u])\n", o->name, pcText, str, x, y, r, g, b, is_unicode, font);

    if (is_unicode) {
        tsf_drawText((uint8_t *)str, x, y, MAKERGB565(r, g, b), uc);
    } else {
        uint8_t *out = (uint8_t *)gbToUCS2BE((uint8_t *)str, NULL);
        tsf_drawText(out, x, y, MAKERGB565(r, g, b), uc);
        free(out);
    }
    free(str);
    SET_RET_V(MR_SUCCESS);
    RET();
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

    LOG("ext call %s(0x%X, 0x%X, 0x%X, 0x%X, 0x%X)\n", o->name, bmp, x, y, w, h);
    LOG("ext call %s([%u], [%u], [%u], [%u], [%u])\n", o->name, bmp, x, y, w, h);

    for (uint32_t i = 0; i < w; i++) {
        for (uint32_t j = 0; j < h; j++) {
            int32_t xx = x + i;
            int32_t yy = y + j;
            if (xx < 0 || yy < 0 || xx >= SCREEN_WIDTH || yy >= SCREEN_HEIGHT) {
                continue;
            }
            uint16_t color;
            uc_mem_read(uc, bmp + (xx + yy * SCREEN_WIDTH) * 2, &color, 2);
            guiSetPixel(xx, yy, color);
        }
    }
    guiRefreshScreen(x, y, w, h);

    RET();
}

static void br_mr_open(BridgeMap *o, uc_engine *uc) {
    // typedef int32 (*T_mr_open)(const char* filename,  uint32 mode);
    uint32_t filename, mode;

    uc_reg_read(uc, UC_ARM_REG_R0, &filename);
    uc_reg_read(uc, UC_ARM_REG_R1, &mode);

    char *filenameStr = getStrFromUc(uc, filename);
    LOG("ext call %s(0x%X[%s], 0x%X)\n", o->name, filename, filenameStr, mode);
    LOG("ext call %s([%u], [%u])\n", o->name, filename, mode);

    int32_t ret = my_open(filenameStr, mode);
    free(filenameStr);

    LOG("ext call %s(): 0x%X[%u]\n", o->name, ret, ret);

    SET_RET_V(ret);
    RET();
}

static void br_mr_close(BridgeMap *o, uc_engine *uc) {
    // typedef int32 (*T_mr_close)(int32 f);
    uint32_t f, ret;

    uc_reg_read(uc, UC_ARM_REG_R0, &f);

    LOG("ext call %s(0x%X)\n", o->name, f);
    LOG("ext call %s([%u])\n", o->name, f);

    ret = my_close(f);
    LOG("ext call %s(): 0x%X[%u]\n", o->name, ret, ret);

    SET_RET_V(ret);
    RET();
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
    RET();
}

static void br_mr_read(BridgeMap *o, uc_engine *uc) {
    // typedef int32 (*T_mr_read)(int32 f,void *p,uint32 l);
    uint32_t f, p, l, ret;

    uc_reg_read(uc, UC_ARM_REG_R0, &f);
    uc_reg_read(uc, UC_ARM_REG_R1, &p);
    uc_reg_read(uc, UC_ARM_REG_R2, &l);

    LOG("ext call %s(0x%X, 0x%X, 0x%X)\n", o->name, f, p, l);
    LOG("ext call %s([%u], [%u], [%u])\n", o->name, f, p, l);

    char *buf = malloc(l);
    ret = my_read(f, buf, l);
    uc_mem_write(uc, p, buf, l);
    free(buf);

    SET_RET_V(ret);
    RET();
}

static void br_mr_seek(BridgeMap *o, uc_engine *uc) {
    // typedef int32 (*T_mr_seek)(int32 f, int32 pos, int method);
    uint32_t f, pos, method, ret;

    uc_reg_read(uc, UC_ARM_REG_R0, &f);
    uc_reg_read(uc, UC_ARM_REG_R1, &pos);
    uc_reg_read(uc, UC_ARM_REG_R2, &method);

    LOG("ext call %s(0x%X, 0x%X, 0x%X)\n", o->name, f, pos, method);
    LOG("ext call %s([%u], [%u], [%u])\n", o->name, f, pos, method);

    ret = my_seek(f, pos, method);

    SET_RET_V(ret);
    RET();
}

static void br_mr_getLen(BridgeMap *o, uc_engine *uc) {
    // typedef int32 (*T_mr_getLen)(const char* filename);
    uint32_t filename, ret;

    uc_reg_read(uc, UC_ARM_REG_R0, &filename);
    char *filenameStr = getStrFromUc(uc, filename);

    LOG("ext call %s(%s)\n", o->name, filenameStr);

    ret = my_getLen(filenameStr);
    free(filenameStr);

    SET_RET_V(ret);
    RET();
}

static void br_mr_remove(BridgeMap *o, uc_engine *uc) {
    // typedef int32 (*T_mr_remove)(const char* filename);
    uint32_t filename, ret;

    uc_reg_read(uc, UC_ARM_REG_R0, &filename);
    char *filenameStr = getStrFromUc(uc, filename);

    LOG("ext call %s(%s)\n", o->name, filenameStr);

    ret = my_remove(filenameStr);
    free(filenameStr);

    SET_RET_V(ret);
    RET();
}

static void br_mr_rename(BridgeMap *o, uc_engine *uc) {
    // typedef int32 (*T_mr_rename)(const char* oldname, const char* newname);
    uint32_t oldname, newname, ret;

    uc_reg_read(uc, UC_ARM_REG_R0, &oldname);
    uc_reg_read(uc, UC_ARM_REG_R1, &newname);
    char *oldnameStr = getStrFromUc(uc, oldname);
    char *newnameStr = getStrFromUc(uc, newname);

    LOG("ext call %s(%s, %s)\n", o->name, oldnameStr, newnameStr);

    ret = my_rename(oldnameStr, newnameStr);
    free(oldnameStr);
    free(newnameStr);

    SET_RET_V(ret);
    RET();
}

static void br_mr_mkDir(BridgeMap *o, uc_engine *uc) {
    // typedef int32 (*T_mr_mkDir)(const char* name);
    uint32_t name, ret;

    uc_reg_read(uc, UC_ARM_REG_R0, &name);
    char *nameStr = getStrFromUc(uc, name);

    LOG("ext call %s(%s)\n", o->name, nameStr);

    ret = my_mkDir(nameStr);
    free(nameStr);

    SET_RET_V(ret);
    RET();
}

static void br_mr_rmDir(BridgeMap *o, uc_engine *uc) {
    // typedef int32 (*T_mr_rmDir)(const char* name);
    uint32_t name, ret;

    uc_reg_read(uc, UC_ARM_REG_R0, &name);
    char *nameStr = getStrFromUc(uc, name);

    LOG("ext call %s(%s)\n", o->name, nameStr);

    ret = my_rmDir(nameStr);
    free(nameStr);

    SET_RET_V(ret);
    RET();
}

static void br_atoi(BridgeMap *o, uc_engine *uc) {
    // typedef int (*T_atoi)(const char * nptr);
    uint32_t nptr;

    uc_reg_read(uc, UC_ARM_REG_R0, &nptr);

    char *str = getStrFromUc(uc, nptr);
    LOG("ext call %s(0x%X[%s])\n", o->name, nptr, str);

    int32_t ret = atoi(str);
    free(str);

    LOG("ext call %s(): 0x%X[%u]\n", o->name, ret, ret);

    SET_RET_V(ret);
    RET();
}

static void br_mr_exit(BridgeMap *o, uc_engine *uc) {
    // typedef int32 (*T_mr_exit)(void);
    LOG("##### ext call %s()\n", o->name);
    SET_RET_V(MR_SUCCESS);
    RET();
}

//////////////////////////////////////////////////////////////////////////////////////////
// todo 调用 set_putchar 方法 偏移量在0x2df4 设置一个回调函数，这样才能真正实现mr_printf
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
    SET_RET_V(ret);
    RET();
}

static void br_log(BridgeMap *o, uc_engine *uc) {
    // void (*log)(char *msg);
    uint32_t msg;
    uc_reg_read(uc, UC_ARM_REG_R0, &msg);
    puts(getMrpMemPtr(msg));
    RET();
}

static void br_mem_get(BridgeMap *o, uc_engine *uc) {
    // int32 (*mem_get)(char **mem_base, uint32 *mem_len);
    uint32_t mem_base, mem_len;
    uc_reg_read(uc, UC_ARM_REG_R0, &mem_base);
    uc_reg_read(uc, UC_ARM_REG_R1, &mem_len);

    uint32_t len = 1024 * 1024 * 1;
    uint32_t buffer = allocMem(len);

    printf("br_mem_get base=0x%X len=%d =================\n", buffer, len);

    // *mem_base = buffer;
    uc_mem_write(uc, mem_base, &buffer, 4);
    // *mem_len = len;
    uc_mem_write(uc, mem_len, &len, 4);

    SET_RET_V(MR_SUCCESS);
    RET();
}

static void br_mem_free(BridgeMap *o, uc_engine *uc) {
    // int32 (*mem_free)(char *mem, uint32 mem_len);
    uint32_t mem, mem_len;
    uc_reg_read(uc, UC_ARM_REG_R0, &mem);
    uc_reg_read(uc, UC_ARM_REG_R1, &mem_len);

    LOG("ext call %s(0x%X, 0x%X)\n", o->name, mem, mem_len);
    freeMem(mem);

    SET_RET_V(MR_SUCCESS);
    RET();
}

// 偏移量由./mrc/[x]_offsets.c直接从mrp中导出
#define MR_TABLE_SIZE 0x248
static BridgeMap mr_table_funcMap[] = {
    BRIDGE_FUNC_MAP(0x0, 0x4, MAP_FUNC, mr_malloc, NULL, br_mr_malloc),  // 0x280000
    BRIDGE_FUNC_MAP(0x4, 0x4, MAP_FUNC, mr_free, NULL, br_mr_free),
    BRIDGE_FUNC_MAP(0x8, 0x4, MAP_FUNC, mr_realloc, NULL, NULL),
    BRIDGE_FUNC_MAP_FULL(0xC, 0x4, MAP_FUNC, memcpy, br_baseLib_init, NULL, 0x1b90),
    BRIDGE_FUNC_MAP_FULL(0x10, 0x4, MAP_FUNC, memmove, br_baseLib_init, NULL, 0x1bb0),
    BRIDGE_FUNC_MAP_FULL(0x14, 0x4, MAP_FUNC, strcpy, br_baseLib_init, NULL, 0x2eac),
    BRIDGE_FUNC_MAP_FULL(0x18, 0x4, MAP_FUNC, strncpy, br_baseLib_init, NULL, 0x2f7c),
    BRIDGE_FUNC_MAP_FULL(0x1C, 0x4, MAP_FUNC, strcat, br_baseLib_init, NULL, 0x2e48),
    BRIDGE_FUNC_MAP_FULL(0x20, 0x4, MAP_FUNC, strncat, br_baseLib_init, NULL, 0x2ee4),
    BRIDGE_FUNC_MAP_FULL(0x24, 0x4, MAP_FUNC, memcmp, br_baseLib_init, NULL, 0x1b5c),
    BRIDGE_FUNC_MAP_FULL(0x28, 0x4, MAP_FUNC, strcmp, br_baseLib_init, NULL, 0x2e7c),
    BRIDGE_FUNC_MAP_FULL(0x2C, 0x4, MAP_FUNC, strncmp, br_baseLib_init, NULL, 0x2f40),
    BRIDGE_FUNC_MAP(0x30, 0x4, MAP_FUNC, strcoll, NULL, NULL),
    BRIDGE_FUNC_MAP_FULL(0x34, 0x4, MAP_FUNC, memchr, br_baseLib_init, NULL, 0x1b30),
    BRIDGE_FUNC_MAP_FULL(0x38, 0x4, MAP_FUNC, memset, br_baseLib_init, NULL, 0x1c00),
    BRIDGE_FUNC_MAP_FULL(0x3C, 0x4, MAP_FUNC, strlen, br_baseLib_init, NULL, 0x2ec8),
    BRIDGE_FUNC_MAP_FULL(0x40, 0x4, MAP_FUNC, strstr, br_baseLib_init, NULL, 0x2fa8),
    BRIDGE_FUNC_MAP_FULL(0x44, 0x4, MAP_FUNC, sprintf, br_baseLib_init, NULL, 0x2e08),
    BRIDGE_FUNC_MAP(0x48, 0x4, MAP_FUNC, atoi, NULL, br_atoi),
    BRIDGE_FUNC_MAP(0x4C, 0x4, MAP_FUNC, strtoul, NULL, NULL),
    BRIDGE_FUNC_MAP(0x50, 0x4, MAP_FUNC, rand, NULL, NULL),
    BRIDGE_FUNC_MAP(0x54, 0x4, MAP_DATA, reserve0, NULL, NULL),
    BRIDGE_FUNC_MAP(0x58, 0x4, MAP_DATA, reserve1, NULL, NULL),
    BRIDGE_FUNC_MAP(0x5C, 0x4, MAP_DATA, _mr_c_internal_table, NULL, NULL),
    BRIDGE_FUNC_MAP(0x60, 0x4, MAP_DATA, _mr_c_port_table, NULL, NULL),
    BRIDGE_FUNC_MAP(0x64, 0x4, MAP_FUNC, _mr_c_function_new, NULL, br__mr_c_function_new),
    BRIDGE_FUNC_MAP_FULL(0x68, 0x4, MAP_FUNC, mr_printf, br_baseLib_init, NULL, 0x2db4),
    BRIDGE_FUNC_MAP(0x6C, 0x4, MAP_FUNC, mr_mem_get, NULL, NULL),
    BRIDGE_FUNC_MAP(0x70, 0x4, MAP_FUNC, mr_mem_free, NULL, NULL),
    BRIDGE_FUNC_MAP(0x74, 0x4, MAP_FUNC, mr_drawBitmap, NULL, br_mr_drawBitmap),
    BRIDGE_FUNC_MAP(0x78, 0x4, MAP_FUNC, mr_getCharBitmap, NULL, NULL),
    BRIDGE_FUNC_MAP(0x7C, 0x4, MAP_FUNC, g_mr_timerStart, NULL, NULL),  // todo 在mrp初始化时会修改这个值（修改为mrp内的mrc_extTimerStart函数地址），目前没有实现对mrp读写的hook
    BRIDGE_FUNC_MAP(0x80, 0x4, MAP_FUNC, g_mr_timerStop, NULL, NULL),   // todo 在mrp初始化时会修改这个值（修改为mrp内的mrc_extTimerStop函数地址），目前没有实现对mrp读写的hook
    BRIDGE_FUNC_MAP(0x84, 0x4, MAP_FUNC, mr_getTime, NULL, NULL),
    BRIDGE_FUNC_MAP(0x88, 0x4, MAP_FUNC, mr_getDatetime, NULL, NULL),
    BRIDGE_FUNC_MAP(0x8C, 0x4, MAP_FUNC, mr_getUserInfo, NULL, NULL),
    BRIDGE_FUNC_MAP(0x90, 0x4, MAP_FUNC, mr_sleep, NULL, NULL),
    BRIDGE_FUNC_MAP(0x94, 0x4, MAP_FUNC, mr_plat, NULL, NULL),
    BRIDGE_FUNC_MAP(0x98, 0x4, MAP_FUNC, mr_platEx, NULL, NULL),
    BRIDGE_FUNC_MAP(0x9C, 0x4, MAP_FUNC, mr_ferrno, NULL, NULL),
    BRIDGE_FUNC_MAP(0xA0, 0x4, MAP_FUNC, mr_open, NULL, br_mr_open),
    BRIDGE_FUNC_MAP(0xA4, 0x4, MAP_FUNC, mr_close, NULL, br_mr_close),
    BRIDGE_FUNC_MAP(0xA8, 0x4, MAP_FUNC, mr_info, NULL, NULL),
    BRIDGE_FUNC_MAP(0xAC, 0x4, MAP_FUNC, mr_write, NULL, br_mr_write),
    BRIDGE_FUNC_MAP(0xB0, 0x4, MAP_FUNC, mr_read, NULL, br_mr_read),
    BRIDGE_FUNC_MAP(0xB4, 0x4, MAP_FUNC, mr_seek, NULL, br_mr_seek),
    BRIDGE_FUNC_MAP(0xB8, 0x4, MAP_FUNC, mr_getLen, NULL, br_mr_getLen),
    BRIDGE_FUNC_MAP(0xBC, 0x4, MAP_FUNC, mr_remove, NULL, br_mr_remove),
    BRIDGE_FUNC_MAP(0xC0, 0x4, MAP_FUNC, mr_rename, NULL, br_mr_rename),
    BRIDGE_FUNC_MAP(0xC4, 0x4, MAP_FUNC, mr_mkDir, NULL, br_mr_mkDir),
    BRIDGE_FUNC_MAP(0xC8, 0x4, MAP_FUNC, mr_rmDir, NULL, br_mr_rmDir),
    BRIDGE_FUNC_MAP(0xCC, 0x4, MAP_FUNC, mr_findStart, NULL, NULL),
    BRIDGE_FUNC_MAP(0xD0, 0x4, MAP_FUNC, mr_findGetNext, NULL, NULL),
    BRIDGE_FUNC_MAP(0xD4, 0x4, MAP_FUNC, mr_findStop, NULL, NULL),
    BRIDGE_FUNC_MAP(0xD8, 0x4, MAP_FUNC, mr_exit, NULL, br_mr_exit),
    BRIDGE_FUNC_MAP(0xDC, 0x4, MAP_FUNC, mr_startShake, NULL, NULL),
    BRIDGE_FUNC_MAP(0xE0, 0x4, MAP_FUNC, mr_stopShake, NULL, NULL),
    BRIDGE_FUNC_MAP(0xE4, 0x4, MAP_FUNC, mr_playSound, NULL, NULL),
    BRIDGE_FUNC_MAP(0xE8, 0x4, MAP_FUNC, mr_stopSound, NULL, NULL),
    BRIDGE_FUNC_MAP(0xEC, 0x4, MAP_FUNC, mr_sendSms, NULL, NULL),
    BRIDGE_FUNC_MAP(0xF0, 0x4, MAP_FUNC, mr_call, NULL, NULL),
    BRIDGE_FUNC_MAP(0xF4, 0x4, MAP_FUNC, mr_getNetworkID, NULL, NULL),
    BRIDGE_FUNC_MAP(0xF8, 0x4, MAP_FUNC, mr_connectWAP, NULL, NULL),
    BRIDGE_FUNC_MAP(0xFC, 0x4, MAP_FUNC, mr_menuCreate, NULL, NULL),
    BRIDGE_FUNC_MAP(0x100, 0x4, MAP_FUNC, mr_menuSetItem, NULL, NULL),
    BRIDGE_FUNC_MAP(0x104, 0x4, MAP_FUNC, mr_menuShow, NULL, NULL),
    BRIDGE_FUNC_MAP(0x108, 0x4, MAP_DATA, reserve, NULL, NULL),
    BRIDGE_FUNC_MAP(0x10C, 0x4, MAP_FUNC, mr_menuRelease, NULL, NULL),
    BRIDGE_FUNC_MAP(0x110, 0x4, MAP_FUNC, mr_menuRefresh, NULL, NULL),
    BRIDGE_FUNC_MAP(0x114, 0x4, MAP_FUNC, mr_dialogCreate, NULL, NULL),
    BRIDGE_FUNC_MAP(0x118, 0x4, MAP_FUNC, mr_dialogRelease, NULL, NULL),
    BRIDGE_FUNC_MAP(0x11C, 0x4, MAP_FUNC, mr_dialogRefresh, NULL, NULL),
    BRIDGE_FUNC_MAP(0x120, 0x4, MAP_FUNC, mr_textCreate, NULL, NULL),
    BRIDGE_FUNC_MAP(0x124, 0x4, MAP_FUNC, mr_textRelease, NULL, NULL),
    BRIDGE_FUNC_MAP(0x128, 0x4, MAP_FUNC, mr_textRefresh, NULL, NULL),
    BRIDGE_FUNC_MAP(0x12C, 0x4, MAP_FUNC, mr_editCreate, NULL, NULL),
    BRIDGE_FUNC_MAP(0x130, 0x4, MAP_FUNC, mr_editRelease, NULL, NULL),
    BRIDGE_FUNC_MAP(0x134, 0x4, MAP_FUNC, mr_editGetText, NULL, NULL),
    BRIDGE_FUNC_MAP(0x138, 0x4, MAP_FUNC, mr_winCreate, NULL, NULL),
    BRIDGE_FUNC_MAP(0x13C, 0x4, MAP_FUNC, mr_winRelease, NULL, NULL),
    BRIDGE_FUNC_MAP(0x140, 0x4, MAP_FUNC, mr_getScreenInfo, NULL, NULL),
    BRIDGE_FUNC_MAP(0x144, 0x4, MAP_FUNC, mr_initNetwork, NULL, NULL),
    BRIDGE_FUNC_MAP(0x148, 0x4, MAP_FUNC, mr_closeNetwork, NULL, NULL),
    BRIDGE_FUNC_MAP(0x14C, 0x4, MAP_FUNC, mr_getHostByName, NULL, NULL),
    BRIDGE_FUNC_MAP(0x150, 0x4, MAP_FUNC, mr_socket, NULL, NULL),
    BRIDGE_FUNC_MAP(0x154, 0x4, MAP_FUNC, mr_connect, NULL, NULL),
    BRIDGE_FUNC_MAP(0x158, 0x4, MAP_FUNC, mr_closeSocket, NULL, NULL),
    BRIDGE_FUNC_MAP(0x15C, 0x4, MAP_FUNC, mr_recv, NULL, NULL),
    BRIDGE_FUNC_MAP(0x160, 0x4, MAP_FUNC, mr_recvfrom, NULL, NULL),
    BRIDGE_FUNC_MAP(0x164, 0x4, MAP_FUNC, mr_send, NULL, NULL),
    BRIDGE_FUNC_MAP(0x168, 0x4, MAP_FUNC, mr_sendto, NULL, NULL),
    BRIDGE_FUNC_MAP(0x16C, 0x4, MAP_DATA, mr_screenBuf, br_mr_screenBuf_init, NULL),
    BRIDGE_FUNC_MAP(0x170, 0x4, MAP_DATA, mr_screen_w, br_mr_screen_w_init, NULL),
    BRIDGE_FUNC_MAP(0x174, 0x4, MAP_DATA, mr_screen_h, br_mr_screen_h_init, NULL),
    BRIDGE_FUNC_MAP(0x178, 0x4, MAP_DATA, mr_screen_bit, NULL, NULL),
    BRIDGE_FUNC_MAP(0x17C, 0x4, MAP_DATA, mr_bitmap, NULL, NULL),
    BRIDGE_FUNC_MAP(0x180, 0x4, MAP_DATA, mr_tile, NULL, NULL),
    BRIDGE_FUNC_MAP(0x184, 0x4, MAP_DATA, mr_map, NULL, NULL),
    BRIDGE_FUNC_MAP(0x188, 0x4, MAP_DATA, mr_sound, NULL, NULL),
    BRIDGE_FUNC_MAP(0x18C, 0x4, MAP_DATA, mr_sprite, NULL, NULL),
    BRIDGE_FUNC_MAP(0x190, 0x4, MAP_DATA, pack_filename, NULL, NULL),
    BRIDGE_FUNC_MAP(0x194, 0x4, MAP_DATA, start_filename, NULL, NULL),
    BRIDGE_FUNC_MAP(0x198, 0x4, MAP_DATA, old_pack_filename, NULL, NULL),
    BRIDGE_FUNC_MAP(0x19C, 0x4, MAP_DATA, old_start_filename, NULL, NULL),
    BRIDGE_FUNC_MAP(0x1A0, 0x4, MAP_DATA, mr_ram_file, NULL, NULL),
    BRIDGE_FUNC_MAP(0x1A4, 0x4, MAP_DATA, mr_ram_file_len, NULL, NULL),
    BRIDGE_FUNC_MAP(0x1A8, 0x4, MAP_DATA, mr_soundOn, NULL, NULL),
    BRIDGE_FUNC_MAP(0x1AC, 0x4, MAP_DATA, mr_shakeOn, NULL, NULL),
    BRIDGE_FUNC_MAP(0x1B0, 0x4, MAP_DATA, LG_mem_base, NULL, NULL),
    BRIDGE_FUNC_MAP(0x1B4, 0x4, MAP_DATA, LG_mem_len, NULL, NULL),
    BRIDGE_FUNC_MAP(0x1B8, 0x4, MAP_DATA, LG_mem_end, NULL, NULL),
    BRIDGE_FUNC_MAP(0x1BC, 0x4, MAP_DATA, LG_mem_left, NULL, NULL),
    BRIDGE_FUNC_MAP(0x1C0, 0x4, MAP_DATA, mr_sms_cfg_buf, NULL, NULL),
    BRIDGE_FUNC_MAP(0x1C4, 0x4, MAP_FUNC, mr_md5_init, NULL, NULL),
    BRIDGE_FUNC_MAP(0x1C8, 0x4, MAP_FUNC, mr_md5_append, NULL, NULL),
    BRIDGE_FUNC_MAP(0x1CC, 0x4, MAP_FUNC, mr_md5_finish, NULL, NULL),
    BRIDGE_FUNC_MAP(0x1D0, 0x4, MAP_FUNC, _mr_load_sms_cfg, NULL, NULL),
    BRIDGE_FUNC_MAP(0x1D4, 0x4, MAP_FUNC, _mr_save_sms_cfg, NULL, NULL),
    BRIDGE_FUNC_MAP(0x1D8, 0x4, MAP_FUNC, _DispUpEx, NULL, NULL),
    BRIDGE_FUNC_MAP(0x1DC, 0x4, MAP_FUNC, _DrawPoint, NULL, br__DrawPoint),
    BRIDGE_FUNC_MAP(0x1E0, 0x4, MAP_FUNC, _DrawBitmap, NULL, NULL),
    BRIDGE_FUNC_MAP(0x1E4, 0x4, MAP_FUNC, _DrawBitmapEx, NULL, NULL),
    BRIDGE_FUNC_MAP(0x1E8, 0x4, MAP_FUNC, DrawRect, NULL, br_DrawRect),
    BRIDGE_FUNC_MAP(0x1EC, 0x4, MAP_FUNC, _DrawText, NULL, br__DrawText),
    BRIDGE_FUNC_MAP(0x1F0, 0x4, MAP_FUNC, _BitmapCheck, NULL, NULL),
    BRIDGE_FUNC_MAP(0x1F4, 0x4, MAP_FUNC, _mr_readFile, NULL, NULL),
    BRIDGE_FUNC_MAP(0x1F8, 0x4, MAP_FUNC, mr_wstrlen, NULL, NULL),
    BRIDGE_FUNC_MAP(0x1FC, 0x4, MAP_FUNC, mr_registerAPP, NULL, NULL),
    BRIDGE_FUNC_MAP(0x200, 0x4, MAP_FUNC, _DrawTextEx, NULL, NULL),
    BRIDGE_FUNC_MAP(0x204, 0x4, MAP_FUNC, _mr_EffSetCon, NULL, NULL),
    BRIDGE_FUNC_MAP(0x208, 0x4, MAP_FUNC, _mr_TestCom, NULL, br__mr_TestCom),
    BRIDGE_FUNC_MAP(0x20C, 0x4, MAP_FUNC, _mr_TestCom1, NULL, NULL),
    BRIDGE_FUNC_MAP(0x210, 0x4, MAP_FUNC, c2u, NULL, NULL),
    BRIDGE_FUNC_MAP(0x214, 0x4, MAP_FUNC, _mr_div, NULL, NULL),
    BRIDGE_FUNC_MAP(0x218, 0x4, MAP_FUNC, _mr_mod, NULL, NULL),
    BRIDGE_FUNC_MAP(0x21C, 0x4, MAP_DATA, LG_mem_min, NULL, NULL),
    BRIDGE_FUNC_MAP(0x220, 0x4, MAP_DATA, LG_mem_top, NULL, NULL),
    BRIDGE_FUNC_MAP(0x224, 0x4, MAP_DATA, mr_updcrc, NULL, NULL),
    BRIDGE_FUNC_MAP(0x228, 0x4, MAP_DATA, start_fileparameter, NULL, NULL),
    BRIDGE_FUNC_MAP(0x22C, 0x4, MAP_DATA, mr_sms_return_flag, NULL, NULL),
    BRIDGE_FUNC_MAP(0x230, 0x4, MAP_DATA, mr_sms_return_val, NULL, NULL),
    BRIDGE_FUNC_MAP(0x234, 0x4, MAP_DATA, mr_unzip, NULL, NULL),
    BRIDGE_FUNC_MAP(0x238, 0x4, MAP_DATA, mr_exit_cb, NULL, NULL),
    BRIDGE_FUNC_MAP(0x23C, 0x4, MAP_DATA, mr_exit_cb_data, NULL, NULL),
    BRIDGE_FUNC_MAP(0x240, 0x4, MAP_DATA, mr_entry, NULL, NULL),
    BRIDGE_FUNC_MAP(0x244, 0x4, MAP_FUNC, mr_platDrawChar, NULL, NULL),
};

#define MR_C_FUNCTION_SIZE 0x14
static BridgeMap mr_c_function_funcMap[] = {
    BRIDGE_FUNC_MAP(0x0, 0x4, MAP_DATA, start_of_ER_RW, NULL, NULL),  // 0x280248
    BRIDGE_FUNC_MAP(0x4, 0x4, MAP_DATA, ER_RW_Length, NULL, NULL),    // 调用ext内的mrc_malloc()时会加4
    BRIDGE_FUNC_MAP(0x8, 0x4, MAP_DATA, ext_type, NULL, NULL),
    BRIDGE_FUNC_MAP(0xC, 0x4, MAP_DATA, mrc_extChunk, NULL, NULL),  // 0x280254
    BRIDGE_FUNC_MAP(0x10, 0x4, MAP_DATA, stack, NULL, NULL),
};

#define DSM_REQUIRE_FUNCS_SIZE 0x6c
static BridgeMap dsm_require_funcs_funcMap[] = {
    // void (*panic)(char *msg);
    BRIDGE_FUNC_MAP_FULL(0x0, 0x4, MAP_FUNC, panic, NULL, NULL, 0),  // 0x28025C
    BRIDGE_FUNC_MAP_FULL(0x4, 0x4, MAP_FUNC, log, NULL, br_log, 0),
    // void (*exit)(void);
    BRIDGE_FUNC_MAP_FULL(0x8, 0x4, MAP_FUNC, exit, NULL, NULL, 0),
    // void (*srand)(uint32 seed);
    BRIDGE_FUNC_MAP_FULL(0xc, 0x4, MAP_FUNC, srand, NULL, NULL, 0),
    // int32 (*rand)(void);
    BRIDGE_FUNC_MAP_FULL(0x10, 0x4, MAP_FUNC, rand, NULL, NULL, 0),
    BRIDGE_FUNC_MAP_FULL(0x14, 0x4, MAP_FUNC, mem_get, NULL, br_mem_get, 0),
    BRIDGE_FUNC_MAP_FULL(0x18, 0x4, MAP_FUNC, mem_free, NULL, br_mem_free, 0),
    // int32 (*timerStart)(uint16 t);
    BRIDGE_FUNC_MAP_FULL(0x1c, 0x4, MAP_FUNC, timerStart, NULL, NULL, 0),
    // int32 (*timerStop)(void);
    BRIDGE_FUNC_MAP_FULL(0x20, 0x4, MAP_FUNC, timerStop, NULL, NULL, 0),
    BRIDGE_FUNC_MAP_FULL(0x24, 0x4, MAP_FUNC, get_uptime_ms, br_get_uptime_ms_init, br_get_uptime_ms, 0),
    // int32 (*getDatetime)(mr_datetime *datetime);
    BRIDGE_FUNC_MAP_FULL(0x28, 0x4, MAP_FUNC, getDatetime, NULL, NULL, 0),
    // int32 (*sleep)(uint32 ms);
    BRIDGE_FUNC_MAP_FULL(0x2c, 0x4, MAP_FUNC, sleep, NULL, NULL, 0),
    BRIDGE_FUNC_MAP_FULL(0x30, 0x4, MAP_FUNC, open, NULL, br_mr_open, 0),
    BRIDGE_FUNC_MAP_FULL(0x34, 0x4, MAP_FUNC, close, NULL, br_mr_close, 0),
    BRIDGE_FUNC_MAP_FULL(0x38, 0x4, MAP_FUNC, read, NULL, br_mr_read, 0),
    BRIDGE_FUNC_MAP_FULL(0x3c, 0x4, MAP_FUNC, write, NULL, br_mr_write, 0),
    BRIDGE_FUNC_MAP_FULL(0x40, 0x4, MAP_FUNC, seek, NULL, br_mr_seek, 0),
    // int32 (*info)(const char *filename);
    BRIDGE_FUNC_MAP_FULL(0x44, 0x4, MAP_FUNC, info, NULL, NULL, 0),
    BRIDGE_FUNC_MAP_FULL(0x48, 0x4, MAP_FUNC, remove, NULL, br_mr_remove, 0),
    BRIDGE_FUNC_MAP_FULL(0x4c, 0x4, MAP_FUNC, rename, NULL, br_mr_rename, 0),
    BRIDGE_FUNC_MAP_FULL(0x50, 0x4, MAP_FUNC, mkDir, NULL, br_mr_mkDir, 0),
    BRIDGE_FUNC_MAP_FULL(0x54, 0x4, MAP_FUNC, rmDir, NULL, br_mr_rmDir, 0),
    // int32 (*opendir)(const char *name);
    BRIDGE_FUNC_MAP_FULL(0x58, 0x4, MAP_FUNC, opendir, NULL, NULL, 0),
    // char *(*readdir)(int32 f);
    BRIDGE_FUNC_MAP_FULL(0x5c, 0x4, MAP_FUNC, readdir, NULL, NULL, 0),
    // int32 (*closedir)(int32 f);
    BRIDGE_FUNC_MAP_FULL(0x60, 0x4, MAP_FUNC, closedir, NULL, NULL, 0),
    BRIDGE_FUNC_MAP_FULL(0x64, 0x4, MAP_FUNC, getLen, NULL, br_mr_getLen, 0),
    // void (*drawBitmap)(uint16 *bmp, int16 x, int16 y, uint16 w, uint16 h);
    BRIDGE_FUNC_MAP_FULL(0x68, 0x4, MAP_FUNC, drawBitmap, NULL, NULL, 0),
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

    LOG("[bridge_init]startAddr: 0x%X, endAddr: 0x%X, size: 0x%X\n", BRIDGE_TABLE_ADDRESS, END_ADDRESS, size);
    LOG("[bridge_init]MR_TABLE_ADDRESS: 0x%X\n", MR_TABLE_ADDRESS);
    LOG("[bridge_init]MR_C_FUNCTION_ADDRESS: 0x%X\n", MR_C_FUNCTION_ADDRESS);
    LOG("[bridge_init]DSM_REQUIRE_FUNCS_ADDRESS: 0x%X\n", DSM_REQUIRE_FUNCS_ADDRESS);
    if (size > BRIDGE_TABLE_SIZE) {
        printf("error: size[%d] > BRIDGE_TABLE_SIZE[%d]\n", size, BRIDGE_TABLE_SIZE);
        exit(1);
    }

    // 加载预编译的包含有纯C语言实现函数的机器码指令数据，由mrc/baseLib项目生成的mrp中提取
    extern unsigned char baseLib_cfunction_ext[18524];
    baseLib_cfunction_ext_mem = allocMem(sizeof(baseLib_cfunction_ext));
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

    mr_c_event_st_mem = allocMem(20);
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
    LOG("bridge_mr_helper() sp: 0x%X[%u]\n", sp, sp);

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
int32_t bridge_mr_event(uc_engine *uc, int32_t code, int32_t param1, int32_t param2) {
    // typedef struct _mr_c_event_st{
    //     int32 code;
    //     int32 param0;
    //     int32 param1;
    //     int32 param2;
    //     int32 param3;
    // }mr_c_event_st
    // sizeof(mr_c_event_st) = 20
    // return mr_helper(&cfunction_table, 1, (uint8 *)input, sizeof(input), NULL, NULL);

    LOG("bridge_mr_event() ------------------------------------------------ \n");
    uc_mem_write(uc, mr_c_event_st_mem, &code, 4);
    uc_mem_write(uc, mr_c_event_st_mem + 4, &param1, 4);
    uc_mem_write(uc, mr_c_event_st_mem + 8, &param2, 4);
    int32_t ret = bridge_mr_helper(uc, 1, mr_c_event_st_mem, 20);
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
static uint32_t dsm_export_funcs;

int32_t bridge_dsm_version(uc_engine *uc) {
    //     int32 version; // 0x00
    return *(int32_t *)getMrpMemPtr(dsm_export_funcs + 0x00);
}

int32_t bridge_dsm_mr_start_dsm(uc_engine *uc, const char *entry) {
    //     int32 (*mr_start_dsm)(const char *entry); // 0x04
    uint32_t addr = *(uint32_t *)getMrpMemPtr(dsm_export_funcs + 0x04);

    uint32_t v = allocMem(strlen(entry));
    strcpy(getMrpMemPtr(v), entry);

    uc_reg_write(uc, UC_ARM_REG_R0, &v);
    runCode(uc, addr, CODE_ADDRESS, false);

    freeMem(v);

    uc_reg_read(uc, UC_ARM_REG_R0, &v);
    return (int32_t)v;
}

// int32_t bridge_dsm_mr_pauseApp(uc_engine *uc) {
//     //     int32 (*mr_pauseApp)(void); // 0x08
//     uint32_t addr = *(uint32_t *)getMrpMemPtr(dsm_export_funcs + 0x08);
// }

// int32_t bridge_dsm_mr_resumeApp(uc_engine *uc) {
//     //     int32 (*mr_resumeApp)(void); // 0x0c
//     uint32_t addr = *(uint32_t *)getMrpMemPtr(dsm_export_funcs + 0x0c);
// }

// int32_t bridge_dsm_mr_timer(uc_engine *uc) {
//     //     int32 (*mr_timer)(void); // 0x10
//     uint32_t addr = *(uint32_t *)getMrpMemPtr(dsm_export_funcs + 0x10);
// }

// int32_t bridge_dsm_mr_event(uc_engine *uc) {
//     //     int32 (*mr_event)(int16 type, int32 param1, int32 param2); // 0x14
//     uint32_t addr = *(uint32_t *)getMrpMemPtr(dsm_export_funcs + 0x14);
// }

int32_t bridge_dsm_init(uc_engine *uc, uint32_t addr) {
    uint32_t v = DSM_REQUIRE_FUNCS_ADDRESS;
    uc_reg_write(uc, UC_ARM_REG_R0, &v);

    // mr_c_function.start_of_ER_RW 写入r9(SB)，指向的内存是用来存放全局变量的
    v = *(uint32_t *)getMrpMemPtr(MR_C_FUNCTION_ADDRESS);
    uc_reg_write(uc, UC_ARM_REG_SB, &v);

    runCode(uc, addr, CODE_ADDRESS, false);

    // 返回值，DSM_EXPORT_FUNCS指针
    uc_reg_read(uc, UC_ARM_REG_R0, &dsm_export_funcs);

    v = bridge_dsm_version(uc);
    if (v == VMRP_VER) {
        return MR_SUCCESS;
    } else {
        printf("warning: bridge_dsm_version:%d != %d\n", v, VMRP_VER);
    }
    return MR_FAILED;
}
