#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "./header/bridge.h"
#include "./header/main.h"
#include "./header/memory.h"

//////////////////////////////////////////////////////////////////////////////////////////
#ifdef LOG
#undef LOG
#endif
#define LOG(format, ...) printf("   -> bridge: " format, ##__VA_ARGS__)

#define RET()                                 \
    {                                         \
        uint32_t lr;                          \
        uc_reg_read(uc, UC_ARM_REG_LR, &lr);  \
        uc_reg_write(uc, UC_ARM_REG_PC, &lr); \
    }

#define SET_RET_V(ret) uc_reg_write(uc, UC_ARM_REG_R0, &ret);

static uint32_t mr_helper_addr;
static uint32_t mr_table_startAddress;
static uint32_t mr_c_function_startAddress;
static uint32_t mrc_extChunk_startAddress;
static uint32_t endAddress;

static void br_defaultInit(BridgeMap *o, uc_engine *uc, uint32_t addr) {
    uc_mem_write(uc, addr, &addr, 4);
}

static void br__mr_c_function_new(BridgeMap *o, uc_engine *uc) {
    uint32_t p_f, p_len, ret;
    uc_reg_read(uc, UC_ARM_REG_R0, &p_f);
    uc_reg_read(uc, UC_ARM_REG_R1, &p_len);
    LOG("ext call %s(0x%X[%u], 0x%X[%u])\n", o->name, p_f, p_f, p_len, p_len);
    mr_helper_addr = p_f;
    ret = MR_SUCCESS;
    SET_RET_V(ret);
    RET();
}

static void br_mr_malloc(BridgeMap *o, uc_engine *uc) {
    uint32_t p_len, ret;
    uc_reg_read(uc, UC_ARM_REG_R0, &p_len);

    LOG("ext call %s(0x%X[%u])\n", o->name, p_len, p_len);
    dumpREG(uc);

    ret = (uint32_t)allocMem((size_t)p_len);
    LOG("ext call %s(0x%X[%u]) ret=0x%X[%u]\n", o->name, p_len, p_len, ret, ret);
    SET_RET_V(ret);
    RET();
}

static void br_mr_free(BridgeMap *o, uc_engine *uc) {
    uint32_t p, len;
    uc_reg_read(uc, UC_ARM_REG_R0, &p);
    uc_reg_read(uc, UC_ARM_REG_R1, &len);

    LOG("ext call %s(0x%X[%u], 0x%X[%u])\n", o->name, p, p, len, len);
    dumpREG(uc);

    freeMem((size_t)p);
    RET();
}

// todo 采用直接执行arm机器码的方式优化
static void br_memcpy(BridgeMap *o, uc_engine *uc) {
    uint32_t p_dst, p_src, p_size, ret;
    uc_reg_read(uc, UC_ARM_REG_R0, &p_dst);
    uc_reg_read(uc, UC_ARM_REG_R1, &p_src);
    uc_reg_read(uc, UC_ARM_REG_R2, &p_size);

    LOG("ext call %s(0x%X[%u], 0x%X[%u], 0x%X[%u])\n", o->name, p_dst, p_dst, p_src, p_src, p_size, p_size);
    dumpREG(uc);

    ret = p_dst;
    uint32_t b;
    for (size_t i = 0; i < p_size; i++) {
        uc_mem_read(uc, p_src + i, &b, 1);
        uc_mem_write(uc, p_dst + i, &b, 1);
    }
    SET_RET_V(ret);
    RET();
}

// todo 采用直接执行arm机器码的方式优化
static void br_memset(BridgeMap *o, uc_engine *uc) {
    uint32_t p_dst, p_val, p_size, ret;

    uc_reg_read(uc, UC_ARM_REG_R0, &p_dst);
    uc_reg_read(uc, UC_ARM_REG_R1, &p_val);
    uc_reg_read(uc, UC_ARM_REG_R2, &p_size);

    LOG("ext call %s(0x%X[%u], 0x%X[%u], 0x%X[%u])\n", o->name, p_dst, p_dst, p_val, p_val, p_size, p_size);
    dumpREG(uc);

    ret = p_dst;
    for (size_t i = 0; i < p_size; i++) {
        uc_mem_write(uc, p_dst + i, &p_val, 1);
    }

    SET_RET_V(ret);
    RET();
}

static void br__mr_TestCom(BridgeMap *o, uc_engine *uc) {
    // typedef int32 (*T__mr_TestCom)(int32 L, int input0, int input1);
    uint32_t L, input0, input1, ret;

    uc_reg_read(uc, UC_ARM_REG_R0, &L);
    uc_reg_read(uc, UC_ARM_REG_R1, &input0);
    uc_reg_read(uc, UC_ARM_REG_R2, &input1);

    LOG("ext call %s(0x%X[%u], 0x%X[%u], 0x%X[%u])\n", o->name, L, L, input0, input0, input1, input1);
    dumpREG(uc);

    ret = MR_SUCCESS;
    SET_RET_V(ret);
    RET();
}

// data ////////////////////////////////////////////////////////////////////////////////////////

static uint32_t mr_screen_h;  // 只是一个地址值
static uint32_t mr_screen_w;  // 只是一个地址值

static void br_mr_screen_h_init(BridgeMap *o, uc_engine *uc, uint32_t addr) {
    LOG("br_%s_init() 0x%X[%u]\n", o->name, addr, addr);
    uint32_t h = SCREEN_HEIGHT;
    mr_screen_h = allocMem(4);
    uc_mem_write(uc, addr, &mr_screen_h, 4);
    uc_mem_write(uc, mr_screen_h, &h, 4);
}

static void br_mr_screen_w_init(BridgeMap *o, uc_engine *uc, uint32_t addr) {
    LOG("br_%s_init() 0x%X[%u]\n", o->name, addr, addr);
    uint32_t w = SCREEN_WIDTH;
    mr_screen_w = allocMem(4);
    uc_mem_write(uc, addr, &mr_screen_w, 4);
    uc_mem_write(uc, mr_screen_w, &w, 4);
}

//////////////////////////////////////////////////////////////////////////////////////////

// 偏移量由./mrc/[x]_offsets.c直接从mrp中导出
static BridgeMap mr_table_funcMap[] = {
    BRIDGE_FUNC_MAP(0x0, 0x4, MAP_FUNC, mr_malloc, NULL, br_mr_malloc),  // 0x280000
    BRIDGE_FUNC_MAP(0x4, 0x4, MAP_FUNC, mr_free, NULL, br_mr_free),
    BRIDGE_FUNC_MAP(0x8, 0x4, MAP_FUNC, mr_realloc, NULL, NULL),
    BRIDGE_FUNC_MAP(0xC, 0x4, MAP_FUNC, memcpy, NULL, br_memcpy),
    BRIDGE_FUNC_MAP(0x10, 0x4, MAP_FUNC, memmove, NULL, NULL),
    BRIDGE_FUNC_MAP(0x14, 0x4, MAP_FUNC, strcpy, NULL, NULL),
    BRIDGE_FUNC_MAP(0x18, 0x4, MAP_FUNC, strncpy, NULL, NULL),
    BRIDGE_FUNC_MAP(0x1C, 0x4, MAP_FUNC, strcat, NULL, NULL),
    BRIDGE_FUNC_MAP(0x20, 0x4, MAP_FUNC, strncat, NULL, NULL),
    BRIDGE_FUNC_MAP(0x24, 0x4, MAP_FUNC, memcmp, NULL, NULL),
    BRIDGE_FUNC_MAP(0x28, 0x4, MAP_FUNC, strcmp, NULL, NULL),
    BRIDGE_FUNC_MAP(0x2C, 0x4, MAP_FUNC, strncmp, NULL, NULL),
    BRIDGE_FUNC_MAP(0x30, 0x4, MAP_FUNC, strcoll, NULL, NULL),
    BRIDGE_FUNC_MAP(0x34, 0x4, MAP_FUNC, memchr, NULL, NULL),
    BRIDGE_FUNC_MAP(0x38, 0x4, MAP_FUNC, memset, NULL, br_memset),
    BRIDGE_FUNC_MAP(0x3C, 0x4, MAP_FUNC, strlen, NULL, NULL),
    BRIDGE_FUNC_MAP(0x40, 0x4, MAP_FUNC, strstr, NULL, NULL),
    BRIDGE_FUNC_MAP(0x44, 0x4, MAP_FUNC, sprintf, NULL, NULL),
    BRIDGE_FUNC_MAP(0x48, 0x4, MAP_FUNC, atoi, NULL, NULL),
    BRIDGE_FUNC_MAP(0x4C, 0x4, MAP_FUNC, strtoul, NULL, NULL),
    BRIDGE_FUNC_MAP(0x50, 0x4, MAP_FUNC, rand, NULL, NULL),
    BRIDGE_FUNC_MAP(0x54, 0x4, MAP_DATA, reserve0, NULL, NULL),
    BRIDGE_FUNC_MAP(0x58, 0x4, MAP_DATA, reserve1, NULL, NULL),
    BRIDGE_FUNC_MAP(0x5C, 0x4, MAP_DATA, _mr_c_internal_table, NULL, NULL),
    BRIDGE_FUNC_MAP(0x60, 0x4, MAP_DATA, _mr_c_port_table, NULL, NULL),
    BRIDGE_FUNC_MAP(0x64, 0x4, MAP_FUNC, _mr_c_function_new, NULL, br__mr_c_function_new),
    BRIDGE_FUNC_MAP(0x68, 0x4, MAP_FUNC, mr_printf, NULL, NULL),
    BRIDGE_FUNC_MAP(0x6C, 0x4, MAP_FUNC, mr_mem_get, NULL, NULL),
    BRIDGE_FUNC_MAP(0x70, 0x4, MAP_FUNC, mr_mem_free, NULL, NULL),
    BRIDGE_FUNC_MAP(0x74, 0x4, MAP_FUNC, mr_drawBitmap, NULL, NULL),
    BRIDGE_FUNC_MAP(0x78, 0x4, MAP_FUNC, mr_getCharBitmap, NULL, NULL),
    BRIDGE_FUNC_MAP(0x7C, 0x4, MAP_FUNC, g_mr_timerStart, NULL, NULL),
    BRIDGE_FUNC_MAP(0x80, 0x4, MAP_FUNC, g_mr_timerStop, NULL, NULL),
    BRIDGE_FUNC_MAP(0x84, 0x4, MAP_FUNC, mr_getTime, NULL, NULL),
    BRIDGE_FUNC_MAP(0x88, 0x4, MAP_FUNC, mr_getDatetime, NULL, NULL),
    BRIDGE_FUNC_MAP(0x8C, 0x4, MAP_FUNC, mr_getUserInfo, NULL, NULL),
    BRIDGE_FUNC_MAP(0x90, 0x4, MAP_FUNC, mr_sleep, NULL, NULL),
    BRIDGE_FUNC_MAP(0x94, 0x4, MAP_FUNC, mr_plat, NULL, NULL),
    BRIDGE_FUNC_MAP(0x98, 0x4, MAP_FUNC, mr_platEx, NULL, NULL),
    BRIDGE_FUNC_MAP(0x9C, 0x4, MAP_FUNC, mr_ferrno, NULL, NULL),
    BRIDGE_FUNC_MAP(0xA0, 0x4, MAP_FUNC, mr_open, NULL, NULL),
    BRIDGE_FUNC_MAP(0xA4, 0x4, MAP_FUNC, mr_close, NULL, NULL),
    BRIDGE_FUNC_MAP(0xA8, 0x4, MAP_FUNC, mr_info, NULL, NULL),
    BRIDGE_FUNC_MAP(0xAC, 0x4, MAP_FUNC, mr_write, NULL, NULL),
    BRIDGE_FUNC_MAP(0xB0, 0x4, MAP_FUNC, mr_read, NULL, NULL),
    BRIDGE_FUNC_MAP(0xB4, 0x4, MAP_FUNC, mr_seek, NULL, NULL),
    BRIDGE_FUNC_MAP(0xB8, 0x4, MAP_FUNC, mr_getLen, NULL, NULL),
    BRIDGE_FUNC_MAP(0xBC, 0x4, MAP_FUNC, mr_remove, NULL, NULL),
    BRIDGE_FUNC_MAP(0xC0, 0x4, MAP_FUNC, mr_rename, NULL, NULL),
    BRIDGE_FUNC_MAP(0xC4, 0x4, MAP_FUNC, mr_mkDir, NULL, NULL),
    BRIDGE_FUNC_MAP(0xC8, 0x4, MAP_FUNC, mr_rmDir, NULL, NULL),
    BRIDGE_FUNC_MAP(0xCC, 0x4, MAP_FUNC, mr_findStart, NULL, NULL),
    BRIDGE_FUNC_MAP(0xD0, 0x4, MAP_FUNC, mr_findGetNext, NULL, NULL),
    BRIDGE_FUNC_MAP(0xD4, 0x4, MAP_FUNC, mr_findStop, NULL, NULL),
    BRIDGE_FUNC_MAP(0xD8, 0x4, MAP_FUNC, mr_exit, NULL, NULL),
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
    BRIDGE_FUNC_MAP(0x16C, 0x4, MAP_DATA, mr_screenBuf, NULL, NULL),
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
    BRIDGE_FUNC_MAP(0x1DC, 0x4, MAP_FUNC, _DrawPoint, NULL, NULL),
    BRIDGE_FUNC_MAP(0x1E0, 0x4, MAP_FUNC, _DrawBitmap, NULL, NULL),
    BRIDGE_FUNC_MAP(0x1E4, 0x4, MAP_FUNC, _DrawBitmapEx, NULL, NULL),
    BRIDGE_FUNC_MAP(0x1E8, 0x4, MAP_FUNC, DrawRect, NULL, NULL),
    BRIDGE_FUNC_MAP(0x1EC, 0x4, MAP_FUNC, _DrawText, NULL, NULL),
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

static BridgeMap mr_c_function_funcMap[] = {
    BRIDGE_FUNC_MAP(0x0, 0x4, MAP_DATA, start_of_ER_RW, NULL, NULL),  // 0x280248
    BRIDGE_FUNC_MAP(0x4, 0x4, MAP_DATA, ER_RW_Length, NULL, NULL),
    BRIDGE_FUNC_MAP(0x8, 0x4, MAP_DATA, ext_type, NULL, NULL),
    BRIDGE_FUNC_MAP(0xC, 0x4, MAP_DATA, mrc_extChunk, NULL, NULL),  // 0x280254
    BRIDGE_FUNC_MAP(0x10, 0x4, MAP_DATA, stack, NULL, NULL),
};

static BridgeMap mrc_extChunk_funcMap[] = {
    BRIDGE_FUNC_MAP(0x0, 0x4, MAP_DATA, check, NULL, NULL),
    BRIDGE_FUNC_MAP(0x4, 0x4, MAP_FUNC, init_func, NULL, NULL),
    BRIDGE_FUNC_MAP(0x8, 0x4, MAP_FUNC, event, NULL, NULL),
    BRIDGE_FUNC_MAP(0xC, 0x4, MAP_DATA, code_buf, NULL, NULL),
    BRIDGE_FUNC_MAP(0x10, 0x4, MAP_DATA, code_len, NULL, NULL),
    BRIDGE_FUNC_MAP(0x14, 0x4, MAP_DATA, var_buf, NULL, NULL),
    BRIDGE_FUNC_MAP(0x18, 0x4, MAP_DATA, var_len, NULL, NULL),
    BRIDGE_FUNC_MAP(0x1C, 0x4, MAP_DATA, global_p_buf, NULL, NULL),
    BRIDGE_FUNC_MAP(0x20, 0x4, MAP_DATA, global_p_len, NULL, NULL),
    BRIDGE_FUNC_MAP(0x24, 0x4, MAP_DATA, timer, NULL, NULL),
    BRIDGE_FUNC_MAP(0x28, 0x4, MAP_FUNC, sendAppEvent, NULL, NULL),
    BRIDGE_FUNC_MAP(0x2C, 0x4, MAP_DATA, extMrTable, NULL, NULL),
    BRIDGE_FUNC_MAP(0x30, 0x4, MAP_DATA, isPause, NULL, NULL),
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

static int init(uc_engine *uc, BridgeMap *map, uint32_t mapCount, uint32_t startAddress) {
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
                br_defaultInit(obj, uc, addr);
            }
        }
        mobj = malloc(sizeof(uIntMap));
        mobj->key = addr;
        mobj->data = obj;
        if (uIntMap_insert(&root, mobj)) {
            printf("uIntMap_insert() failed %d exists.\n", addr);
            return -1;
        }
    }
    return 0;
}

uc_err bridge_init(uc_engine *uc, uint32_t codeAddress, uint32_t startAddress) {
    mr_table_startAddress = startAddress;
    mr_c_function_startAddress = mr_table_startAddress + MR_TABLE_SIZE;
    mrc_extChunk_startAddress = mr_c_function_startAddress + MR_C_FUNCTION_SIZE;
    endAddress = mrc_extChunk_startAddress + MRC_EXTCHUNK_SIZE;

    uc_err err = init(uc, mr_table_funcMap, countof(mr_table_funcMap), mr_table_startAddress);
    if (err) return err;
    err = uc_mem_write(uc, codeAddress, &mr_table_startAddress, 4);
    if (err) return err;

    err = init(uc, mr_c_function_funcMap, countof(mr_c_function_funcMap), mr_c_function_startAddress);
    if (err) return err;
    err = uc_mem_write(uc, codeAddress + 4, &mr_c_function_startAddress, 4);
    if (err) return err;

    err = init(uc, mrc_extChunk_funcMap, countof(mrc_extChunk_funcMap), mrc_extChunk_startAddress);
    if (err) return err;

    LOG("startAddr: 0x%X, endAddr: 0x%X\n", startAddress, endAddress);
    LOG("mr_table_startAddress: 0x%X\n", mr_table_startAddress);
    LOG("mr_c_function_startAddress: 0x%X\n", mr_c_function_startAddress);
    LOG("mrc_extChunk_startAddress: 0x%X\n", mrc_extChunk_startAddress);
    return UC_ERR_OK;
}

// todo 传递参数超过4个，用寄存器传所有参数应该是错的，有待研究
void bridge_mr_init(uc_engine *uc) {
    // typedef int32 (*MR_C_FUNCTION)(void* P, int32 code, uint8* input, int32 input_len, uint8** output, int32* output_len);
    // mr_helper(&cfunction_table, 0, NULL, 0, NULL, NULL);
    LOG("bridge_mr_init()\n");

    uint32_t v = mr_c_function_startAddress;
    uc_reg_write(uc, UC_ARM_REG_R0, &v);  // p
    v = 0;
    uc_reg_write(uc, UC_ARM_REG_R1, &v);  // code
    uc_reg_write(uc, UC_ARM_REG_R2, &v);  // input
    uc_reg_write(uc, UC_ARM_REG_R3, &v);  // input_len
    uc_reg_write(uc, UC_ARM_REG_R4, &v);  // output
    uc_reg_write(uc, UC_ARM_REG_R5, &v);  // output_len

    runCode(uc, mr_helper_addr, STOP_ADDRESS, false);
}