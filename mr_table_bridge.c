#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "./header/bridge.h"

//////////////////////////////////////////////////////////////////////////////////////////
#define TAG "mr_table_bridge: "

static bool _mr_c_function_new(char *name, uc_engine *uc, uc_mem_type type,
                               uint64_t address, int size, int64_t value,
                               void *user_data) {
    uint32_t p0, p1, lr, ret;

    uc_reg_read(uc, UC_ARM_REG_R0, &p0);
    uc_reg_read(uc, UC_ARM_REG_R1, &p1);
    uc_reg_read(uc, UC_ARM_REG_LR, &lr);

    printf(TAG "ext call %s(0x%X[%u], 0x%X[%u])\n", name, p0, p0, p1, p1);
    dumpREG(uc);

    ret = MR_SUCCESS;
    uc_reg_write(uc, UC_ARM_REG_R0, &ret);
    uc_reg_write(uc, UC_ARM_REG_PC, &lr);  // 返回ext调用点
    // 返回true允许继续运行
    return true;
}

//////////////////////////////////////////////////////////////////////////////////////////
// 根据最后一个字段的位置得到
#define MR_TABLE_MAP_LEN (MR_STRUCT_INDEX_OF(mr_table, mr_platDrawChar) + 1)

#define BRIDGE_FUNC_MAP(field, mapType, func)                        \
    {                                                                \
        .name = #field, .pos = MR_STRUCT_OFFSET_OF(mr_table, field), \
        .type = mapType, .fn = func                                  \
    }

static BridgeMap funcMap[MR_TABLE_MAP_LEN] = {
    BRIDGE_FUNC_MAP(mr_malloc, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_free, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_realloc, MAP_FUNC, NULL),

    BRIDGE_FUNC_MAP(memcpy, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(memmove, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(strcpy, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(strncpy, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(strcat, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(strncat, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(memcmp, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(strcmp, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(strncmp, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(strcoll, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(memchr, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(memset, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(strlen, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(strstr, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(sprintf, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(atoi, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(strtoul, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(rand, MAP_FUNC, NULL),

    BRIDGE_FUNC_MAP(reserve0, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(reserve1, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(_mr_c_internal_table, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(_mr_c_port_table, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(_mr_c_function_new, MAP_FUNC, _mr_c_function_new),

    BRIDGE_FUNC_MAP(mr_printf, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_mem_get, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_mem_free, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_drawBitmap, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_getCharBitmap, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(g_mr_timerStart, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(g_mr_timerStop, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_getTime, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_getDatetime, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_getUserInfo, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_sleep, MAP_FUNC, NULL),

    BRIDGE_FUNC_MAP(mr_plat, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_platEx, MAP_FUNC, NULL),

    BRIDGE_FUNC_MAP(mr_ferrno, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_open, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_close, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_info, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_write, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_read, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_seek, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_getLen, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_remove, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_rename, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_mkDir, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_rmDir, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_findStart, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_findGetNext, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_findStop, MAP_FUNC, NULL),

    BRIDGE_FUNC_MAP(mr_exit, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_startShake, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_stopShake, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_playSound, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_stopSound, MAP_FUNC, NULL),

    BRIDGE_FUNC_MAP(mr_sendSms, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_call, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_getNetworkID, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_connectWAP, MAP_FUNC, NULL),

    BRIDGE_FUNC_MAP(mr_menuCreate, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_menuSetItem, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_menuShow, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(reserve, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(mr_menuRelease, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_menuRefresh, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_dialogCreate, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_dialogRelease, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_dialogRefresh, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_textCreate, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_textRelease, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_textRefresh, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_editCreate, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_editRelease, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_editGetText, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_winCreate, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_winRelease, MAP_FUNC, NULL),

    BRIDGE_FUNC_MAP(mr_getScreenInfo, MAP_FUNC, NULL),

    BRIDGE_FUNC_MAP(mr_initNetwork, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_closeNetwork, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_getHostByName, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_socket, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_connect, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_closeSocket, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_recv, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_recvfrom, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_send, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_sendto, MAP_FUNC, NULL),

    BRIDGE_FUNC_MAP(mr_screenBuf, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(mr_screen_w, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(mr_screen_h, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(mr_screen_bit, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(mr_bitmap, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(mr_tile, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(mr_map, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(mr_sound, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(mr_sprite, MAP_DATA, NULL),

    BRIDGE_FUNC_MAP(pack_filename, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(start_filename, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(old_pack_filename, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(old_start_filename, MAP_DATA, NULL),

    BRIDGE_FUNC_MAP(mr_ram_file, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(mr_ram_file_len, MAP_DATA, NULL),

    BRIDGE_FUNC_MAP(mr_soundOn, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(mr_shakeOn, MAP_DATA, NULL),

    BRIDGE_FUNC_MAP(LG_mem_base, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(LG_mem_len, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(LG_mem_end, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(LG_mem_left, MAP_DATA, NULL),

    BRIDGE_FUNC_MAP(mr_sms_cfg_buf, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(mr_md5_init, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_md5_append, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_md5_finish, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(_mr_load_sms_cfg, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(_mr_save_sms_cfg, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(_DispUpEx, MAP_FUNC, NULL),

    BRIDGE_FUNC_MAP(_DrawPoint, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(_DrawBitmap, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(_DrawBitmapEx, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(DrawRect, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(_DrawText, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(_BitmapCheck, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(_mr_readFile, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_wstrlen, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(mr_registerAPP, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(_DrawTextEx, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(_mr_EffSetCon, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(_mr_TestCom, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(_mr_TestCom1, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(c2u, MAP_FUNC, NULL),

    BRIDGE_FUNC_MAP(_mr_div, MAP_FUNC, NULL),
    BRIDGE_FUNC_MAP(_mr_mod, MAP_FUNC, NULL),

    BRIDGE_FUNC_MAP(LG_mem_min, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(LG_mem_top, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(mr_updcrc, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(start_fileparameter, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(mr_sms_return_flag, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(mr_sms_return_val, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(mr_unzip, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(mr_exit_cb, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(mr_exit_cb_data, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(mr_entry, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(mr_platDrawChar, MAP_FUNC, NULL),
};

static uint32_t mrTableStartAddress, mrTableEndAddress;

bool mr_table_bridge_exec(uc_engine *uc, uc_mem_type type, uint64_t address,
                          int size, int64_t value, void *user_data) {
    if (address < mrTableStartAddress || address > mrTableEndAddress) {
        return false;
    }
    int i = (address - mrTableStartAddress) / 4;
    BridgeMap *obj = &funcMap[i];
    if (obj->type == MAP_FUNC) {
        if (obj->fn == NULL) {
            printf(TAG "%s() Not yet implemented function !!! \n", obj->name);
            return false;
        }
        return obj->fn(obj->name, uc, type, address, size, value, user_data);
    }
    printf(TAG "unregister function at 0x%" PRIX64 "\n", address);
    return false;
}

uc_err mr_table_bridge_init(uc_engine *uc, uint32_t address) {
    mrTableStartAddress = address;

    // 地址表的作用是当ext尝试跳转到表中的地址执行时拦截下来
    uint32_t addressTable[MR_TABLE_MAP_LEN];
    for (int i = 0; i < MR_TABLE_MAP_LEN; i++) {
        addressTable[i] = mrTableStartAddress + funcMap[i].pos;
    }
    mrTableEndAddress = addressTable[MR_TABLE_MAP_LEN - 1];

    printf(TAG "mrTableStartAddress: 0x%X, mrTableEndAddress: 0x%X\n",
           mrTableStartAddress, mrTableEndAddress);

    int size = ALIGN(sizeof(addressTable), 4096);
    uc_err err = uc_mem_map(uc, mrTableStartAddress, size, UC_PROT_READ);
    if (err) {
        return err;
    }
    return uc_mem_write(uc, mrTableStartAddress, addressTable,
                        sizeof(addressTable));
}
