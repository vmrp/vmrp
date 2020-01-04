#include "mrc_base.h"

#define offsetof(type, field) ((uint32) & ((type*)0)->field)
#define countof(x) (sizeof(x) / sizeof((x)[0]))

#undef memcpy
#undef memmove
#undef strcpy
#undef strncpy
#undef strcat
#undef strncat
#undef memcmp
#undef strcmp
#undef strncmp
#undef strcoll
#undef memchr
#undef memset
#undef strlen
#undef strstr
#undef sprintf
#undef atoi
#undef strtoul

/////////////////////////////////////////////////////////////////////////////////////////////
// 因为在vs2005中直接引入mr_helper.h会有报错，为了方便省事，直接把结构体拿过来了，把所有报错的地方替换成相应大小的数据类型，指针换成void*就可以，用vim编辑器很快就能替换好

typedef struct {
    void* mr_malloc;
    void* mr_free;
    void* mr_realloc;

    void* memcpy;
    void* memmove;
    void* strcpy;
    void* strncpy;
    void* strcat;
    void* strncat;
    void* memcmp;
    void* strcmp;
    void* strncmp;
    void* strcoll;
    void* memchr;
    void* memset;
    void* strlen;
    void* strstr;
    void* sprintf;
    void* atoi;
    void* strtoul;
    void* rand;

    void* reserve0;
    void* reserve1;
    void** _mr_c_internal_table;
    void** _mr_c_port_table;
    void* _mr_c_function_new;

    void* mr_printf;
    void* mr_mem_get;
    void* mr_mem_free;
    void* mr_drawBitmap;
    void* mr_getCharBitmap;
    void* g_mr_timerStart;
    void* g_mr_timerStop;
    void* mr_getTime;
    void* mr_getDatetime;
    void* mr_getUserInfo;
    void* mr_sleep;

    void* mr_plat;
    void* mr_platEx;

    void* mr_ferrno;
    void* mr_open;
    void* mr_close;
    void* mr_info;
    void* mr_write;
    void* mr_read;
    void* mr_seek;
    void* mr_getLen;
    void* mr_remove;
    void* mr_rename;
    void* mr_mkDir;
    void* mr_rmDir;
    void* mr_findStart;
    void* mr_findGetNext;
    void* mr_findStop;

    void* mr_exit;
    void* mr_startShake;
    void* mr_stopShake;
    void* mr_playSound;
    void* mr_stopSound;

    void* mr_sendSms;
    void* mr_call;
    void* mr_getNetworkID;
    void* mr_connectWAP;

    void* mr_menuCreate;
    void* mr_menuSetItem;
    void* mr_menuShow;
    void* reserve;
    void* mr_menuRelease;
    void* mr_menuRefresh;
    void* mr_dialogCreate;
    void* mr_dialogRelease;
    void* mr_dialogRefresh;
    void* mr_textCreate;
    void* mr_textRelease;
    void* mr_textRefresh;
    void* mr_editCreate;
    void* mr_editRelease;
    void* mr_editGetText;
    void* mr_winCreate;
    void* mr_winRelease;

    void* mr_getScreenInfo;

    void* mr_initNetwork;
    void* mr_closeNetwork;
    void* mr_getHostByName;
    void* mr_socket;
    void* mr_connect;
    void* mr_closeSocket;
    void* mr_recv;
    void* mr_recvfrom;
    void* mr_send;
    void* mr_sendto;

    uint16** mr_screenBuf;
    int32* mr_screen_w;
    int32* mr_screen_h;
    int32* mr_screen_bit;
    mr_bitmapSt* mr_bitmap;
    mr_tileSt* mr_tile;
    int16** mr_map;
    void* mr_sound;
    mr_spriteSt* mr_sprite;

    char* pack_filename;
    char* start_filename;
    char* old_pack_filename;
    char* old_start_filename;

    char** mr_ram_file;
    int32* mr_ram_file_len;

    int8* mr_soundOn;
    int8* mr_shakeOn;

    char** LG_mem_base;  // VM 内存基址
    int32* LG_mem_len;   // VM 内存大小
    char** LG_mem_end;   // VM 内存终止
    int32* LG_mem_left;  // VM 剩余内存

    uint8* mr_sms_cfg_buf;
    void* mr_md5_init;
    void* mr_md5_append;
    void* mr_md5_finish;
    void* _mr_load_sms_cfg;
    void* _mr_save_sms_cfg;
    void* _DispUpEx;

    void* _DrawPoint;
    void* _DrawBitmap;
    void* _DrawBitmapEx;
    void* DrawRect;
    void* _DrawText;
    void* _BitmapCheck;
    void* _mr_readFile;
    void* mr_wstrlen;
    void* mr_registerAPP;
    void* _DrawTextEx;  // 1936
    void* _mr_EffSetCon;
    void* _mr_TestCom;
    void* _mr_TestCom1;  // 1938
    void* c2u;           // 1939

    void* _mr_div;  // 1941
    void* _mr_mod;

    uint32* LG_mem_min;
    uint32* LG_mem_top;
    void* mr_updcrc;            // 1943
    char* start_fileparameter;  // 1945
    void* mr_sms_return_flag;   // 1949
    void* mr_sms_return_val;
    void* mr_unzip;           // 1950
    mrc_timerCB* mr_exit_cb;  // 1951
    int32* mr_exit_cb_data;   // 1951
    char* mr_entry;           // 1952,V2000-V2002不支持
    void* mr_platDrawChar;    // 1961
} mr_table;

/////////////////////////////////////////////////////////////////////////////////////////////

typedef enum BridgeMapType {
    MAP_DATA,  // 数据字段
    MAP_FUNC  // 函数字段
} BridgeMapType;

typedef struct StructOffset {
    // mrp要求必需是字符数组，定义成字符串指针会导致字符串丢失
    char fieldName[50];
    uint32 pos;
    BridgeMapType type;
} StructOffset;

#define GET_POS(field, mapType) \
    { #field, offsetof(mr_table, field), mapType }

StructOffset offsets[] = {
    GET_POS(mr_malloc, MAP_FUNC),
    GET_POS(mr_free, MAP_FUNC),
    GET_POS(mr_realloc, MAP_FUNC),

    GET_POS(memcpy, MAP_FUNC),
    GET_POS(memmove, MAP_FUNC),
    GET_POS(strcpy, MAP_FUNC),
    GET_POS(strncpy, MAP_FUNC),
    GET_POS(strcat, MAP_FUNC),
    GET_POS(strncat, MAP_FUNC),
    GET_POS(memcmp, MAP_FUNC),
    GET_POS(strcmp, MAP_FUNC),
    GET_POS(strncmp, MAP_FUNC),
    GET_POS(strcoll, MAP_FUNC),
    GET_POS(memchr, MAP_FUNC),
    GET_POS(memset, MAP_FUNC),
    GET_POS(strlen, MAP_FUNC),
    GET_POS(strstr, MAP_FUNC),
    GET_POS(sprintf, MAP_FUNC),
    GET_POS(atoi, MAP_FUNC),
    GET_POS(strtoul, MAP_FUNC),
    GET_POS(rand, MAP_FUNC),

    GET_POS(reserve0, MAP_DATA),
    GET_POS(reserve1, MAP_DATA),
    GET_POS(_mr_c_internal_table, MAP_DATA),
    GET_POS(_mr_c_port_table, MAP_DATA),
    GET_POS(_mr_c_function_new, MAP_FUNC),

    GET_POS(mr_printf, MAP_FUNC),
    GET_POS(mr_mem_get, MAP_FUNC),
    GET_POS(mr_mem_free, MAP_FUNC),
    GET_POS(mr_drawBitmap, MAP_FUNC),
    GET_POS(mr_getCharBitmap, MAP_FUNC),
    GET_POS(g_mr_timerStart, MAP_FUNC),
    GET_POS(g_mr_timerStop, MAP_FUNC),
    GET_POS(mr_getTime, MAP_FUNC),
    GET_POS(mr_getDatetime, MAP_FUNC),
    GET_POS(mr_getUserInfo, MAP_FUNC),
    GET_POS(mr_sleep, MAP_FUNC),

    GET_POS(mr_plat, MAP_FUNC),
    GET_POS(mr_platEx, MAP_FUNC),

    GET_POS(mr_ferrno, MAP_FUNC),
    GET_POS(mr_open, MAP_FUNC),
    GET_POS(mr_close, MAP_FUNC),
    GET_POS(mr_info, MAP_FUNC),
    GET_POS(mr_write, MAP_FUNC),
    GET_POS(mr_read, MAP_FUNC),
    GET_POS(mr_seek, MAP_FUNC),
    GET_POS(mr_getLen, MAP_FUNC),
    GET_POS(mr_remove, MAP_FUNC),
    GET_POS(mr_rename, MAP_FUNC),
    GET_POS(mr_mkDir, MAP_FUNC),
    GET_POS(mr_rmDir, MAP_FUNC),
    GET_POS(mr_findStart, MAP_FUNC),
    GET_POS(mr_findGetNext, MAP_FUNC),
    GET_POS(mr_findStop, MAP_FUNC),

    GET_POS(mr_exit, MAP_FUNC),
    GET_POS(mr_startShake, MAP_FUNC),
    GET_POS(mr_stopShake, MAP_FUNC),
    GET_POS(mr_playSound, MAP_FUNC),
    GET_POS(mr_stopSound, MAP_FUNC),

    GET_POS(mr_sendSms, MAP_FUNC),
    GET_POS(mr_call, MAP_FUNC),
    GET_POS(mr_getNetworkID, MAP_FUNC),
    GET_POS(mr_connectWAP, MAP_FUNC),

    GET_POS(mr_menuCreate, MAP_FUNC),
    GET_POS(mr_menuSetItem, MAP_FUNC),
    GET_POS(mr_menuShow, MAP_FUNC),
    GET_POS(reserve, MAP_DATA),
    GET_POS(mr_menuRelease, MAP_FUNC),
    GET_POS(mr_menuRefresh, MAP_FUNC),
    GET_POS(mr_dialogCreate, MAP_FUNC),
    GET_POS(mr_dialogRelease, MAP_FUNC),
    GET_POS(mr_dialogRefresh, MAP_FUNC),
    GET_POS(mr_textCreate, MAP_FUNC),
    GET_POS(mr_textRelease, MAP_FUNC),
    GET_POS(mr_textRefresh, MAP_FUNC),
    GET_POS(mr_editCreate, MAP_FUNC),
    GET_POS(mr_editRelease, MAP_FUNC),
    GET_POS(mr_editGetText, MAP_FUNC),
    GET_POS(mr_winCreate, MAP_FUNC),
    GET_POS(mr_winRelease, MAP_FUNC),

    GET_POS(mr_getScreenInfo, MAP_FUNC),

    GET_POS(mr_initNetwork, MAP_FUNC),
    GET_POS(mr_closeNetwork, MAP_FUNC),
    GET_POS(mr_getHostByName, MAP_FUNC),
    GET_POS(mr_socket, MAP_FUNC),
    GET_POS(mr_connect, MAP_FUNC),
    GET_POS(mr_closeSocket, MAP_FUNC),
    GET_POS(mr_recv, MAP_FUNC),
    GET_POS(mr_recvfrom, MAP_FUNC),
    GET_POS(mr_send, MAP_FUNC),
    GET_POS(mr_sendto, MAP_FUNC),

    GET_POS(mr_screenBuf, MAP_DATA),
    GET_POS(mr_screen_w, MAP_DATA),
    GET_POS(mr_screen_h, MAP_DATA),
    GET_POS(mr_screen_bit, MAP_DATA),
    GET_POS(mr_bitmap, MAP_DATA),
    GET_POS(mr_tile, MAP_DATA),
    GET_POS(mr_map, MAP_DATA),
    GET_POS(mr_sound, MAP_DATA),
    GET_POS(mr_sprite, MAP_DATA),

    GET_POS(pack_filename, MAP_DATA),
    GET_POS(start_filename, MAP_DATA),
    GET_POS(old_pack_filename, MAP_DATA),
    GET_POS(old_start_filename, MAP_DATA),

    GET_POS(mr_ram_file, MAP_DATA),
    GET_POS(mr_ram_file_len, MAP_DATA),

    GET_POS(mr_soundOn, MAP_DATA),
    GET_POS(mr_shakeOn, MAP_DATA),

    GET_POS(LG_mem_base, MAP_DATA),
    GET_POS(LG_mem_len, MAP_DATA),
    GET_POS(LG_mem_end, MAP_DATA),
    GET_POS(LG_mem_left, MAP_DATA),

    GET_POS(mr_sms_cfg_buf, MAP_DATA),
    GET_POS(mr_md5_init, MAP_FUNC),
    GET_POS(mr_md5_append, MAP_FUNC),
    GET_POS(mr_md5_finish, MAP_FUNC),
    GET_POS(_mr_load_sms_cfg, MAP_FUNC),
    GET_POS(_mr_save_sms_cfg, MAP_FUNC),
    GET_POS(_DispUpEx, MAP_FUNC),

    GET_POS(_DrawPoint, MAP_FUNC),
    GET_POS(_DrawBitmap, MAP_FUNC),
    GET_POS(_DrawBitmapEx, MAP_FUNC),
    GET_POS(DrawRect, MAP_FUNC),
    GET_POS(_DrawText, MAP_FUNC),
    GET_POS(_BitmapCheck, MAP_FUNC),
    GET_POS(_mr_readFile, MAP_FUNC),
    GET_POS(mr_wstrlen, MAP_FUNC),
    GET_POS(mr_registerAPP, MAP_FUNC),
    GET_POS(_DrawTextEx, MAP_FUNC),
    GET_POS(_mr_EffSetCon, MAP_FUNC),
    GET_POS(_mr_TestCom, MAP_FUNC),
    GET_POS(_mr_TestCom1, MAP_FUNC),
    GET_POS(c2u, MAP_FUNC),

    GET_POS(_mr_div, MAP_FUNC),
    GET_POS(_mr_mod, MAP_FUNC),

    GET_POS(LG_mem_min, MAP_DATA),
    GET_POS(LG_mem_top, MAP_DATA),
    GET_POS(mr_updcrc, MAP_DATA),
    GET_POS(start_fileparameter, MAP_DATA),
    GET_POS(mr_sms_return_flag, MAP_DATA),
    GET_POS(mr_sms_return_val, MAP_DATA),
    GET_POS(mr_unzip, MAP_DATA),
    GET_POS(mr_exit_cb, MAP_DATA),
    GET_POS(mr_exit_cb_data, MAP_DATA),
    GET_POS(mr_entry, MAP_DATA),
    GET_POS(mr_platDrawChar, MAP_FUNC),
};

int32 mrc_init(void) {
    char* filename = "mr_table_offsets.txt";
    mrc_clearScreen(0, 0, 0);
    mrc_drawText(filename, 0, 0, 255, 255, 255, 0, 1);
    mrc_refreshScreen(0, 0, 240, 320);
    {
        int i;
        char buf[128];
        int32 f = mrc_open(filename, MR_FILE_CREATE | MR_FILE_WRONLY);
        for (i = 0; i < countof(offsets); i++) {
            StructOffset* o = &offsets[i];
            if (o->type == MAP_FUNC) {
                mrc_sprintf(buf,
                            "BRIDGE_FUNC_MAP(0x%X, %s, MAP_FUNC, NULL),\r\n",
                            o->pos, o->fieldName);
            } else if (o->type == MAP_DATA) {
                mrc_sprintf(buf,
                            "BRIDGE_FUNC_MAP(0x%X, %s, MAP_DATA, NULL),\r\n",
                            o->pos, o->fieldName);
            }
            mrc_write(f, buf, mrc_strlen(buf));
        }
        mrc_close(f);
    }
    return MR_SUCCESS;
}

int32 mrc_exitApp(void) { return MR_SUCCESS; }

int32 mrc_event(int32 code, int32 param0, int32 param1) { return MR_SUCCESS; }

int32 mrc_pause() { return MR_SUCCESS; }

int32 mrc_resume() { return MR_SUCCESS; }

int32 mrc_extRecvAppEventEx(int32 code, int32 param0, int32 param1) {
    return MR_SUCCESS;
}

int32 mrc_extRecvAppEvent(int32 app, int32 code, int32 param0, int32 param1) {
    return MR_SUCCESS;
}
