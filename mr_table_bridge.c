#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "./header/mr_helper.h"
#include "./header/mr_table_bridge.h"
#include "./header/rbtree.h"
#include "./header/utils.h"

typedef struct uIntMap {
    struct rb_node node;
    unsigned int key;
    void *data;
} uIntMap;

static struct uIntMap *uIntMap_search(struct rb_root *root, unsigned int key) {
    struct rb_node *n = root->rb_node;
    uIntMap *obj;
    int cmp;

    while (n) {
        obj = rb_entry(n, uIntMap, node);

        cmp = key - obj->key;
        if (cmp < 0) {
            n = n->rb_left;
        } else if (cmp > 0) {
            n = n->rb_right;
        } else {
            return obj;
        }
    }
    return NULL;
}

static int uIntMap_insert(struct rb_root *root, uIntMap *obj) {
    struct rb_node **p = &(root->rb_node);
    struct rb_node *parent = NULL;
    uIntMap *cur;
    int cmp;

    while (*p) {
        parent = *p;
        cur = rb_entry(parent, uIntMap, node);
        cmp = obj->key - cur->key;
        if (cmp < 0) {
            p = &(*p)->rb_left;
        } else if (cmp > 0) {
            p = &(*p)->rb_right;
        } else {
            return -1;
        }
    }
    rb_link_node(&obj->node, parent, p);
    rb_insert_color(&obj->node, root);
    return 0;
}

static uIntMap *uIntMap_delete(struct rb_root *root, unsigned int key) {
    uIntMap *obj = uIntMap_search(root, key);
    if (!obj) {
        return NULL;
    }
    rb_erase(&obj->node, root);
    return obj;
}

static void testInsert(struct rb_root *root, unsigned int key, void *data) {
    uIntMap *obj;
    int ret;

    obj = malloc(sizeof(uIntMap));
    obj->key = key;
    obj->data = data;
    ret = uIntMap_insert(root, obj);
    if (ret == -1) {
        printf("insert failed %d exists.\n", key);
        return;
    }
    printf("insert %d success.\n", key);
}

static void testSearch(struct rb_root *root, unsigned int key) {
    uIntMap *obj = uIntMap_search(root, key);
    if (obj == NULL) {
        printf("search: not found %d\n", key);
    } else {
        printf("search: %d=%s\n", key, (char *)obj->data);
    }
}

static void printAll(struct rb_root *root) {
    for (struct rb_node *p = rb_first(root); p; p = rb_next(p)) {
        uIntMap *obj = rb_entry(p, uIntMap, node);
        printf("iterator: %d  \t  %s\n", obj->key, (char *)obj->data);
    }
}

static void testDelete(struct rb_root *root, unsigned int key) {
    uIntMap *obj = uIntMap_delete(root, key);
    if (obj != NULL) {
        printf("delete %d %s\n", obj->key, (char *)obj->data);
        free(obj);
    } else {
        printf("delete %d not found\n", key);
    }
}

void mr_table_bridge_testMain() {
    struct rb_root root = RB_ROOT;

    testInsert(&root, 100, "hell");
    testInsert(&root, 0, "world");
    testInsert(&root, 0, "world2");
    testInsert(&root, 990, "test");

    printAll(&root);

    testSearch(&root, 990);
    testSearch(&root, 22);

    testDelete(&root, 990);
    testDelete(&root, 990);
    testSearch(&root, 990);

    printAll(&root);
    testInsert(&root, 990, "test2");
    printAll(&root);
}

//////////////////////////////////////////////////////////////////////////////////////////
#define MR_TABLE_OFFSET(member) offsetof(mr_table, member)

// 最后一个字段的偏移
#define MR_TABLE_MAP_LEN (MR_TABLE_OFFSET(mr_platDrawChar) + 1)

#define MR_TABLE_START_ADDRESS MR_TABLE_ADDRESS
#define MR_TABLE_END_ADDRESS MR_TABLE_ADDRESS + MR_TABLE_MAP_LEN - 1

typedef void (*mrTableBridgeCB)(char *name, uc_engine *uc, uint64_t address,
                                uint32_t size, void *user_data);

typedef struct mrTableBridgeMap {
    char *funcName;
    mrTableBridgeCB fn;
} mrTableBridgeMap;

// 函数映射表，虽然有些浪费内存，但是快！
static mrTableBridgeMap mr_table_bridge_map[MR_TABLE_MAP_LEN];

void defaultBridge(char *name, uc_engine *uc, uint64_t address, uint32_t size,
                   void *user_data) {
    printf("===========>> %s() Not yet implemented function !!! \n", name);
    dumpREG(uc);
}

void mr_table_bridge_exec(uc_engine *uc, uint64_t address, uint32_t size,
                          void *user_data) {
    if (address < MR_TABLE_START_ADDRESS && address > MR_TABLE_END_ADDRESS) {
        return;
    }
    mrTableBridgeMap *obj =
        &mr_table_bridge_map[address - MR_TABLE_START_ADDRESS];
    if (obj->fn) {
        obj->fn(obj->funcName, uc, address, size, user_data);
        return;
    }
    printf("mr_table_bridge exec unregister function at 0x%" PRIX64 "\n",
           address);
}

#define FUNC_MAP(name, func)                                       \
    {                                                              \
        mrTableBridgeMap *obj;                                     \
        int offset = MR_TABLE_OFFSET(name);                        \
        obj = &mr_table_bridge_map[offset];                        \
        obj->funcName = #name;                                     \
        obj->fn = func;                                            \
        printf("register %s() at 0x%X\n", #name, offset); \
    }

void mr_table_bridge_init() {
    printf("mr_table_bridge_maps size: %I64d\n", sizeof(mr_table_bridge_map));

    memset(mr_table_bridge_map, 0, sizeof(mr_table_bridge_map));

    FUNC_MAP(mr_malloc, defaultBridge);
    FUNC_MAP(mr_free, defaultBridge);
    FUNC_MAP(mr_realloc, defaultBridge);

    //    T_memcpy       memcpy;
    //    T_memmove      memmove;
    //    T_strcpy       strcpy;
    //    T_strncpy      strncpy;
    //    T_strcat       strcat;
    //    T_strncat      strncat;
    //    T_memcmp       memcmp;
    //    T_strcmp       strcmp;
    //    T_strncmp      strncmp;
    //    T_strcoll      strcoll;
    //    T_memchr       memchr;
    //    T_memset       memset;
    //    T_strlen       strlen;
    //    T_strstr       strstr;
    //    T_sprintf      sprintf;
    //    T_atoi         atoi;
    //    T_strtoul      strtoul;
    //    T_rand       rand;

    //    void*          reserve0;
    //    void*          reserve1;
    //    mr_internal_table*       _mr_c_internal_table;
    //    mr_c_port_table*         _mr_c_port_table;
    //    T__mr_c_function_new		_mr_c_function_new;

    //    T_mr_printf              mr_printf;
    //    T_mr_mem_get             mr_mem_get ;
    //    T_mr_mem_free            mr_mem_free ;
    //    T_mr_drawBitmap          mr_drawBitmap;
    //    T_mr_getCharBitmap       mr_getCharBitmap;
    //    T_mr_timerStart          g_mr_timerStart;
    //    T_mr_timerStop           g_mr_timerStop;
    //    T_mr_getTime             mr_getTime;
    //    T_mr_getDatetime         mr_getDatetime;
    //    T_mr_getUserInfo         mr_getUserInfo;
    //    T_mr_sleep               mr_sleep;

    //    T_mr_plat                mr_plat;
    //    T_mr_platEx              mr_platEx;

    //    T_mr_ferrno              mr_ferrno;
    //    T_mr_open                mr_open;
    //    T_mr_close               mr_close;
    //    T_mr_info                mr_info;
    //    T_mr_write               mr_write;
    //    T_mr_read                mr_read;
    //    T_mr_seek                mr_seek;
    //    T_mr_getLen              mr_getLen;
    //    T_mr_remove              mr_remove;
    //    T_mr_rename              mr_rename;
    //    T_mr_mkDir               mr_mkDir;
    //    T_mr_rmDir               mr_rmDir;
    //    T_mr_findStart           mr_findStart;
    //    T_mr_findGetNext         mr_findGetNext;
    //    T_mr_findStop            mr_findStop;

    //    T_mr_exit                mr_exit;
    //    T_mr_startShake          mr_startShake;
    //    T_mr_stopShake           mr_stopShake;
    //    T_mr_playSound           mr_playSound;
    //    T_mr_stopSound           mr_stopSound ;

    //    T_mr_sendSms             mr_sendSms;
    //    T_mr_call                mr_call;
    //    T_mr_getNetworkID        mr_getNetworkID;
    //    T_mr_connectWAP          mr_connectWAP;

    //    T_mr_menuCreate          mr_menuCreate;
    //    T_mr_menuSetItem         mr_menuSetItem;
    //    T_mr_menuShow            mr_menuShow;
    //    void*                    reserve;
    //    T_mr_menuRelease         mr_menuRelease;
    //    T_mr_menuRefresh         mr_menuRefresh;
    //    T_mr_dialogCreate        mr_dialogCreate;
    //    T_mr_dialogRelease       mr_dialogRelease;
    //    T_mr_dialogRefresh       mr_dialogRefresh;
    //    T_mr_textCreate          mr_textCreate;
    //    T_mr_textRelease         mr_textRelease;
    //    T_mr_textRefresh         mr_textRefresh;
    //    T_mr_editCreate          mr_editCreate;
    //    T_mr_editRelease         mr_editRelease;
    //    T_mr_editGetText         mr_editGetText;
    //    T_mr_winCreate           mr_winCreate;
    //    T_mr_winRelease          mr_winRelease;

    //    T_mr_getScreenInfo       mr_getScreenInfo;

    //    T_mr_initNetwork         mr_initNetwork;
    //    T_mr_closeNetwork        mr_closeNetwork;
    //    T_mr_getHostByName       mr_getHostByName;
    //    T_mr_socket              mr_socket;
    //    T_mr_connect             mr_connect;
    //    T_mr_closeSocket         mr_closeSocket;
    //    T_mr_recv                mr_recv;
    //    T_mr_recvfrom            mr_recvfrom;
    //    T_mr_send                mr_send;
    //    T_mr_sendto              mr_sendto;

    //    uint16**               mr_screenBuf;
    //    int32*                 mr_screen_w;
    //    int32*                 mr_screen_h;
    //    int32*                 mr_screen_bit;
    //    mr_bitmapSt*           mr_bitmap;
    //    mr_tileSt*             mr_tile;
    //    int16**                mr_map;
    //    mr_soundSt*            mr_sound;
    //    mr_spriteSt*           mr_sprite;

    //    char*                  pack_filename;
    //    char*                  start_filename;
    //    char*                  old_pack_filename;
    //    char*                  old_start_filename;

    //    char**                 mr_ram_file;
    //    int32*                 mr_ram_file_len;

    //    int8*                  mr_soundOn;
    //    int8*                  mr_shakeOn;

    //    char**                 LG_mem_base;	//VM 内存基址
    //    int32*                 LG_mem_len;	//VM 内存大小
    //    char**                 LG_mem_end;	//VM 内存终止
    //    int32*                 LG_mem_left;	//VM 剩余内存

    //    uint8*                 mr_sms_cfg_buf;
    //    T_mr_md5_init          mr_md5_init;
    //    T_mr_md5_append        mr_md5_append;
    //    T_mr_md5_finish        mr_md5_finish;
    //    T__mr_load_sms_cfg     _mr_load_sms_cfg;
    //    T__mr_save_sms_cfg     _mr_save_sms_cfg;
    //    T__DispUpEx            _DispUpEx;

    //    T__DrawPoint           _DrawPoint;
    //    T__DrawBitmap          _DrawBitmap;
    //    T__DrawBitmapEx        _DrawBitmapEx;
    //    T_DrawRect             DrawRect;
    //    T__DrawText            _DrawText;
    //    T__BitmapCheck         _BitmapCheck;
    //    T__mr_readFile         _mr_readFile;
    //    T_mr_wstrlen           mr_wstrlen;
    //    T_mr_registerAPP       mr_registerAPP;
    //    T__DrawTextEx          _DrawTextEx;  //1936
    //    T__mr_EffSetCon        _mr_EffSetCon;
    //    T__mr_TestCom          _mr_TestCom;
    //    T__mr_TestCom1         _mr_TestCom1;//1938
    //    T_c2u                  c2u;  //1939

    //    T__mr_div _mr_div;           //1941
    //    T__mr_mod _mr_mod;

    //    uint32*   LG_mem_min;
    //    uint32*    LG_mem_top;
    //    void*      mr_updcrc;    //1943
    //    char*       start_fileparameter;//1945
    //    void*       mr_sms_return_flag;//1949
    //    void*       mr_sms_return_val;
    //    void*		mr_unzip;   //1950
    //    mrc_timerCB*  mr_exit_cb;//1951
    //    int32*        mr_exit_cb_data;//1951
    //    char*         mr_entry;//1952,V2000-V2002不支持
    //    T_mr_platDrawChar   mr_platDrawChar; //1961
}