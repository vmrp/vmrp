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
// 因为mrp是在32位处理器上运行，所以指针是4字节，偏移量应该是以32位指针地址计算
#define MR_TABLE_OFFSET(member) \
    (offsetof(mr_table, member) / ((sizeof(void *) / 4)))

// 字段的索引位置
#define MR_TABLE_INDEX(member) (MR_TABLE_OFFSET(member) / 4)

typedef void (*mrTableBridgeCB)(char *name, uc_engine *uc, uint64_t address,
                                uint32_t size, void *user_data);

void defaultBridge(char *name, uc_engine *uc, uint64_t address, uint32_t size,
                   void *user_data);
typedef enum mrTableBridgeMapType {
    MAP_DATA,
    MAP_FUNC,
} mrTableBridgeMapType;

typedef struct mrTableBridgeMap {
    char *name;
    mrTableBridgeMapType type;
    mrTableBridgeCB fn;
} mrTableBridgeMap;

#define FUNC_MAP(field, mapType, func) \
    { .name = #field, .type = mapType, .fn = func }

// 根据最后一个字段的位置得到
#define MR_TABLE_MAP_LEN (MR_TABLE_INDEX(mr_platDrawChar) + 1)

static mrTableBridgeMap funcMap[MR_TABLE_MAP_LEN] = {
    FUNC_MAP(mr_malloc, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_free, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_realloc, MAP_FUNC, defaultBridge),

    FUNC_MAP(memcpy, MAP_FUNC, defaultBridge),
    FUNC_MAP(memmove, MAP_FUNC, defaultBridge),
    FUNC_MAP(strcpy, MAP_FUNC, defaultBridge),
    FUNC_MAP(strncpy, MAP_FUNC, defaultBridge),
    FUNC_MAP(strcat, MAP_FUNC, defaultBridge),
    FUNC_MAP(strncat, MAP_FUNC, defaultBridge),
    FUNC_MAP(memcmp, MAP_FUNC, defaultBridge),
    FUNC_MAP(strcmp, MAP_FUNC, defaultBridge),
    FUNC_MAP(strncmp, MAP_FUNC, defaultBridge),
    FUNC_MAP(strcoll, MAP_FUNC, defaultBridge),
    FUNC_MAP(memchr, MAP_FUNC, defaultBridge),
    FUNC_MAP(memset, MAP_FUNC, defaultBridge),
    FUNC_MAP(strlen, MAP_FUNC, defaultBridge),
    FUNC_MAP(strstr, MAP_FUNC, defaultBridge),
    FUNC_MAP(sprintf, MAP_FUNC, defaultBridge),
    FUNC_MAP(atoi, MAP_FUNC, defaultBridge),
    FUNC_MAP(strtoul, MAP_FUNC, defaultBridge),
    FUNC_MAP(rand, MAP_FUNC, defaultBridge),

    FUNC_MAP(reserve0, MAP_DATA, defaultBridge),
    FUNC_MAP(reserve1, MAP_DATA, defaultBridge),
    FUNC_MAP(_mr_c_internal_table, MAP_DATA, defaultBridge),
    FUNC_MAP(_mr_c_port_table, MAP_DATA, defaultBridge),
    FUNC_MAP(_mr_c_function_new, MAP_FUNC, defaultBridge),

    FUNC_MAP(mr_printf, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_mem_get, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_mem_free, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_drawBitmap, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_getCharBitmap, MAP_FUNC, defaultBridge),
    FUNC_MAP(g_mr_timerStart, MAP_FUNC, defaultBridge),
    FUNC_MAP(g_mr_timerStop, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_getTime, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_getDatetime, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_getUserInfo, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_sleep, MAP_FUNC, defaultBridge),

    FUNC_MAP(mr_plat, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_platEx, MAP_FUNC, defaultBridge),

    FUNC_MAP(mr_ferrno, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_open, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_close, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_info, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_write, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_read, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_seek, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_getLen, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_remove, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_rename, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_mkDir, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_rmDir, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_findStart, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_findGetNext, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_findStop, MAP_FUNC, defaultBridge),

    FUNC_MAP(mr_exit, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_startShake, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_stopShake, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_playSound, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_stopSound, MAP_FUNC, defaultBridge),

    FUNC_MAP(mr_sendSms, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_call, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_getNetworkID, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_connectWAP, MAP_FUNC, defaultBridge),

    FUNC_MAP(mr_menuCreate, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_menuSetItem, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_menuShow, MAP_FUNC, defaultBridge),
    FUNC_MAP(reserve, MAP_DATA, defaultBridge),
    FUNC_MAP(mr_menuRelease, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_menuRefresh, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_dialogCreate, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_dialogRelease, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_dialogRefresh, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_textCreate, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_textRelease, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_textRefresh, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_editCreate, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_editRelease, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_editGetText, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_winCreate, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_winRelease, MAP_FUNC, defaultBridge),

    FUNC_MAP(mr_getScreenInfo, MAP_FUNC, defaultBridge),

    FUNC_MAP(mr_initNetwork, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_closeNetwork, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_getHostByName, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_socket, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_connect, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_closeSocket, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_recv, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_recvfrom, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_send, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_sendto, MAP_FUNC, defaultBridge),

    FUNC_MAP(mr_screenBuf, MAP_DATA, defaultBridge),
    FUNC_MAP(mr_screen_w, MAP_DATA, defaultBridge),
    FUNC_MAP(mr_screen_h, MAP_DATA, defaultBridge),
    FUNC_MAP(mr_screen_bit, MAP_DATA, defaultBridge),
    FUNC_MAP(mr_bitmap, MAP_DATA, defaultBridge),
    FUNC_MAP(mr_tile, MAP_DATA, defaultBridge),
    FUNC_MAP(mr_map, MAP_DATA, defaultBridge),
    FUNC_MAP(mr_sound, MAP_DATA, defaultBridge),
    FUNC_MAP(mr_sprite, MAP_DATA, defaultBridge),

    FUNC_MAP(pack_filename, MAP_DATA, defaultBridge),
    FUNC_MAP(start_filename, MAP_DATA, defaultBridge),
    FUNC_MAP(old_pack_filename, MAP_DATA, defaultBridge),
    FUNC_MAP(old_start_filename, MAP_DATA, defaultBridge),

    FUNC_MAP(mr_ram_file, MAP_DATA, defaultBridge),
    FUNC_MAP(mr_ram_file_len, MAP_DATA, defaultBridge),

    FUNC_MAP(mr_soundOn, MAP_DATA, defaultBridge),
    FUNC_MAP(mr_shakeOn, MAP_DATA, defaultBridge),

    FUNC_MAP(LG_mem_base, MAP_DATA, defaultBridge),
    FUNC_MAP(LG_mem_len, MAP_DATA, defaultBridge),
    FUNC_MAP(LG_mem_end, MAP_DATA, defaultBridge),
    FUNC_MAP(LG_mem_left, MAP_DATA, defaultBridge),

    FUNC_MAP(mr_sms_cfg_buf, MAP_DATA, defaultBridge),
    FUNC_MAP(mr_md5_init, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_md5_append, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_md5_finish, MAP_FUNC, defaultBridge),
    FUNC_MAP(_mr_load_sms_cfg, MAP_FUNC, defaultBridge),
    FUNC_MAP(_mr_save_sms_cfg, MAP_FUNC, defaultBridge),
    FUNC_MAP(_DispUpEx, MAP_FUNC, defaultBridge),

    FUNC_MAP(_DrawPoint, MAP_FUNC, defaultBridge),
    FUNC_MAP(_DrawBitmap, MAP_FUNC, defaultBridge),
    FUNC_MAP(_DrawBitmapEx, MAP_FUNC, defaultBridge),
    FUNC_MAP(DrawRect, MAP_FUNC, defaultBridge),
    FUNC_MAP(_DrawText, MAP_FUNC, defaultBridge),
    FUNC_MAP(_BitmapCheck, MAP_FUNC, defaultBridge),
    FUNC_MAP(_mr_readFile, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_wstrlen, MAP_FUNC, defaultBridge),
    FUNC_MAP(mr_registerAPP, MAP_FUNC, defaultBridge),
    FUNC_MAP(_DrawTextEx, MAP_FUNC, defaultBridge),
    FUNC_MAP(_mr_EffSetCon, MAP_FUNC, defaultBridge),
    FUNC_MAP(_mr_TestCom, MAP_FUNC, defaultBridge),
    FUNC_MAP(_mr_TestCom1, MAP_FUNC, defaultBridge),
    FUNC_MAP(c2u, MAP_FUNC, defaultBridge),

    FUNC_MAP(_mr_div, MAP_FUNC, defaultBridge),
    FUNC_MAP(_mr_mod, MAP_FUNC, defaultBridge),

    FUNC_MAP(LG_mem_min, MAP_DATA, defaultBridge),
    FUNC_MAP(LG_mem_top, MAP_DATA, defaultBridge),
    FUNC_MAP(mr_updcrc, MAP_DATA, defaultBridge),
    FUNC_MAP(start_fileparameter, MAP_DATA, defaultBridge),
    FUNC_MAP(mr_sms_return_flag, MAP_DATA, defaultBridge),
    FUNC_MAP(mr_sms_return_val, MAP_DATA, defaultBridge),
    FUNC_MAP(mr_unzip, MAP_DATA, defaultBridge),
    FUNC_MAP(mr_exit_cb, MAP_DATA, defaultBridge),
    FUNC_MAP(mr_exit_cb_data, MAP_DATA, defaultBridge),
    FUNC_MAP(mr_entry, MAP_DATA, defaultBridge),
    FUNC_MAP(mr_platDrawChar, MAP_FUNC, defaultBridge),
};

static uint32_t mrTableStartAddress, mrTableEndAddress;

void defaultBridge(char *name, uc_engine *uc, uint64_t address, uint32_t size,
                   void *user_data) {
    printf("===========>> %s() Not yet implemented function !!! \n", name);
    dumpREG(uc);
}

void mr_table_bridge_exec(uc_engine *uc, uint64_t address, uint32_t size,
                          void *user_data) {
    if (address < mrTableStartAddress || address > mrTableEndAddress) {
        return;
    }
    mrTableBridgeMap *obj = &funcMap[address - mrTableStartAddress];
    if (obj->type == MAP_FUNC && obj->fn) {
        obj->fn(obj->name, uc, address, size, user_data);
        return;
    }
    printf("mr_table_bridge_exec(): unregister function at 0x%" PRIX64 "\n",
           address);
}

// 字节对齐
#define ALIGN(x, align) (((x) + ((align)-1)) & ~((align)-1))

uc_err mr_table_bridge_mapAddressTable(uc_engine *uc) {
    uint32_t addressTable[MR_TABLE_MAP_LEN];
    for (int i = 0; i < MR_TABLE_MAP_LEN; i++) {
        // 因为mr_table全部都是指针，所以可以计算出所有偏移量
        addressTable[i] = mrTableStartAddress + i * 4;
    }
    int size = ALIGN(sizeof(addressTable), 4096);
    uc_err err = uc_mem_map(uc, mrTableStartAddress, size, UC_PROT_READ);
    if (err) {
        printf(
            "Failed on mr_table_bridge_mapAddressTable() uc_mem_map() with "
            "error returned: "
            "%u (%s)\n",
            err, uc_strerror(err));
        return err;
    }
    err = uc_mem_write(uc, mrTableStartAddress, addressTable,
                       sizeof(addressTable));
    if (err) {
        printf(
            "Failed on mr_table_bridge_mapAddressTable() uc_mem_write() with "
            "error returned: "
            "%u (%s)\n",
            err, uc_strerror(err));
    }
    return err;
}

void mr_table_bridge_init(uint32_t mrTableAddress) {
    mrTableStartAddress = mrTableAddress;
    mrTableEndAddress = mrTableStartAddress + (MR_TABLE_MAP_LEN - 1) * 4;
    printf(
        "mr_table_bridge mrTableStartAddress: 0x%X, "
        "mrTableEndAddress: 0x%X\n",
        mrTableStartAddress, mrTableEndAddress);
}