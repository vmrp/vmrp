#include "mrc_base.h"

#define offsetof(type, field) ((uint32) & ((type*)0)->field)
#define szof(type, field) sizeof(((type*)0)->field)
#define countof(x) (sizeof(x) / sizeof((x)[0]))
#define _STR(v) #v
#define STR(v) _STR(v)

typedef enum BridgeMapType {
    MAP_DATA,  // 数据字段
    MAP_FUNC   // 函数字段
} BridgeMapType;

typedef struct StructOffset {
    // mrp要求必需是字符数组，定义成字符串指针会导致字符串丢失
    char fieldName[50];
    uint32 pos;
    uint32 size;
    BridgeMapType type;
} StructOffset;

// clang-format off
#define GET_POS(field, mapType) \
    { #field, offsetof(mrc_extChunk_st, field), szof(mrc_extChunk_st, field), mapType }
// clang-format on

/////////////////////////////////////////////////////////////////////////////////////////////
// 因为在vs2005中直接引入mr_helper.h会有报错，为了方便省事，直接把结构体拿过来了，把所有报错的地方替换成相应大小的数据类型，指针换成void*就可以，用vim编辑器很快就能替换好
typedef struct _mrc_extChunk_st {
    int32 check;  // 0x7FD854EB 标志

    void* init_func;  // mr_c_function_load 函数指针

    void* event;  // mr_helper 函数指针

    uint8* code_buf;     // ext内存地址
    int32 code_len;      // ext长度
    uint8* var_buf;      // RW段地址
    int32 var_len;       // RW段长度
    void* global_p_buf;  // mr_c_function_st 表地址
    int32 global_p_len;  // mr_c_function_st 表长度
    int32 timer;

    void* sendAppEvent;
    void* extMrTable;  // mr_table函数表。

    // 后面的几乎没有使用，因为分配的0x30大小到这为止。
#ifdef MRC_PLUGIN
    void* eventEx;
#endif

    int32 isPause; /*1: pause 状态0:正常状态*/
} mrc_extChunk_st;

#define TABLE mrc_extChunk_st

// clang-format off
StructOffset offsets[] = {
    GET_POS(check, MAP_DATA),
    GET_POS(init_func, MAP_FUNC),
    GET_POS(event, MAP_FUNC),
    GET_POS(code_buf, MAP_DATA),
    GET_POS(code_len, MAP_DATA),
    GET_POS(var_buf, MAP_DATA),
    GET_POS(var_len, MAP_DATA),
    GET_POS(global_p_buf, MAP_DATA),
    GET_POS(global_p_len, MAP_DATA),
    GET_POS(timer, MAP_DATA),
    GET_POS(sendAppEvent, MAP_FUNC),
    GET_POS(extMrTable, MAP_DATA),
#ifdef MRC_PLUGIN
    GET_POS(eventEx, MAP_FUNC),
#endif
    GET_POS(isPause, MAP_DATA),
};
// clang-format on
/////////////////////////////////////////////////////////////////////////////////////////////

int32 mrc_init(void) {
    char* filename = STR(TABLE) "_offsets.txt";
    mrc_clearScreen(0, 0, 0);
    mrc_drawText(filename, 0, 0, 255, 255, 255, 0, 1);
    mrc_refreshScreen(0, 0, 240, 320);
    {
        int i;
        char buf[128];
        int32 f = mrc_open(filename, MR_FILE_CREATE | MR_FILE_WRONLY);
        for (i = 0; i < countof(offsets); i++) {
            StructOffset* o = &offsets[i];
            char* type = "MAP_DATA";
            if (o->type == MAP_FUNC) {
                type = "MAP_FUNC";
            }
            mrc_sprintf(buf, "BRIDGE_FUNC_MAP(0x%X, 0x%X, %s, %s, NULL),\r\n",
                        o->pos, o->size, type, o->fieldName);
            mrc_write(f, buf, mrc_strlen(buf));
        }
        mrc_sprintf(buf, "sizeof(%s) = 0x%X\r\n", STR(TABLE), sizeof(TABLE));
        mrc_write(f, buf, mrc_strlen(buf));
        mrc_close(f);
    }
    return MR_SUCCESS;
}

int32 mrc_exitApp(void) {
    return MR_SUCCESS;
}

int32 mrc_event(int32 code, int32 param0, int32 param1) {
    return MR_SUCCESS;
}

int32 mrc_pause() {
    return MR_SUCCESS;
}

int32 mrc_resume() {
    return MR_SUCCESS;
}

int32 mrc_extRecvAppEventEx(int32 code, int32 param0, int32 param1) {
    return MR_SUCCESS;
}

int32 mrc_extRecvAppEvent(int32 app, int32 code, int32 param0, int32 param1) {
    return MR_SUCCESS;
}
