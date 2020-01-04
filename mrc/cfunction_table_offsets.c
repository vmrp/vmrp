#include "mrc_base.h"

#define offsetof(type, field) ((uint32) & ((type*)0)->field)
#define countof(x) (sizeof(x) / sizeof((x)[0]))

/////////////////////////////////////////////////////////////////////////////////////////////
// 因为在vs2005中直接引入mr_helper.h会有报错，为了方便省事，直接把结构体拿过来了，把所有报错的地方替换成相应大小的数据类型，指针换成void*就可以，用vim编辑器很快就能替换好
typedef struct _mr_c_function_st {
    uint8* start_of_ER_RW;  // RW段指针
    uint32 ER_RW_Length;    // RW长度
    int32 ext_type;         // ext启动类型，为1时表示ext启动
    void* mrc_extChunk;     // ext模块描述段，下面的结构体。
    int32 stack;            // stack shell 2008-2-28
} mr_c_function_st;
/////////////////////////////////////////////////////////////////////////////////////////////

typedef enum BridgeMapType {
    MAP_DATA,  // 数据字段
    MAP_FUNC   // 函数字段
} BridgeMapType;

typedef struct StructOffset {
    // mrp要求必需是字符数组，定义成字符串指针会导致字符串丢失
    char fieldName[50];
    uint32 pos;
    BridgeMapType type;
} StructOffset;

#define GET_POS(field, mapType) \
    { #field, offsetof(mr_c_function_st, field), mapType }

StructOffset offsets[] = {
    GET_POS(start_of_ER_RW, MAP_DATA),
    GET_POS(ER_RW_Length, MAP_DATA),
    GET_POS(ext_type, MAP_DATA),
    GET_POS(mrc_extChunk, MAP_DATA),
    GET_POS(stack, MAP_DATA),
};

int32 mrc_init(void) {
    char* filename = "cfunction_table_offsets.txt";
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
