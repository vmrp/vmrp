#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "./header/bridge.h"
#include "./header/mr_helper.h"
#include "./header/rbtree.h"
#include "./header/utils.h"

#define TAG "cfuntion_table_bridge: "

extern mr_c_function_st cfunction_table;

//////////////////////////////////////////////////////////////////////////////////////////

// 根据最后一个字段的位置得到
#define CFUNCTION_TABLE_MAP_LEN \
    (MR_STRUCT_INDEX_OF(mr_c_function_st, stack) + 1)

#define BRIDGE_FUNC_MAP(field, mapType, func)                                \
    {                                                                        \
        .name = #field, .pos = MR_STRUCT_OFFSET_OF(mr_c_function_st, field), \
        .type = mapType, .fn = func                                          \
    }

static BridgeMap funcMap[CFUNCTION_TABLE_MAP_LEN] = {
    BRIDGE_FUNC_MAP(start_of_ER_RW, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(ER_RW_Length, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(ext_type, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(mrc_extChunk, MAP_DATA, NULL),
    // BRIDGE_FUNC_MAP(stack, MAP_DATA, NULL),
};

static uint32_t startAddress, endAddress;

bool cfunction_table_bridge_exec(uc_engine *uc, uc_mem_type type,
                                 uint64_t address, int size, int64_t value,
                                 void *user_data) {
    if (address < startAddress || address > endAddress) {
        return false;
    }
    int i = (address - startAddress) / 4;
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

uc_err cfunction_table_bridge_init(uc_engine *uc, uint32_t address) {
    startAddress = address;

    // 地址表的作用是当ext尝试跳转到表中的地址执行时拦截下来
    uint32_t addressTable[CFUNCTION_TABLE_MAP_LEN];
    for (int i = 0; i < CFUNCTION_TABLE_MAP_LEN; i++) {
        addressTable[i] = startAddress + funcMap[i].pos;
    }
    endAddress = addressTable[CFUNCTION_TABLE_MAP_LEN - 1];

    printf(TAG "CFUNCTION_TABLE_MAP_LEN:%I64d\n", CFUNCTION_TABLE_MAP_LEN);

#undef MR_STRUCT_OFFSET_OF
#define MR_STRUCT_OFFSET_OF offsetof
    printf(TAG "CFUNCTION_TABLE:%I64d\n", MR_STRUCT_OFFSET_OF(mr_c_function_st, start_of_ER_RW));
    printf(TAG "CFUNCTION_TABLE:%I64d\n", MR_STRUCT_OFFSET_OF(mr_c_function_st, ER_RW_Length));
    printf(TAG "CFUNCTION_TABLE:%I64d\n", MR_STRUCT_OFFSET_OF(mr_c_function_st, ext_type));
    printf(TAG "CFUNCTION_TABLE:%I64d\n", MR_STRUCT_OFFSET_OF(mr_c_function_st, mrc_extChunk));
    printf(TAG "CFUNCTION_TABLE:%I64d\n", MR_STRUCT_OFFSET_OF(mr_c_function_st, stack));

    printf(TAG "startAddress: 0x%X, endAddress: 0x%X\n", startAddress,
           endAddress);

    int size = ALIGN(sizeof(addressTable), 4096);
    uc_err err = uc_mem_map(uc, startAddress, size, UC_PROT_READ);
    if (err) {
        return err;
    }
    return uc_mem_write(uc, startAddress, addressTable, sizeof(addressTable));
}
