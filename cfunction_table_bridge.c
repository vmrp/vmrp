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

#define BRIDGE_FUNC_MAP(field, mapType, func)                                \
    {                                                                        \
        .name = #field, .pos = MR_STRUCT_OFFSET_OF(mr_c_function_st, field), \
        .type = mapType, .fn = func                                          \
    }

static BridgeMap funcMap[] = {
    BRIDGE_FUNC_MAP(start_of_ER_RW, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(ER_RW_Length, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(ext_type, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(mrc_extChunk, MAP_DATA, NULL),
    BRIDGE_FUNC_MAP(stack, MAP_DATA, NULL),
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
    uint32_t addressTable[countof(funcMap)];
    for (int i = 0; i < countof(funcMap); i++) {
        addressTable[i] = startAddress + funcMap[i].pos;
    }
    endAddress = addressTable[countof(funcMap) - 1];

    printf(TAG "startAddress: 0x%X, endAddress: 0x%X\n", startAddress,
           endAddress);

    int size = ALIGN(sizeof(addressTable), 4096);
    uc_err err = uc_mem_map(uc, startAddress, size, UC_PROT_READ);
    if (err) {
        return err;
    }
    return uc_mem_write(uc, startAddress, addressTable, sizeof(addressTable));
}
