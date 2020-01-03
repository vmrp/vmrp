#ifndef __VMRP_BRIDGE_H__
#define __VMRP_BRIDGE_H__

#include <ctype.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include "../windows/include/unicorn/unicorn.h"
#else
#include <unicorn/unicorn.h>
#endif

#include "mr_helper.h"
#include "utils.h"

typedef bool (*BridgeCB)(char *name, uc_engine *uc, uc_mem_type type,
                         uint64_t address, int size, int64_t value,
                         void *user_data);

typedef enum BridgeMapType {
    MAP_DATA,
    MAP_FUNC,
} BridgeMapType;

typedef struct BridgeMap {
    char *name;
    uint32_t pos;
    BridgeMapType type;
    BridgeCB fn;
} BridgeMap;

bool mr_table_bridge_exec(uc_engine *uc, uc_mem_type type, uint64_t address,
                          int size, int64_t value, void *user_data);
uc_err mr_table_bridge_init(uc_engine *uc, uint32_t address);

bool cfunction_table_bridge_exec(uc_engine *uc, uc_mem_type type,
                                 uint64_t address, int size, int64_t value,
                                 void *user_data);
uc_err cfunction_table_bridge_init(uc_engine *uc, uint32_t address);

#endif
