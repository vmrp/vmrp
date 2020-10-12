#ifndef __VMRP_BRIDGE_H__
#define __VMRP_BRIDGE_H__

#include <ctype.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "utils.h"

typedef struct BridgeMap BridgeMap;

typedef void (*BridgeCB)(struct BridgeMap *o, uc_engine *uc);
typedef void (*BridgeInit)(struct BridgeMap *o, uc_engine *uc, uint32_t addr);

typedef enum BridgeMapType {
    MAP_DATA,
    MAP_FUNC,
} BridgeMapType;

typedef struct BridgeMap {
    char *name;
    uint32_t pos;
    uint32_t size;
    BridgeMapType type;
    BridgeInit initFn;
    BridgeCB fn;
    uint32_t extraData;
} BridgeMap;

#define BRIDGE_FUNC_MAP(offset, size, mapType, field, init, func) \
    { #field, offset, size, mapType, init, func, 0 }

#define BRIDGE_FUNC_MAP_FULL(offset, size, mapType, field, init, func, extraData) \
    { #field, offset, size, mapType, init, func, extraData }

void bridge(uc_engine *uc, uc_mem_type type, uint64_t address);
uc_err bridge_init(uc_engine *uc);

// 对应mrp中的几个入口函数
int32_t bridge_mr_init(uc_engine *uc);
int32_t bridge_mr_resumeApp(uc_engine *uc);
int32_t bridge_mr_pauseApp(uc_engine *uc);
int32_t bridge_mr_event(uc_engine *uc, int32_t code, int32_t param1, int32_t param2);

int32_t bridge_dsm_init(uc_engine *uc, uint32_t addr);
int32_t bridge_dsm_mr_start_dsm(uc_engine *uc, const char *entry);

#endif
