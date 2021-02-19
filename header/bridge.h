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
    BridgeMapType type;
    BridgeInit initFn;
    BridgeCB fn;
    uint32_t extraData;
} BridgeMap;
extern uint32_t cb_addr;
extern uint32_t cb_p0;
#define BRIDGE_FUNC_MAP(offset, mapType, field, init, func, extraData) \
    { #field, offset, mapType, init, func, extraData }

void bridge(uc_engine *uc, uc_mem_type type, uint64_t address);
uc_err bridge_init(uc_engine *uc);

// 对应mrp中的几个入口函数
int32_t bridge_mr_init(uc_engine *uc);
int32_t bridge_mr_resumeApp(uc_engine *uc);
int32_t bridge_mr_pauseApp(uc_engine *uc);
int32_t bridge_mr_event(uc_engine *uc, int32_t code, int32_t param1, int32_t param2);

int32_t bridge_dsm_init(uc_engine *uc, uint32_t addr);
int32_t bridge_dsm_mr_start_dsm(uc_engine *uc, char *filename, char *ext, char *entry);
int32_t bridge_dsm_mr_pauseApp(uc_engine *uc);
int32_t bridge_dsm_mr_resumeApp(uc_engine *uc);
int32_t bridge_dsm_mr_timer(uc_engine *uc);
int32_t bridge_dsm_mr_event(uc_engine *uc, int32_t code, int32_t p1, int32_t p2);

#endif
