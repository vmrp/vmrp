#ifndef __VMRP_MR_TABLE_BRIDGE_H__
#define __VMRP_MR_TABLE_BRIDGE_H__

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

bool mr_table_bridge_exec(uc_engine *uc, uc_mem_type type, uint64_t address,
                          int size, int64_t value, void *user_data);
uc_err mr_table_bridge_init(uc_engine *uc, uint32_t mrTableAddress);

#endif
