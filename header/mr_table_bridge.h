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

// ext文件0地址处的值
#define MR_TABLE_ADDRESS 0x4750524d


void mr_table_bridge_exec(uc_engine *uc, uint64_t address, uint32_t size,
                          void *user_data);

void mr_table_bridge_init();

#endif
