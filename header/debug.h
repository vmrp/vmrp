#ifndef __VMRP_DEBUG_H__
#define __VMRP_DEBUG_H__

#include <ctype.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "utils.h"

void hook_code_debug(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
#endif
