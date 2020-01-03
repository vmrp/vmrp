#ifndef __VMRP_DEBUG_H__
#define __VMRP_DEBUG_H__

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

void hook_code_debug(uc_engine *uc, uint64_t address);

#endif
