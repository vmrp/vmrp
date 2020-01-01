#ifndef __VMRP_UTILS_H__
#define __VMRP_UTILS_H__

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

char *memTypeStr(uc_mem_type type);
void dumpREG(uc_engine *uc);

#endif
