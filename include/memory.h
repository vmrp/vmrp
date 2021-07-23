#ifndef __VMRP_MEMORY_H__
#define __VMRP_MEMORY_H__

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

void *my_mallocExt(uint32 len);
void my_freeExt(void *p);
void initMemoryManager(uint32_t baseAddress, uint32_t len);

#endif
