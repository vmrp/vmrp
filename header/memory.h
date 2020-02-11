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

#define HEAP_ALIGNMENT 4

bool freeMem(size_t addr);
size_t allocMem(size_t num);
void initMemoryManager(size_t baseAddress, size_t len);

#endif
