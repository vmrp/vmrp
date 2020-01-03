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

#ifndef NULL
#include <stddef.h>
#endif

#ifndef offsetof
#define offsetof(type, field) ((size_t) & ((type *)0)->field)
#endif
#ifndef countof
#define countof(x) (sizeof(x) / sizeof((x)[0]))
#endif

// 字节对齐
#define ALIGN(x, align) (((x) + ((align)-1)) & ~((align)-1))

// 字段处在结构体的偏移量，因为mrp是在32位处理器上运行，所以指针是4字节，偏移量应该是以32位指针地址计算
#define MR_STRUCT_OFFSET_OF(type, member) \
    (offsetof(type, member) / ((sizeof(void *) / 4)))

// 字段处在结构体的什么位置
#define MR_STRUCT_INDEX_OF(type, member) (MR_STRUCT_OFFSET_OF(type, member) / 4)

char *memTypeStr(uc_mem_type type);
void dumpREG(uc_engine *uc);
void dumpMemStr(void *ptr, size_t len);

#endif
