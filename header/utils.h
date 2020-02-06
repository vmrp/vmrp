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

#include "rbtree.h"

#ifndef offsetof
#define offsetof(type, field) ((size_t) & ((type *)0)->field)
#endif
#ifndef countof
#define countof(x) (sizeof(x) / sizeof((x)[0]))
#endif

// 字节对齐
#define ALIGN(x, align) (((x) + ((align)-1)) & ~((align)-1))

char *memTypeStr(uc_mem_type type);
void dumpREG(uc_engine *uc);
void dumpMemStr(void *ptr, size_t len);
void runCode(uc_engine *uc, uint32_t startAddr, uint32_t stopAddr, bool isThumb);

typedef struct uIntMap {
    struct rb_node node;
    uint32_t key;
    void *data;
} uIntMap;

uIntMap *uIntMap_search(struct rb_root *root, uint32_t key);
int uIntMap_insert(struct rb_root *root, uIntMap *obj);
uIntMap *uIntMap_delete(struct rb_root *root, uint32_t key);
char *getStrFromUc(uc_engine *uc, uint32_t addr);

#endif
