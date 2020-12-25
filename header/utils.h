#ifndef __VMRP_UTILS_H__
#define __VMRP_UTILS_H__

#include <ctype.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "types.h"

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
// #ifdef _WIN64
// #include "../windows/unicorn-1.0.1-win64/include/unicorn/unicorn.h"
// #else
#include "../windows/unicorn-1.0.2-win32/include/unicorn/unicorn.h"
// #endif
#endif

#ifndef EM_PORT_API
#if defined(__EMSCRIPTEN__)
#include <emscripten.h>
#define EM_PORT_API(rettype) rettype EMSCRIPTEN_KEEPALIVE
#include "../wasm/unicorn/unicorn.h"
#else
#define EM_PORT_API(rettype) rettype
#endif
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

#ifdef __x86_64__
#define PRId "I64d"
#define PRIX "I64X"
#elif __i386__
#define PRId "d"
#define PRIX "X"
#endif

// 字节对齐
#define ALIGN(x, align) (((x) + ((align)-1)) & ~((align)-1))

#define MAKERGB565(r, g, b) (uint16_t)(((uint32_t)(r >> 3) << 11) | ((uint32_t)(g >> 2) << 5) | ((uint32_t)(b >> 3)))
#define PIXEL565R(v) ((((uint32_t)v >> 11) << 3) & 0xff)
#define PIXEL565G(v) ((((uint32_t)v >> 5) << 2) & 0xff)
#define PIXEL565B(v) (((uint32_t)v << 3) & 0xff)

void cpsrToStr(uint32_t v, char *out);
char *memTypeStr(uc_mem_type type);
void dumpREG(uc_engine *uc);
void dumpMemStr(void *ptr, size_t len);
void runCode(uc_engine *uc, uint32_t startAddr, uint32_t stopAddr, bool isThumb);
char *getSplitStr(char *str, char split, int n);

typedef struct uIntMap {
    struct rb_node node;
    uint32_t key;
    void *data;
} uIntMap;

uIntMap *uIntMap_search(struct rb_root *root, uint32_t key);
int uIntMap_insert(struct rb_root *root, uIntMap *obj);
uIntMap *uIntMap_delete(struct rb_root *root, uint32_t key);

size_t copyToMrp(char *str);
void printScreen(char *filename, uint16_t *buf);

int64_t get_uptime_ms(void);
int64_t get_time_ms(void);
int32_t getDatetime(mr_datetime *datetime);

#endif
