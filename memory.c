#include "./header/vmrp.h"
#include "./header/memory.h"
#include "./header/utils.h"

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#endif
#include "header/types.h"

typedef struct {
    uint32 next;
    uint32 len;
} LG_mem_free_t;

uint32 LG_mem_min;  // 从未分配过的长度？
uint32 LG_mem_top;  // 动态申请到达的最高内存值
LG_mem_free_t LG_mem_free;
char *LG_mem_base;
uint32 LG_mem_len;
char *Origin_LG_mem_base;
uint32 Origin_LG_mem_len;
char *LG_mem_end;
uint32 LG_mem_left;  // 剩余内存

#define realLGmemSize(x) (((x) + 7) & (0xfffffff8))

void initMemoryManager(uint32_t baseAddress, uint32_t len) {
    LOG("initMemoryManager: baseAddress:0x%X len: 0x%X\n", baseAddress, len);
    Origin_LG_mem_base = getMrpMemPtr(baseAddress);
    Origin_LG_mem_len = len;

    LG_mem_base = (char *)((uint32)(Origin_LG_mem_base + 3) & (~3));
    LG_mem_len = (Origin_LG_mem_len - (LG_mem_base - Origin_LG_mem_base)) & (~3);
    LG_mem_end = LG_mem_base + LG_mem_len;
    LG_mem_free.next = 0;
    LG_mem_free.len = 0;
    ((LG_mem_free_t *)LG_mem_base)->next = LG_mem_len;
    ((LG_mem_free_t *)LG_mem_base)->len = LG_mem_len;
    LG_mem_left = LG_mem_len;
#ifdef MEM_DEBUG
    LG_mem_min = LG_mem_len;
    LG_mem_top = 0;
#endif
}

#ifdef __EMSCRIPTEN__
EMSCRIPTEN_KEEPALIVE
#endif
void printMemoryInfo() {
    LOG(".......total:%d, min:%d, free:%d, top:%d\n", LG_mem_len, LG_mem_min, LG_mem_left, LG_mem_top);
    LOG(".......base:%p, end:%p\n", LG_mem_base, LG_mem_end);
    LOG(".......obase:%p, olen:%d\n", Origin_LG_mem_base, Origin_LG_mem_len);
}

void *my_malloc(uint32 len) {
    LG_mem_free_t *previous, *nextfree, *l;
    void *ret;

    len = (uint32)realLGmemSize(len);
    if (len >= LG_mem_left) {
        LOG("my_malloc no memory\n");
        goto err;
    }
    if (!len) {
        LOG("my_malloc invalid memory request");
        goto err;
    }
    if (LG_mem_base + LG_mem_free.next > LG_mem_end) {
        LOG("my_malloc corrupted memory");
        goto err;
    }
    previous = &LG_mem_free;
    nextfree = (LG_mem_free_t *)(LG_mem_base + previous->next);
    while ((char *)nextfree < LG_mem_end) {
        if (nextfree->len == len) {
            previous->next = nextfree->next;
            LG_mem_left -= len;
#ifdef MEM_DEBUG
            if (LG_mem_left < LG_mem_min)
                LG_mem_min = LG_mem_left;
            if (LG_mem_top < previous->next)
                LG_mem_top = previous->next;
#endif
            ret = (void *)nextfree;
            goto end;
        }
        if (nextfree->len > len) {
            l = (LG_mem_free_t *)((char *)nextfree + len);
            l->next = nextfree->next;
            l->len = (uint32)(nextfree->len - len);
            previous->next += len;
            LG_mem_left -= len;
#ifdef MEM_DEBUG
            if (LG_mem_left < LG_mem_min)
                LG_mem_min = LG_mem_left;
            if (LG_mem_top < previous->next)
                LG_mem_top = previous->next;
#endif
            ret = (void *)nextfree;
            goto end;
        }
        previous = nextfree;
        nextfree = (LG_mem_free_t *)(LG_mem_base + nextfree->next);
    }
    LOG("my_malloc no memory\n");
err:
    return 0;
end:
    return ret;
}

void my_free(void *p, uint32 len) {
    LG_mem_free_t *free, *n;
    len = (uint32)realLGmemSize(len);
#ifdef MEM_DEBUG
    if (!len || !p || (char *)p < LG_mem_base || (char *)p >= LG_mem_end || (char *)p + len > LG_mem_end || (char *)p + len <= LG_mem_base) {
        LOG("my_free invalid\n");
        LOG("p=%d,l=%d,base=%d,LG_mem_end=%d\n", (int32)p, len, (int32)LG_mem_base, (int32)LG_mem_end);
        return;
    }
#endif
    free = &LG_mem_free;
    n = (LG_mem_free_t *)(LG_mem_base + free->next);
    while (((char *)n < LG_mem_end) && ((void *)n < p)) {
        free = n;
        n = (LG_mem_free_t *)(LG_mem_base + n->next);
    }
#ifdef MEM_DEBUG
    if (p == (void *)free || p == (void *)n) {
        LOG("my_free:already free\n");
        return;
    }
#endif
    if ((free != &LG_mem_free) && ((char *)free + free->len == p)) {
        free->len += len;
    } else {
        free->next = (uint32)((char *)p - LG_mem_base);
        free = (LG_mem_free_t *)p;
        free->next = (uint32)((char *)n - LG_mem_base);
        free->len = len;
    }
    if (((char *)n < LG_mem_end) && ((char *)p + len == (char *)n)) {
        free->next = n->next;
        free->len += n->len;
    }
    LG_mem_left += len;
}

void *my_realloc(void *p, uint32 oldlen, uint32 len) {
    unsigned long minsize = (oldlen > len) ? len : oldlen;
    void *newblock;
    if (p == NULL) {
        return my_malloc(len);
    }
    if (len == 0) {
        my_free(p, oldlen);
        return NULL;
    }
    newblock = my_malloc(len);
    if (newblock == NULL) {
        return newblock;
    }
    memmove(newblock, p, minsize);
    my_free(p, oldlen);
    return newblock;
}

#ifdef __EMSCRIPTEN__
EMSCRIPTEN_KEEPALIVE
#endif
void *my_mallocExt(uint32 len) {
    uint32 *p;
    if (len == 0) {
        return NULL;
    }
    p = my_malloc(len + sizeof(uint32));
    if (p) {
        *p = len;
        return (void *)(p + 1);
    }
    return p;
}

void *my_mallocExt0(uint32 len) {
    uint32 *p = my_mallocExt(len);
    if (p) {
        memset(p, 0, len);
        return p;
    }
    return p;
}

#ifdef __EMSCRIPTEN__
EMSCRIPTEN_KEEPALIVE
#endif
void my_freeExt(void *p) {
    if (p) {
        uint32 *t = (uint32 *)p - 1;
        my_free(t, *t + sizeof(uint32));
    }
}

void *my_reallocExt(void *p, uint32 newLen) {
    if (p == NULL) {
        return my_mallocExt(newLen);
    } else if (newLen == 0) {
        my_freeExt(p);
        return NULL;
    } else {
        uint32 oldlen = *((uint32 *)p - 1) + sizeof(uint32);
        uint32 minsize = (oldlen < newLen) ? oldlen : newLen;
        void *newblock = my_mallocExt(newLen);
        if (newblock == NULL) {
            return newblock;
        }
        memmove(newblock, p, minsize);
        my_freeExt(p);
        return newblock;
    }
}
