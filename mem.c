#include "./include/mem.h"

#include "./include/fixR9.h"
#include "./include/mythroad.h"

uint32 LG_mem_min;  // 从未分配过的长度？
uint32 LG_mem_top;  // 动态申请到达的最高内存值
LG_mem_free_t LG_mem_free;
char* LG_mem_base;
uint32 LG_mem_len;
char* Origin_LG_mem_base;
uint32 Origin_LG_mem_len;
char* LG_mem_end;
uint32 LG_mem_left;  // 剩余内存

#define realLGmemSize(x) (((x) + 7) & (0xfffffff8))
#define MRDBGPRINTF mr_printf

int32 _mr_mem_init(void) {
    if (mr_mem_get(&Origin_LG_mem_base, &Origin_LG_mem_len) != MR_SUCCESS) {
        MRDBGPRINTF("mr_mem_get failed!");
        return MR_FAILED;
    }
    MRDBGPRINTF("got Origin_LG_mem_len:%d", Origin_LG_mem_len);
    LG_mem_base = (char*)((uint32)(Origin_LG_mem_base + 3) & (~3));
    LG_mem_len = (Origin_LG_mem_len - (LG_mem_base - Origin_LG_mem_base)) & (~3);
    LG_mem_end = LG_mem_base + LG_mem_len;
    LG_mem_free.next = 0;
    LG_mem_free.len = 0;
    ((LG_mem_free_t*)LG_mem_base)->next = LG_mem_len;
    ((LG_mem_free_t*)LG_mem_base)->len = LG_mem_len;
    LG_mem_left = LG_mem_len;
#ifdef MYTHROAD_DEBUG
    LG_mem_min = LG_mem_len;
    LG_mem_top = 0;
#endif
    return MR_SUCCESS;
}

void printMemoryInfo() {
    mr_printf(".......total:%d, min:%d, free:%d, top:%d", LG_mem_len, LG_mem_min, LG_mem_left, LG_mem_top);
    mr_printf(".......base:%p, end:%p", LG_mem_base, LG_mem_end);
    mr_printf(".......obase:%p, olen:%d", Origin_LG_mem_base, Origin_LG_mem_len);
}

void* mr_malloc(uint32 len) {
    LG_mem_free_t *previous, *nextfree, *l;
    void* ret;

    len = (uint32)realLGmemSize(len);
    if (len >= LG_mem_left) {
        MRDBGPRINTF("mr_malloc no memory");
        goto err;
    }
    if (!len) {
        MRDBGPRINTF("mr_malloc invalid memory request");
        goto err;
    }
    if (LG_mem_base + LG_mem_free.next > LG_mem_end) {
        MRDBGPRINTF("mr_malloc corrupted memory");
        goto err;
    }
    previous = &LG_mem_free;
    nextfree = (LG_mem_free_t*)(LG_mem_base + previous->next);
    while ((char*)nextfree < LG_mem_end) {
        if (nextfree->len == len) {
            previous->next = nextfree->next;
            LG_mem_left -= len;
#ifdef MYTHROAD_DEBUG
            if (LG_mem_left < LG_mem_min)
                LG_mem_min = LG_mem_left;
            if (LG_mem_top < previous->next)
                LG_mem_top = previous->next;
#endif
            ret = (void*)nextfree;
            goto end;
        }
        if (nextfree->len > len) {
            l = (LG_mem_free_t*)((char*)nextfree + len);
            l->next = nextfree->next;
            l->len = (uint32)(nextfree->len - len);
            previous->next += len;
            LG_mem_left -= len;
#ifdef MYTHROAD_DEBUG
            if (LG_mem_left < LG_mem_min)
                LG_mem_min = LG_mem_left;
            if (LG_mem_top < previous->next)
                LG_mem_top = previous->next;
#endif
            ret = (void*)nextfree;
            goto end;
        }
        previous = nextfree;
        nextfree = (LG_mem_free_t*)(LG_mem_base + nextfree->next);
    }
    MRDBGPRINTF("mr_malloc no memory");
err:
    return 0;
end:
    // MRDBGPRINTF("R9:%X malloc(0x%X[%d]): 0x%X", getR9(), len, len, ret);
    // MRDBGPRINTF("malloc(0x%X[%d]): 0x%X", len, len, ret);
    return ret;
}

void mr_free(void* p, uint32 len) {
    LG_mem_free_t *free, *n;
    len = (uint32)realLGmemSize(len);
    // MRDBGPRINTF("R9:%X free(0x%X, %u)", getR9(), p, len);
    // MRDBGPRINTF("free(0x%X, %u)", p, len);
#ifdef MYTHROAD_DEBUG
    if (!len || !p || (char*)p < LG_mem_base || (char*)p >= LG_mem_end || (char*)p + len > LG_mem_end || (char*)p + len <= LG_mem_base) {
        MRDBGPRINTF("mr_free invalid");
        MRDBGPRINTF("p=%d,l=%d,base=%d,LG_mem_end=%d", (int32)p, len, (int32)LG_mem_base, (int32)LG_mem_end);
        return;
    }
#endif
    free = &LG_mem_free;
    n = (LG_mem_free_t*)(LG_mem_base + free->next);
    while (((char*)n < LG_mem_end) && ((void*)n < p)) {
        free = n;
        n = (LG_mem_free_t*)(LG_mem_base + n->next);
    }
#ifdef MYTHROAD_DEBUG
    if (p == (void*)free || p == (void*)n) {
        MRDBGPRINTF("mr_free:already free");
        return;
    }
#endif
    if ((free != &LG_mem_free) && ((char*)free + free->len == p)) {
        free->len += len;
    } else {
        free->next = (uint32)((char*)p - LG_mem_base);
        free = (LG_mem_free_t*)p;
        free->next = (uint32)((char*)n - LG_mem_base);
        free->len = len;
    }
    if (((char*)n < LG_mem_end) && ((char*)p + len == (char*)n)) {
        free->next = n->next;
        free->len += n->len;
    }
    LG_mem_left += len;
}

void* mr_realloc(void* p, uint32 oldlen, uint32 len) {
    unsigned long minsize = (oldlen > len) ? len : oldlen;
    void* newblock;
    if (p == NULL) {
        return mr_malloc(len);
    }
    if (len == 0) {
        mr_free(p, oldlen);
        return NULL;
    }
    newblock = mr_malloc(len);
    if (newblock == NULL) {
        return newblock;
    }
    MEMMOVE(newblock, p, minsize);
    mr_free(p, oldlen);
    return newblock;
}

void* mr_mallocExt(uint32 len) {
    uint32* p;
    if (len == 0) {
        return NULL;
    }
    p = mr_malloc(len + sizeof(uint32));
    if (p) {
        *p = len;
        return (void*)(p + 1);
    }
    return p;
}

void* mr_mallocExt0(uint32 len) {
    uint32* p = mr_mallocExt(len);
    if (p) {
        memset2(p, 0, len);
        return p;
    }
    return p;
}

void mr_freeExt(void* p) {
    if (p) {
        uint32* t = (uint32*)p - 1;
        mr_free(t, *t + sizeof(uint32));
    }
}

void* mr_reallocExt(void* p, uint32 newLen) {
    if (p == NULL) {
        return mr_mallocExt(newLen);
    } else if (newLen == 0) {
        mr_freeExt(p);
        return NULL;
    } else {
        uint32 oldlen = *((uint32*)p - 1) + sizeof(uint32);
        uint32 minsize = (oldlen < newLen) ? oldlen : newLen;
        void* newblock = mr_mallocExt(newLen);
        if (newblock == NULL) {
            return newblock;
        }
        MEMMOVE(newblock, p, minsize);
        mr_freeExt(p);
        return newblock;
    }
}
