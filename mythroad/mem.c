#include "./include/mem.h"

#include "./include/fixR9.h"
#include "./include/mythroad.h"
/*
Mythroad的内存分配算法为：First fit。
算法实现：
1)   基于一个双向链表或者循环链表来保存所有的free memory；
2)     mrc_free时先定位其在空闲内存链表中的插入位置，再检查该内存块及其previous、behind空间是否连续，是则合并，反之在空闲内存链表中插入新free块。
算法优点：分配效率较高，一定程度上避免内存块连续分割后形成零碎且无法使用的内存碎片。
算法缺点：当找到的block比请求的大的话,就分割这个block将剩余的插入到free list中.这样会使得前面的block越来越小,进而大块的内存申请失败。
*/

LG_mem_free_t LG_mem_free;  // 可用块的头节点
uint32 LG_mem_min;          // 从未分配过的长度
uint32 LG_mem_top;          // 动态申请到达的最高内存值
char* LG_mem_base;          // 可用内存的基地址
uint32 LG_mem_len;          // 可用内存的长度
char* Origin_LG_mem_base;   // 原始获取到的内存的基地址
uint32 Origin_LG_mem_len;   // 原始获取到的内存长度
char* LG_mem_end;           // 可用内存的结束地址
uint32 LG_mem_left;         // 剩余内存

// 因为可用块链表的数据结构LG_mem_free_t占用8字节，因此要求申请的内存必需8字节对齐这样在释放之后才能将空间利用起来保存节点数据
#define realLGmemSize(x) (((x) + 7) & (~7))
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
    LG_mem_min = LG_mem_len;
    LG_mem_top = 0;
    return MR_SUCCESS;
}

void printMemoryInfo() {
    mr_printf(".......head.next:%d, head.len:%d", LG_mem_free.next, LG_mem_free.len);
    mr_printf(".......total:%d, min:%d, free:%d, top:%d", LG_mem_len, LG_mem_min, LG_mem_left, LG_mem_top);
    mr_printf(".......base:%p, end:%p", LG_mem_base, LG_mem_end);
    mr_printf(".......obase:%p, olen:%d", Origin_LG_mem_base, Origin_LG_mem_len);
}

void* mr_malloc(uint32 len) {
    LG_mem_free_t *previous, *nextfree;
    len = (uint32)realLGmemSize(len);
    if (len >= LG_mem_left) {
        MRDBGPRINTF("no memory, want:%d left:%d", len, LG_mem_left);
        return NULL;
    }
    if (!len) {
        MRDBGPRINTF("mr_malloc invalid memory request");
        return NULL;
    }
    if (LG_mem_base + LG_mem_free.next > LG_mem_end) {
        MRDBGPRINTF("mr_malloc corrupted memory");
        return NULL;
    }
    previous = &LG_mem_free;
    nextfree = (LG_mem_free_t*)(LG_mem_base + previous->next);
    while ((char*)nextfree < LG_mem_end) {
        if (nextfree->len == len) {
            previous->next = nextfree->next;
            goto end;
        }
        if (nextfree->len > len) {
            LG_mem_free_t* l = (LG_mem_free_t*)((char*)nextfree + len);
            l->next = nextfree->next;
            l->len = (uint32)(nextfree->len - len);
            previous->next += len;
            goto end;
        }
        previous = nextfree;
        nextfree = (LG_mem_free_t*)(LG_mem_base + nextfree->next);
    }
    MRDBGPRINTF("no memory2, want:%d left:%d", len, LG_mem_left);
    return NULL;
end:
    LG_mem_left -= len;
    if (LG_mem_left < LG_mem_min)
        LG_mem_min = LG_mem_left;
    if (LG_mem_top < previous->next)
        LG_mem_top = previous->next;
    return (void*)nextfree;
}

void mr_free(void* p, uint32 len) {
    LG_mem_free_t *free, *n;
    len = (uint32)realLGmemSize(len);
    if (!len || !p || (char*)p < LG_mem_base || (char*)p >= LG_mem_end || (char*)p + len > LG_mem_end || (char*)p + len <= LG_mem_base) {
        MRDBGPRINTF("mr_free invalid");
        MRDBGPRINTF("p=%d,l=%d,base=%d,LG_mem_end=%d", (int32)p, len, (int32)LG_mem_base, (int32)LG_mem_end);
        return;
    }
    free = &LG_mem_free;
    n = (LG_mem_free_t*)(LG_mem_base + free->next);
    while (((char*)n < LG_mem_end) && ((void*)n < p)) {
        free = n;
        n = (LG_mem_free_t*)(LG_mem_base + n->next);
    }
    if (p == (void*)free || p == (void*)n) {
        MRDBGPRINTF("mr_free:already free");
        return;
    }
    if ((free != &LG_mem_free) && ((char*)free + free->len == p)) {  // 如果头节点发生了移动，并且新的头块与当前释放的块是连续的
        free->len += len;
    } else {  // 插入当前块
        free->next = (uint32)((char*)p - LG_mem_base);
        free = (LG_mem_free_t*)p;
        free->next = (uint32)((char*)n - LG_mem_base);
        free->len = len;
    }
    if (((char*)n < LG_mem_end) && ((char*)p + len == (char*)n)) {  // 合并相邻的块
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
        p++;
        return (void*)p;
    }
    return NULL;
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
        uint32* t = (uint32*)p;
        t--;
        mr_free(t, (*t) + sizeof(uint32));
    }
}

void* mr_reallocExt(void* p, uint32 newLen) {
    if (p == NULL) {
        return mr_mallocExt(newLen);
    } else if (newLen == 0) {
        mr_freeExt(p);
        return NULL;
    } else {
        uint32 oldlen = *((uint32*)p - 1);
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
