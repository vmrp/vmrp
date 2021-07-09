
#ifndef _MEM_H__
#define _MEM_H__

#include "type.h"

typedef struct {
    uint32 next;
    uint32 len;
} LG_mem_free_t;

extern uint32 LG_mem_min;
extern uint32 LG_mem_top;
extern LG_mem_free_t LG_mem_free;
extern char* LG_mem_base;
extern uint32 LG_mem_len;
extern char* Origin_LG_mem_base;
extern uint32 Origin_LG_mem_len;
extern char* LG_mem_end;
extern uint32 LG_mem_left;

int32 _mr_mem_init(void);
void* mr_malloc(uint32 len);
void mr_free(void* p, uint32 len);
void* mr_realloc(void* p, uint32 oldlen, uint32 len);

void* mr_mallocExt(uint32 len);
void* mr_mallocExt0(uint32 len);
void mr_freeExt(void* p);
void* mr_reallocExt(void* p, uint32 newLen);

#define MR_MALLOC mr_malloc
#define MR_FREE mr_free
#define MR_REALLOC mr_realloc

#endif
