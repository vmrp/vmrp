
#ifndef _MR_STORE_H_
#define _MR_STORE_H_

#include "mr.h"
typedef struct WriterInfo_t {
	char* buf;
	size_t buflen;
} WriterInfo;


typedef struct LoadInfo_t {
  const char *buf;
  size_t size;
} LoadInfo;



void mr_store_persist(mrp_State *L, mrp_Chunkwriter writer, void *ud);

void mr_store_unpersist(mrp_State *L, mrp_Chunkreader reader, void *ud);

int mr_store_open(mrp_State *L);

int mr_str_bufwriter (mrp_State *L, const void* p, size_t sz, void* ud);
const char *mr_str_bufreader(mrp_State *L, void *ud, size_t *sz);

#endif
