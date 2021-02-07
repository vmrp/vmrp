
#ifndef _MEM_H__
#define _MEM_H__

#include "types.h"
#include <stdlib.h>





#define mr_malloc( len) malloc(len)
#define mr_free(p, len) free(p)
#define mr_realloc( p,  oldlen,  len) realloc(p, oldlen, len)
#define mr_mallocExt(len) malloc(len)

#define MR_MALLOC mr_malloc
#define MR_FREE mr_free
#define MR_REALLOC mr_realloc

#endif
