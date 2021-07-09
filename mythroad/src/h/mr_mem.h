/*
** $Id: lmem.h,v 1.26 2002/05/01 20:40:42 roberto Exp $
** Interface to Memory Manager
** See Copyright Notice in lua.h
*/

#ifndef mr_mem_h
#define mr_mem_h



#include "mr_limits.h"

#define MEMERRMSG	"not enough memory"




void *mr_M_realloc (mrp_State *L, void *oldblock, lu_mem oldsize, lu_mem size);

void *mr_M_growmr_aux (mrp_State *L, void *block, int *size, int size_elem,
                    int limit, const char *errormsg);

#define mr_M_free(L, b, s)	mr_M_realloc(L, (b), (s), 0)
#define mr_M_freelem(L, b)	mr_M_realloc(L, (b), sizeof(*(b)), 0)
#define mr_M_freearray(L, b, n, t)	mr_M_realloc(L, (b), \
                                      cast(lu_mem, n)*cast(lu_mem, sizeof(t)), 0)

#define mr_M_malloc(L, t)	mr_M_realloc(L, NULL, 0, (t))
#define mr_M_new(L, t)          cast(t *, mr_M_malloc(L, sizeof(t)))
#define mr_M_newvector(L, n,t)  cast(t *, mr_M_malloc(L, \
                                         cast(lu_mem, n)*cast(lu_mem, sizeof(t))))

#define mr_M_growvector(L,v,nelems,size,t,limit,e) \
          if (((nelems)+1) > (size)) \
            ((v)=cast(t *, mr_M_growmr_aux(L,v,&(size),sizeof(t),limit,e)))

#define mr_M_reallocvector(L, v,oldn,n,t) \
   ((v)=cast(t *, mr_M_realloc(L, v,cast(lu_mem, oldn)*cast(lu_mem, sizeof(t)), \
                                    cast(lu_mem, n)*cast(lu_mem, sizeof(t)))))


#endif

