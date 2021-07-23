


#include "../include/mem.h"
#include "./h/mr_debug.h"
#include "./h/mr_do.h"
#include "./h/mr_mem.h"
#include "./h/mr_object.h"
#include "./h/mr_state.h"



/*
** definition for realloc function. It must assure that l_realloc(NULL,
** 0, x) allocates a new block (ANSI C assures that). (`os' is the old
** block size; some allocators may use that.)
*/
#ifndef l_realloc
//#define l_realloc(b,os,s)	REALLOC(b,s)//ouli brew
#define l_realloc(b,os,s)	MR_REALLOC(b,os,s)//ouli brew
#endif

/*
** definition for free function. (`os' is the old block size; some
** allocators may use that.)
*/
#ifndef l_free
//#define l_free(b,os)	FREE(b)//ouli brew
#define l_free(b,os)	MR_FREE(b, os)//ouli brew
#endif


#define MINSIZEARRAY	4


void *mr_M_growmr_aux (mrp_State *L, void *block, int *size, int size_elems,
                    int limit, const char *errormsg) {
  void *newblock;
  int newsize = (*size)*2;
  if (newsize < MINSIZEARRAY)
    newsize = MINSIZEARRAY;  /* minimum size */
  else if (*size >= limit/2) {  /* cannot double it? */
    if (*size < limit - MINSIZEARRAY)  /* try something smaller... */
      newsize = limit;  /* still have at least MINSIZEARRAY free places */
    else mr_G_runerror(L, errormsg);
  }
  newblock = mr_M_realloc(L, block,
                          cast(lu_mem, *size)*cast(lu_mem, size_elems),
                          cast(lu_mem, newsize)*cast(lu_mem, size_elems));
  *size = newsize;  /* update only when everything else is OK */
  return newblock;
  
}


/*
** generic allocation routine.
*/
void *mr_M_realloc (mrp_State *L, void *block, lu_mem oldsize, lu_mem size) {
  mrp_assert((oldsize == 0) == (block == NULL));
  if (size == 0) {
    if (block != NULL) {
      l_free(block, oldsize);
      block = NULL;
    }
    else return NULL;  /* avoid `nblocks' computations when oldsize==size==0 */
  }
  else if (size >= MAX_SIZET)
    mr_G_runerror(L, "mem err: 2003"); //memory allocation error: block too big
  else {
    block = l_realloc(block, oldsize, size);
    if (block == NULL) {
      if (L)
        mr_D_throw(L, MRP_ERRMEM);
      else return NULL;  /* error before creating state! */
    }
  }
  if (L) {
    mrp_assert(G(L) != NULL && G(L)->nblocks > 0);
    G(L)->nblocks -= oldsize;
    G(L)->nblocks += size;
  }
  return block;
}

