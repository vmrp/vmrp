
#ifndef mr_gc_h
#define mr_gc_h


#include "mr_object.h"


#define mr_C_checkGC(L) { mrp_assert(!(L->ci->state & CI_CALLING)); \
	if (G(L)->nblocks >= G(L)->GCthreshold) mr_C_collectgarbage(L); }


size_t mr_C_separateudata (mrp_State *L);
void mr_C_callGCTM (mrp_State *L);
void mr_C_sweep (mrp_State *L, int all);
void mr_C_collectgarbage (mrp_State *L);
void mr_C_link (mrp_State *L, GCObject *o, lu_byte tt);


#endif
