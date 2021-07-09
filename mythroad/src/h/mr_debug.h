
#ifndef mr_debug_h
#define mr_debug_h


#include "mr_state.h"


#define pcRel(pc, p)	(cast(int, (pc) - (p)->code) - 1)

#define getline(f,pc)	(((f)->lineinfo) ? (f)->lineinfo[pc] : 0)

#define resethookcount(L)	(L->hookcount = L->basehookcount)


void mr_G_inithooks (mrp_State *L);
void mr_G_typeerror (mrp_State *L, const TObject *o, const char *opname);
void mr_G_concaterror (mrp_State *L, StkId p1, StkId p2);
void mr_G_aritherror (mrp_State *L, const TObject *p1, const TObject *p2);
int mr_G_ordererror (mrp_State *L, const TObject *p1, const TObject *p2);
void mr_G_runerror (mrp_State *L, const char *fmt, ...);
void mr_G_errormsg (mrp_State *L);
int mr_G_checkcode (const Proto *pt);


#endif
