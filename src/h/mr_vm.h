
#ifndef mr_vm_h
#define mr_vm_h


#include "mr_do.h"
#include "mr_object.h"
#include "mr_tm.h"


#define tostring(L,o) ((ttype(o) == MRP_TSTRING) || (mr_V_tostring(L, o)))

#define tonumber(o,n)	(ttype(o) == MRP_TNUMBER || \
                         (((o) = mr_V_tonumber(o,n)) != NULL))

#define equalobj(L,o1,o2) \
	(ttype(o1) == ttype(o2) && mr_V_equalval(L, o1, o2))


int mr_V_lessthan (mrp_State *L, const TObject *l, const TObject *r);
int mr_V_equalval (mrp_State *L, const TObject *t1, const TObject *t2);
const TObject *mr_V_tonumber (const TObject *obj, TObject *n);
int mr_V_tostring (mrp_State *L, StkId obj);
const TObject *mr_V_gettable (mrp_State *L, const TObject *t, TObject *key,
                              int loop);
void mr_V_settable (mrp_State *L, const TObject *t, TObject *key, StkId val);
StkId mr_V_execute (mrp_State *L);
void mr_V_concat (mrp_State *L, int total, int last);

#endif
