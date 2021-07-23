/*
** $Id: lfunc.h,v 1.21 2003/03/18 12:50:04 roberto Exp $
** Auxiliary functions to manipulate prototypes and closures
** See Copyright Notice in lua.h
*/

#ifndef mr_func_h
#define mr_func_h


#include "mr_object.h"


Proto *mr_F_newproto (mrp_State *L);
Closure *mr_F_newCclosure (mrp_State *L, int nelems);
Closure *mr_F_newLclosure (mrp_State *L, int nelems, TObject *e);
UpVal *mr_F_findupval (mrp_State *L, StkId level);
void mr_F_close (mrp_State *L, StkId level);
void mr_F_freeproto (mrp_State *L, Proto *f);
void mr_F_freeclosure (mrp_State *L, Closure *c);

const char *mr_F_getlocalname (const Proto *func, int local_number, int pc);


#endif
