


//#define lapi_c

#include "../include/mr.h"

#include "./h/mr_api.h"
#include "./h/mr_debug.h"
#include "./h/mr_do.h"
#include "./h/mr_func.h"
#include "./h/mr_gc.h"
#include "./h/mr_mem.h"
#include "./h/mr_object.h"
#include "./h/mr_state.h"
#include "./h/mr_string.h"
#include "./h/mr_table.h"
#include "./h/mr_tm.h"
#include "./h/mr_undump.h"
#include "./h/mr_vm.h"


/*
const char mrp_ident[] =
  "$Mr: " MR_VERSION " " MR_COPYRIGHT " $\n"
  "$Authors: " MR_AUTHORS " $\n";
*/


#ifndef api_check
#define api_check(L, o)		/*{ assert(o); }*/
#endif

#define api_checknelems(L, n)	api_check(L, (n) <= (L->top - L->base))





static TObject *negindex (mrp_State *L, int idx) {
  if (idx > MRP_REGISTRYINDEX) {
    api_check(L, idx != 0 && -idx <= L->top - L->base);
    return L->top+idx;
  }
  else switch (idx) {  /* pseudo-indices */
    case MRP_REGISTRYINDEX: return registry(L);
    case MRP_GLOBALSINDEX: return gt(L);
    default: {
      TObject *func = (L->base - 1);
      idx = MRP_GLOBALSINDEX - idx;
      mrp_assert(iscfunction(func));
      return (idx <= clvalue(func)->c.nupvalues)
                ? &clvalue(func)->c.upvalue[idx-1]
                : NULL;
    }
  }
}


static TObject *mr_A_index (mrp_State *L, int idx) {
  if (idx > 0) {
    api_check(L, idx <= L->top - L->base);
    return L->base + idx - 1;
  }
  else {
    TObject *o = negindex(L, idx);
    api_check(L, o != NULL);
    return o;
  }
}


static TObject *mr_A_indexAcceptable (mrp_State *L, int idx) {
  if (idx > 0) {
    TObject *o = L->base+(idx-1);
    api_check(L, idx <= L->stack_last - L->base);
    if (o >= L->top) return NULL;
    else return o;
  }
  else
    return negindex(L, idx);
}


void mr_A_pushobject (mrp_State *L, const TObject *o) {
  setobj2s(L->top, o);
  incr_top(L);
}


MRP_API int mrp_checkstack (mrp_State *L, int size) {
  int res;
  mrp_lock(L);
  if ((L->top - L->base + size) > MRP_MAXCSTACK)
    res = 0;  /* stack overflow */
  else {
    mr_D_checkstack(L, size);
    if (L->ci->top < L->top + size)
      L->ci->top = L->top + size;
    res = 1;
  }
  mrp_unlock(L);
  return res;
}


MRP_API void mrp_xmove (mrp_State *from, mrp_State *to, int n) {
  int i;
  mrp_lock(to);
  api_checknelems(from, n);
  from->top -= n;
  for (i = 0; i < n; i++) {
    setobj2s(to->top, from->top + i);
    api_incr_top(to);
  }
  mrp_unlock(to);
}


MRP_API mrp_CFunction mrp_atpanic (mrp_State *L, mrp_CFunction panicf) {
  mrp_CFunction old;
  mrp_lock(L);
  old = G(L)->panic;
  G(L)->panic = panicf;
  mrp_unlock(L);
  return old;
}


MRP_API mrp_State *mrp_newthread (mrp_State *L) {
  mrp_State *L1;
  mrp_lock(L);
  mr_C_checkGC(L);
  L1 = mr_E_newthread(L);
  setthvalue(L->top, L1);
  api_incr_top(L);
  mrp_unlock(L);
  mrp_userstateopen(L1);
  return L1;
}



/*
** basic stack manipulation
*/


MRP_API int mrp_gettop (mrp_State *L) {
  return (L->top - L->base);
}


MRP_API void mrp_settop (mrp_State *L, int idx) {
  mrp_lock(L);
  if (idx >= 0) {
    api_check(L, idx <= L->stack_last - L->base);
    while (L->top < L->base + idx)
      setnilvalue(L->top++);
    L->top = L->base + idx;
  }
  else {
    api_check(L, -(idx+1) <= (L->top - L->base));
    L->top += idx+1;  /* `subtract' index (index is negative) */
  }
  mrp_unlock(L);
}


MRP_API void mrp_remove (mrp_State *L, int idx) {
  StkId p;
  mrp_lock(L);
  p = mr_A_index(L, idx);
  while (++p < L->top) setobjs2s(p-1, p);
  L->top--;
  mrp_unlock(L);
}


MRP_API void mrp_insert (mrp_State *L, int idx) {
  StkId p;
  StkId q;
  mrp_lock(L);
  p = mr_A_index(L, idx);
  for (q = L->top; q>p; q--) setobjs2s(q, q-1);
  setobjs2s(p, L->top);
  mrp_unlock(L);
}


MRP_API void mrp_replace (mrp_State *L, int idx) {
  mrp_lock(L);
  api_checknelems(L, 1);
  setobj(mr_A_index(L, idx), L->top - 1);  /* write barrier */
  L->top--;
  mrp_unlock(L);
}


MRP_API void mrp_pushvalue (mrp_State *L, int idx) {
  mrp_lock(L);
  setobj2s(L->top, mr_A_index(L, idx));
  api_incr_top(L);
  mrp_unlock(L);
}



/*
** access functions (stack -> C)
*/


MRP_API int mrp_type (mrp_State *L, int idx) {
  StkId o = mr_A_indexAcceptable(L, idx);
  return (o == NULL) ? MRP_TNONE : ttype(o);
}


MRP_API const char *mrp_typename (mrp_State *L, int t) {
  UNUSED(L);
  return (t == MRP_TNONE) ? "no value" : mr_T_typenames[t];
}

MRP_API const char *mrp_shorttypename (mrp_State *L, int t) {
  UNUSED(L);
  return (t == MRP_TNONE) ? "no value" : mr_T_short_typenames[t];
}




MRP_API int mrp_iscfunction (mrp_State *L, int idx) {
  StkId o = mr_A_indexAcceptable(L, idx);
  return (o == NULL) ? 0 : iscfunction(o);
}


MRP_API int mrp_isnumber (mrp_State *L, int idx) {
  TObject n;
  const TObject *o = mr_A_indexAcceptable(L, idx);
  return (o != NULL && tonumber(o, &n));
}


MRP_API int mrp_isstring (mrp_State *L, int idx) {
  int t = mrp_type(L, idx);
  return (t == MRP_TSTRING || t == MRP_TNUMBER);
}


MRP_API int mrp_isuserdata (mrp_State *L, int idx) {
  const TObject *o = mr_A_indexAcceptable(L, idx);
  return (o != NULL && (ttisuserdata(o) || ttislightuserdata(o)));
}


MRP_API int mrp_rawequal (mrp_State *L, int index1, int index2) {
  StkId o1 = mr_A_indexAcceptable(L, index1);
  StkId o2 = mr_A_indexAcceptable(L, index2);
  return (o1 == NULL || o2 == NULL) ? 0  /* index out of range */
                                    : mr_O_rawequalObj(o1, o2);
}


MRP_API int mrp_equal (mrp_State *L, int index1, int index2) {
  StkId o1, o2;
  int i;
  mrp_lock(L);  /* may call tag method */
  o1 = mr_A_indexAcceptable(L, index1);
  o2 = mr_A_indexAcceptable(L, index2);
  i = (o1 == NULL || o2 == NULL) ? 0  /* index out of range */
                                 : equalobj(L, o1, o2);
  mrp_unlock(L);
  return i;
}


MRP_API int mrp_lessthan (mrp_State *L, int index1, int index2) {
  StkId o1, o2;
  int i;
  mrp_lock(L);  /* may call tag method */
  o1 = mr_A_indexAcceptable(L, index1);
  o2 = mr_A_indexAcceptable(L, index2);
  i = (o1 == NULL || o2 == NULL) ? 0  /* index out-of-range */
                                 : mr_V_lessthan(L, o1, o2);
  mrp_unlock(L);
  return i;
}



MRP_API mrp_Number mrp_tonumber (mrp_State *L, int idx) {
  TObject n;
  const TObject *o = mr_A_indexAcceptable(L, idx);
  if (o != NULL && tonumber(o, &n))
    return nvalue(o);
  else
    return 0;
}


MRP_API int mrp_toboolean (mrp_State *L, int idx) {
  const TObject *o = mr_A_indexAcceptable(L, idx);
  return (o != NULL) && !l_isfalse(o);
}


MRP_API const char *mrp_tostring (mrp_State *L, int idx) {
  StkId o = mr_A_indexAcceptable(L, idx);
  if (o == NULL)
    return NULL;
  else if (ttisstring(o))
    return svalue(o);
  else {
    const char *s;
    mrp_lock(L);  /* `mr_V_tostring' may create a new string */
    s = (mr_V_tostring(L, o) ? svalue(o) : NULL);
    mr_C_checkGC(L);
    mrp_unlock(L);
    return s;
  }
}

MRP_API const char *mrp_tostring_t (mrp_State *L, int idx) {
  StkId o = mr_A_indexAcceptable(L, idx);
  if (o == NULL)
    return NULL;
  else if (ttisstring(o))
    return svalue(o);
  else if (ttistable(o)){
    char* ret;
    mrp_pushnumber(L, 1);
    mrp_rawget(L, idx);
    ret = (char*)mrp_tonumber( L, -1);
    mrp_pop(L, 1);
    return ret;
   }
  else {
    const char *s;
    mrp_lock(L);  /* `mr_V_tostring' may create a new string */
    s = (mr_V_tostring(L, o) ? svalue(o) : NULL);
    mr_C_checkGC(L);
    mrp_unlock(L);
    return s;
  }
}


MRP_API size_t mrp_strlen (mrp_State *L, int idx) {
  StkId o = mr_A_indexAcceptable(L, idx);
  if (o == NULL)
    return 0;
  else if (ttisstring(o))
    return tsvalue(o)->tsv.len;
  else {
    size_t l;
    mrp_lock(L);  /* `mr_V_tostring' may create a new string */
    l = (mr_V_tostring(L, o) ? tsvalue(o)->tsv.len : 0);
    mrp_unlock(L);
    return l;
  }
}

MRP_API size_t mrp_strlen_t (mrp_State *L, int idx) {
  StkId o = mr_A_indexAcceptable(L, idx);
  if (o == NULL)
    return 0;
  else if (ttisstring(o))
    return tsvalue(o)->tsv.len;
  else if (ttistable(o)){
    size_t ret;
    mrp_pushnumber(L, 2);
    mrp_rawget(L, idx);
    ret = (size_t)mrp_tonumber( L, - 1);
    mrp_pop(L, 1);
    return ret;
   }
  else {
    size_t l;
    mrp_lock(L);  /* `mr_V_tostring' may create a new string */
    l = (mr_V_tostring(L, o) ? tsvalue(o)->tsv.len : 0);
    mrp_unlock(L);
    return l;
  }
}



MRP_API mrp_CFunction mrp_tocfunction (mrp_State *L, int idx) {
  StkId o = mr_A_indexAcceptable(L, idx);
  return (o == NULL || !iscfunction(o)) ? NULL : clvalue(o)->c.f;
}


MRP_API void *mrp_touserdata (mrp_State *L, int idx) {
  StkId o = mr_A_indexAcceptable(L, idx);
  if (o == NULL) return NULL;
  switch (ttype(o)) {
    case MRP_TUSERDATA: return (uvalue(o) + 1);
    case MRP_TLIGHTUSERDATA: return pvalue(o);
    default: return NULL;
  }
}


MRP_API mrp_State *mrp_tothread (mrp_State *L, int idx) {
  StkId o = mr_A_indexAcceptable(L, idx);
  return (o == NULL || !ttisthread(o)) ? NULL : thvalue(o);
}


MRP_API const void *mrp_topointer (mrp_State *L, int idx) {
  StkId o = mr_A_indexAcceptable(L, idx);
  if (o == NULL) return NULL;
  else {
    switch (ttype(o)) {
      case MRP_TTABLE: return hvalue(o);
      case MRP_TFUNCTION: return clvalue(o);
      case MRP_TTHREAD: return thvalue(o);
      case MRP_TUSERDATA:
      case MRP_TLIGHTUSERDATA:
        return mrp_touserdata(L, idx);
      default: return NULL;
    }
  }
}



/*
** push functions (C -> stack)
*/


MRP_API void mrp_pushnil (mrp_State *L) {
  mrp_lock(L);
  setnilvalue(L->top);
  api_incr_top(L);
  mrp_unlock(L);
}


MRP_API void mrp_pushnumber (mrp_State *L, mrp_Number n) {
  mrp_lock(L);
  setnvalue(L->top, n);
  api_incr_top(L);
  mrp_unlock(L);
}


MRP_API void mrp_pushlstring (mrp_State *L, const char *s, size_t len) {
  mrp_lock(L);
  mr_C_checkGC(L);
  setsvalue2s(L->top, mr_S_newlstr(L, s, len));
  api_incr_top(L);
  mrp_unlock(L);
}


MRP_API void mrp_pushstring (mrp_State *L, const char *s) {
  if (s == NULL)
    mrp_pushnil(L);
  else
    mrp_pushlstring(L, s, STRLEN(s));//ouli brew
}


MRP_API const char *mrp_pushvfstring (mrp_State *L, const char *fmt,
                                      va_list argp) {
  const char *ret;
  mrp_lock(L);
  mr_C_checkGC(L);
  ret = mr_O_pushvfstring(L, fmt, argp);
  mrp_unlock(L);
  return ret;
}


MRP_API const char *mrp_pushfstring (mrp_State *L, const char *fmt, ...) {
  const char *ret;
  va_list argp;
  mrp_lock(L);
  mr_C_checkGC(L);
  va_start(argp, fmt);
  ret = mr_O_pushvfstring(L, fmt, argp);
  va_end(argp);
  mrp_unlock(L);
  return ret;
}


MRP_API void mrp_pushcclosure (mrp_State *L, mrp_CFunction fn, int n) {
  Closure *cl;
  mrp_lock(L);
  mr_C_checkGC(L);
  api_checknelems(L, n);
  cl = mr_F_newCclosure(L, n);
  cl->c.f = fn;
  L->top -= n;
  while (n--)
    setobj2n(&cl->c.upvalue[n], L->top+n);
  setclvalue(L->top, cl);
  api_incr_top(L);
  mrp_unlock(L);
}


MRP_API void mrp_pushboolean (mrp_State *L, int b) {
  mrp_lock(L);
  setbvalue(L->top, (b != 0));  /* ensure that true is 1 */
  api_incr_top(L);
  mrp_unlock(L);
}


MRP_API void mrp_pushlightuserdata (mrp_State *L, void *p) {
  mrp_lock(L);
  setpvalue(L->top, p);
  api_incr_top(L);
  mrp_unlock(L);
}



/*
** get functions (Lua -> stack)
*/


MRP_API void mrp_gettable (mrp_State *L, int idx) {
  StkId t;
  mrp_lock(L);
  t = mr_A_index(L, idx);
  setobj2s(L->top - 1, mr_V_gettable(L, t, L->top - 1, 0));
  mrp_unlock(L);
}


MRP_API void mrp_rawget (mrp_State *L, int idx) {
  StkId t;
  mrp_lock(L);
  t = mr_A_index(L, idx);
  api_check(L, ttistable(t));
  setobj2s(L->top - 1, mr_H_get(hvalue(t), L->top - 1));
  mrp_unlock(L);
}


MRP_API void mrp_rawgeti (mrp_State *L, int idx, int n) {
  StkId o;
  mrp_lock(L);
  o = mr_A_index(L, idx);
  api_check(L, ttistable(o));
  setobj2s(L->top, mr_H_getnum(hvalue(o), n));
  api_incr_top(L);
  mrp_unlock(L);
}


MRP_API void mrp_newtable (mrp_State *L) {
  mrp_lock(L);
  mr_C_checkGC(L);
  sethvalue(L->top, mr_H_new(L, 0, 0));
  api_incr_top(L);
  mrp_unlock(L);
}


MRP_API int mrp_getmetatable (mrp_State *L, int objindex) {
  const TObject *obj;
  Table *mt = NULL;
  int res;
  mrp_lock(L);
  obj = mr_A_indexAcceptable(L, objindex);
  if (obj != NULL) {
    switch (ttype(obj)) {
      case MRP_TTABLE:
        mt = hvalue(obj)->metatable;
        break;
      case MRP_TUSERDATA:
        mt = uvalue(obj)->uv.metatable;
        break;
    }
  }
  if (mt == NULL || mt == hvalue(defaultmeta(L)))
    res = 0;
  else {
    sethvalue(L->top, mt);
    api_incr_top(L);
    res = 1;
  }
  mrp_unlock(L);
  return res;
}


MRP_API void mrp_getfenv (mrp_State *L, int idx) {
  StkId o;
  mrp_lock(L);
  o = mr_A_index(L, idx);
  setobj2s(L->top, isLfunction(o) ? &clvalue(o)->l.g : gt(L));
  api_incr_top(L);
  mrp_unlock(L);
}


/*
** set functions (stack -> Lua)
*/


MRP_API void mrp_settable (mrp_State *L, int idx) {
  StkId t;
  mrp_lock(L);
  api_checknelems(L, 2);
  t = mr_A_index(L, idx);
  mr_V_settable(L, t, L->top - 2, L->top - 1);
  L->top -= 2;  /* pop index and value */
  mrp_unlock(L);
}


MRP_API void mrp_rawset (mrp_State *L, int idx) {
  StkId t;
  mrp_lock(L);
  api_checknelems(L, 2);
  t = mr_A_index(L, idx);
  api_check(L, ttistable(t));
  setobj2t(mr_H_set(L, hvalue(t), L->top-2), L->top-1);  /* write barrier */
  L->top -= 2;
  mrp_unlock(L);
}


MRP_API void mrp_rawseti (mrp_State *L, int idx, int n) {
  StkId o;
  mrp_lock(L);
  api_checknelems(L, 1);
  o = mr_A_index(L, idx);
  api_check(L, ttistable(o));
  setobj2t(mr_H_setnum(L, hvalue(o), n), L->top-1);  /* write barrier */
  L->top--;
  mrp_unlock(L);
}


MRP_API int mrp_setmetatable (mrp_State *L, int objindex) {
  TObject *obj, *mt;
  int res = 1;
  mrp_lock(L);
  api_checknelems(L, 1);
  obj = mr_A_index(L, objindex);
  mt = (!ttisnil(L->top - 1)) ? L->top - 1 : defaultmeta(L);
  api_check(L, ttistable(mt));
  switch (ttype(obj)) {
    case MRP_TTABLE: {
      hvalue(obj)->metatable = hvalue(mt);  /* write barrier */
      break;
    }
    case MRP_TUSERDATA: {
      uvalue(obj)->uv.metatable = hvalue(mt);  /* write barrier */
      break;
    }
    default: {
      res = 0;  /* cannot set */
      break;
    }
  }
  L->top--;
  mrp_unlock(L);
  return res;
}


MRP_API int mrp_setfenv (mrp_State *L, int idx) {
  StkId o;
  int res = 0;
  mrp_lock(L);
  api_checknelems(L, 1);
  o = mr_A_index(L, idx);
  L->top--;
  api_check(L, ttistable(L->top));
  if (isLfunction(o)) {
    res = 1;
    clvalue(o)->l.g = *(L->top);
  }
  mrp_unlock(L);
  return res;
}


/*
** `load' and `call' functions (run Lua code)
*/

MRP_API void mrp_call (mrp_State *L, int nargs, int nresults) {
  StkId func;
  mrp_lock(L);
  api_checknelems(L, nargs+1);
  func = L->top - (nargs+1);
  mr_D_call(L, func, nresults);
  mrp_unlock(L);
}



/*
** Execute a protected call.
*/
struct CallS {  /* data to `f_call' */
  StkId func;
  int nresults;
};


static void f_call (mrp_State *L, void *ud) {
  struct CallS *c = cast(struct CallS *, ud);
  mr_D_call(L, c->func, c->nresults);
}



MRP_API int mrp_pcall (mrp_State *L, int nargs, int nresults, int errfunc) {
  struct CallS c;
  int status;
  ptrdiff_t func;
  mrp_lock(L);
  func = (errfunc == 0) ? 0 : savestack(L, mr_A_index(L, errfunc));
  c.func = L->top - (nargs+1);  /* function to be called */
  c.nresults = nresults;

  status = mr_D_pcall(L, f_call, &c, savestack(L, c.func), func);

  mrp_unlock(L);
  return status;
}


/*
** Execute a protected C call.
*/
struct CCallS {  /* data to `f_Ccall' */
  mrp_CFunction func;
  void *ud;
};


static void f_Ccall (mrp_State *L, void *ud) {
  struct CCallS *c = cast(struct CCallS *, ud);
  Closure *cl;
  cl = mr_F_newCclosure(L, 0);
  cl->c.f = c->func;
  setclvalue(L->top, cl);  /* push function */
  incr_top(L);
  setpvalue(L->top, c->ud);  /* push only argument */
  incr_top(L);
  mr_D_call(L, L->top - 2, 0);
}


MRP_API int mrp_cpcall (mrp_State *L, mrp_CFunction func, void *ud) {
  struct CCallS c;
  int status;
  mrp_lock(L);
  c.func = func;
  c.ud = ud;
  status = mr_D_pcall(L, f_Ccall, &c, savestack(L, L->top), 0);
  mrp_unlock(L);
  return status;
}


MRP_API int mrp_load (mrp_State *L, mrp_Chunkreader reader, void *data,
                      const char *chunkname) {
  ZIO z;
  int status;
  int c;
  mrp_lock(L);
  if (!chunkname) chunkname = "?";
  mr_Z_init(&z, reader, data, chunkname);
  c = mr_Z_lookahead(&z);
  status = mr_D_protectedparser(L, &z, (c == MRP_SIGNATURE[0]));
  mrp_unlock(L);
  return status;
}


MRP_API int mrp_dump (mrp_State *L, mrp_Chunkwriter writer, void *data) {
  int status;
  TObject *o;
  mrp_lock(L);
  api_checknelems(L, 1);
  o = L->top - 1;
  if (isLfunction(o) && clvalue(o)->l.nupvalues == 0) {
    mr_U_dump(L, clvalue(o)->l.p, writer, data);
    status = 1;
  }
  else
    status = 0;
  mrp_unlock(L);
  return status;
}


/*
** Garbage-collection functions
*/

/* GC values are expressed in Kbytes: #bytes/2^10 */
#define GCscalel(x)		((x)>>10)
#define GCscale(x)		(cast(int, GCscalel(x)))
#define GCunscale(x)		(cast(lu_mem, x)<<10)

MRP_API int mrp_getgcthreshold (mrp_State *L) {
  int threshold;
  mrp_lock(L);
  threshold = GCscale(G(L)->GCthreshold);
  mrp_unlock(L);
  return threshold;
}

MRP_API int mrp_getgccount (mrp_State *L) {
  int count;
  mrp_lock(L);
  count = GCscale(G(L)->nblocks);
  mrp_unlock(L);
  return count;
}

MRP_API void mrp_setgcthreshold (mrp_State *L, int newthreshold) {
  mrp_lock(L);
  if (cast(lu_mem, newthreshold) > GCscalel(MAX_LUMEM))
    G(L)->GCthreshold = MAX_LUMEM;
  else
    G(L)->GCthreshold = GCunscale(newthreshold);
  mr_C_checkGC(L);
  mrp_unlock(L);
}


/*
** miscellaneous functions
*/


MRP_API uint32 mrp_version (void) {
  return MR_VERSION;
}


MRP_API int mrp_error (mrp_State *L) {
  mrp_lock(L);
  api_checknelems(L, 1);
  mr_G_errormsg(L);
  mrp_unlock(L);
  return 0;  /* to avoid warnings */
}


MRP_API int mrp_next (mrp_State *L, int idx) {
  StkId t;
  int more;
  mrp_lock(L);
  t = mr_A_index(L, idx);
  api_check(L, ttistable(t));
  more = mr_H_next(L, hvalue(t), L->top - 1);
  if (more) {
    api_incr_top(L);
  }
  else  /* no more elements */
    L->top -= 1;  /* remove key */
  mrp_unlock(L);
  return more;
}


MRP_API void mrp_concat (mrp_State *L, int n) {
  mrp_lock(L);
  mr_C_checkGC(L);
  api_checknelems(L, n);
  if (n >= 2) {
    mr_V_concat(L, n, L->top - L->base - 1);
    L->top -= (n-1);
  }
  else if (n == 0) {  /* push empty string */
    setsvalue2s(L->top, mr_S_newlstr(L, NULL, 0));
    api_incr_top(L);
  }
  /* else n == 1; nothing to do */
  mrp_unlock(L);
}


MRP_API void *mrp_newuserdata (mrp_State *L, size_t size) {
  Udata *u;
  mrp_lock(L);
  mr_C_checkGC(L);
  u = mr_S_newudata(L, size);
  setuvalue(L->top, u);
  api_incr_top(L);
  mrp_unlock(L);
  return u + 1;
}


MRP_API int mrp_pushupvalues (mrp_State *L) {
  Closure *func;
  int n, i;
  mrp_lock(L);
  api_check(L, iscfunction(L->base - 1));
  func = clvalue(L->base - 1);
  n = func->c.nupvalues;
  mr_D_checkstack(L, n + MRP_MINSTACK);
  for (i=0; i<n; i++) {
    setobj2s(L->top, &func->c.upvalue[i]);
    L->top++;
  }
  mrp_unlock(L);
  return n;
}


static const char *mr_aux_upvalue (mrp_State *L, int funcindex, int n,
                                TObject **val) {
  Closure *f;
  StkId fi = mr_A_index(L, funcindex);
  if (!ttisfunction(fi)) return NULL;
  f = clvalue(fi);
  if (f->c.isC) {
    if (n > f->c.nupvalues) return NULL;
    *val = &f->c.upvalue[n-1];
    return "";
  }
  else {
    Proto *p = f->l.p;
    if (n > p->sizeupvalues) return NULL;
    *val = f->l.upvals[n-1]->v;
    return getstr(p->upvalues[n-1]);
  }
}


MRP_API const char *mrp_getupvalue (mrp_State *L, int funcindex, int n) {
  const char *name;
  TObject *val=NULL;
  mrp_lock(L);
  name = mr_aux_upvalue(L, funcindex, n, &val);
  if (name) {
    setobj2s(L->top, val);
    api_incr_top(L);
  }
  mrp_unlock(L);
  return name;
}


MRP_API const char *mrp_setupvalue (mrp_State *L, int funcindex, int n) {
  const char *name;
  TObject *val=NULL;
  mrp_lock(L);
  api_checknelems(L, 1);
  name = mr_aux_upvalue(L, funcindex, n, &val);
  if (name) {
    L->top--;
    setobj(val, L->top);  /* write barrier */
  }
  mrp_unlock(L);
  return name;
}

