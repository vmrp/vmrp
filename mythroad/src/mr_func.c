


//#define lfunc_c


#include "./h/mr_func.h"
#include "./h/mr_gc.h"
#include "./h/mr_mem.h"
#include "./h/mr_object.h"
#include "./h/mr_state.h"


#define sizeCclosure(n)	(cast(int, sizeof(CClosure)) + \
                         cast(int, sizeof(TObject)*((n)-1)))

#define sizeLclosure(n)	(cast(int, sizeof(LClosure)) + \
                         cast(int, sizeof(TObject *)*((n)-1)))



Closure *mr_F_newCclosure (mrp_State *L, int nelems) {
  Closure *c = cast(Closure *, mr_M_malloc(L, sizeCclosure(nelems)));
  mr_C_link(L, valtogco(c), MRP_TFUNCTION);
  c->c.isC = 1;
  c->c.nupvalues = cast(lu_byte, nelems);
  return c;
}


Closure *mr_F_newLclosure (mrp_State *L, int nelems, TObject *e) {
  Closure *c = cast(Closure *, mr_M_malloc(L, sizeLclosure(nelems)));
  mr_C_link(L, valtogco(c), MRP_TFUNCTION);
  c->l.isC = 0;
  c->l.g = *e;
  c->l.nupvalues = cast(lu_byte, nelems);
  return c;
}


UpVal *mr_F_findupval (mrp_State *L, StkId level) {
  GCObject **pp = &L->openupval;
  UpVal *p;
  UpVal *v;
  while ((p = ngcotouv(*pp)) != NULL && p->v >= level) {
    if (p->v == level) return p;
    pp = &p->next;
  }
  v = mr_M_new(L, UpVal);  /* not found: create a new one */
  v->tt = MRP_TUPVAL;
  v->marked = 1;  /* open upvalues should not be collected */
  v->v = level;  /* current value lives in the stack */
  v->next = *pp;  /* chain it in the proper position */
  *pp = valtogco(v);
  return v;
}


void mr_F_close (mrp_State *L, StkId level) {
  UpVal *p;
  while ((p = ngcotouv(L->openupval)) != NULL && p->v >= level) {
    setobj(&p->value, p->v);  /* save current value (write barrier) */
    p->v = &p->value;  /* now current value lives here */
    L->openupval = p->next;  /* remove from `open' list */
    mr_C_link(L, valtogco(p), MRP_TUPVAL);
  }
}


Proto *mr_F_newproto (mrp_State *L) {
  Proto *f = mr_M_new(L, Proto);
  mr_C_link(L, valtogco(f), MRP_TPROTO);
  f->k = NULL;
  f->sizek = 0;
  f->p = NULL;
  f->sizep = 0;
  f->code = NULL;
  f->sizecode = 0;
  f->sizelineinfo = 0;
  f->sizeupvalues = 0;
  f->nups = 0;
  f->upvalues = NULL;
  f->numparams = 0;
  f->is_vararg = 0;
  f->maxstacksize = 0;
  f->lineinfo = NULL;
  f->sizelocvars = 0;
  f->locvars = NULL;
  f->lineDefined = 0;
  f->source = NULL;
  return f;
}


void mr_F_freeproto (mrp_State *L, Proto *f) {
  mr_M_freearray(L, f->code, f->sizecode, Instruction);
  mr_M_freearray(L, f->p, f->sizep, Proto *);
  mr_M_freearray(L, f->k, f->sizek, TObject);
  mr_M_freearray(L, f->lineinfo, f->sizelineinfo, int);
  mr_M_freearray(L, f->locvars, f->sizelocvars, struct LocVar);
  mr_M_freearray(L, f->upvalues, f->sizeupvalues, TString *);
  mr_M_freelem(L, f);
}


void mr_F_freeclosure (mrp_State *L, Closure *c) {
  int size = (c->c.isC) ? sizeCclosure(c->c.nupvalues) :
                          sizeLclosure(c->l.nupvalues);
  mr_M_free(L, c, size);
}


/*
** Look for n-th local variable at line `line' in function `func'.
** Returns NULL if not found.
*/
const char *mr_F_getlocalname (const Proto *f, int local_number, int pc) {
  int i;
  for (i = 0; i<f->sizelocvars && f->locvars[i].startpc <= pc; i++) {
    if (pc < f->locvars[i].endpc) {  /* is variable active? */
      local_number--;
      if (local_number == 0)
        return getstr(f->locvars[i].varname);
    }
  }
  return NULL;  /* not found */
}

