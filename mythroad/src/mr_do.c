
//#define ldo_c

#include "../include/mr.h"

#include "./h/mr_debug.h"
#include "./h/mr_do.h"
#include "./h/mr_func.h"
#include "./h/mr_gc.h"
#include "./h/mr_mem.h"
#include "./h/mr_object.h"
#include "./h/mr_opcodes.h"
#include "./h/mr_parser.h"
#include "./h/mr_state.h"
#include "./h/mr_string.h"
#include "./h/mr_table.h"
#include "./h/mr_tm.h"
#include "./h/mr_undump.h"
#include "./h/mr_vm.h"
#include "./h/mr_zio.h"



/*
** {======================================================
** Error-recovery functions (based on long jumps)
** =======================================================
*/


/* chain list of long jump buffers */
struct mrp_longjmp {
  struct mrp_longjmp *previous;
  jmp_buf b;
  volatile int status;  /* error code */
};


static void seterrorobj (mrp_State *L, int errcode, StkId oldtop) {
  switch (errcode) {
    case MRP_ERRMEM: {
      setsvalue2s(oldtop, mr_S_new(L, MEMERRMSG));
      break;
    }
    case MRP_ERRERR: {
      setsvalue2s(oldtop, mr_S_new(L, "error in error handling"));
      break;
    }
    case MRP_ERRSYNTAX:
    case MRP_ERRRUN: {
      setobjs2s(oldtop, L->top - 1);  /* error message on current top */
      break;
    }
  }
  L->top = oldtop + 1;
}


void mr_D_throw (mrp_State *L, int errcode) 
{
   if (L->errorJmp) {
      L->errorJmp->status = errcode;
      LONGJMP(L->errorJmp->b, 1);
   } else {
    G(L)->panic(L);
    //exit(EXIT_FAILURE);  //ouli brew
  }
}


int mr_D_rawrunprotected (mrp_State *L, Pfunc f, void *ud) {
  struct mrp_longjmp lj;
  lj.status = 0;
  lj.previous = L->errorJmp;  /* chain new error handler */
  L->errorJmp = &lj;
  
   if (SETJMP(lj.b) == 0)
   {
      (*f)(L, ud);
   }
  
    
  L->errorJmp = lj.previous;  /* restore old error handler */
  return lj.status;
}


static void restore_stack_limit (mrp_State *L) {
  L->stack_last = L->stack+L->stacksize-1;
  if (L->size_ci > MRP_MAXCALLS) {  /* there was an overflow? */
    int inuse = (L->ci - L->base_ci);
    if (inuse + 1 < MRP_MAXCALLS)  /* can `undo' overflow? */
      mr_D_reallocCI(L, MRP_MAXCALLS);
  }
}

/* }====================================================== */


static void correctstack (mrp_State *L, TObject *oldstack) {
  CallInfo *ci;
  GCObject *up;
  L->top = (L->top - oldstack) + L->stack;
  for (up = L->openupval; up != NULL; up = up->gch.next)
    gcotouv(up)->v = (gcotouv(up)->v - oldstack) + L->stack;
  for (ci = L->base_ci; ci <= L->ci; ci++) {
    ci->top = (ci->top - oldstack) + L->stack;
    ci->base = (ci->base - oldstack) + L->stack;
  }
  L->base = L->ci->base;
}


void mr_D_reallocstack (mrp_State *L, int newsize) {
  TObject *oldstack = L->stack;
  mr_M_reallocvector(L, L->stack, L->stacksize, newsize, TObject);
  L->stacksize = newsize;
  L->stack_last = L->stack+newsize-1-EXTRA_STACK;
  correctstack(L, oldstack);
}


void mr_D_reallocCI (mrp_State *L, int newsize) {
  CallInfo *oldci = L->base_ci;
  mr_M_reallocvector(L, L->base_ci, L->size_ci, newsize, CallInfo);
  L->size_ci = cast(unsigned short, newsize);
  L->ci = (L->ci - oldci) + L->base_ci;
  L->end_ci = L->base_ci + L->size_ci;
}


void mr_D_growstack (mrp_State *L, int n) {
  if (n <= L->stacksize)  /* double size is enough? */
    mr_D_reallocstack(L, 2*L->stacksize);
  else
    mr_D_reallocstack(L, L->stacksize + n + EXTRA_STACK);
}


static void mr_D_growCI (mrp_State *L) {
  if (L->size_ci > MRP_MAXCALLS)  /* overflow while handling overflow? */
    mr_D_throw(L, MRP_ERRERR);
  else {
    mr_D_reallocCI(L, 2*L->size_ci);
    if (L->size_ci > MRP_MAXCALLS)
      mr_G_runerror(L, "stack overflow");
  }
}


void mr_D_callhook (mrp_State *L, int event, int line) {
  mrp_Hook hook = L->hook;
  if (hook && L->allowhook) {
    ptrdiff_t top = savestack(L, L->top);
    ptrdiff_t ci_top = savestack(L, L->ci->top);
    mrp_Debug ar;
    ar.event = event;
    ar.currentline = line;
    if (event == MRP_HOOKTAILRET)
      ar.i_ci = 0;  /* tail call; no debug information about it */
    else
      ar.i_ci = L->ci - L->base_ci;
    mr_D_checkstack(L, MRP_MINSTACK);  /* ensure minimum stack size */
    L->ci->top = L->top + MRP_MINSTACK;
    L->allowhook = 0;  /* cannot call hooks inside a hook */
    mrp_unlock(L);
    (*hook)(L, &ar);
    mrp_lock(L);
    mrp_assert(!L->allowhook);
    L->allowhook = 1;
    L->ci->top = restorestack(L, ci_top);
    L->top = restorestack(L, top);
  }
}


static void adjust_varargs (mrp_State *L, int nfixargs, StkId base) {
  int i;
  Table *htab;
  TObject nname;
  int actual = L->top - base;  /* actual number of arguments */
  if (actual < nfixargs) {
    mr_D_checkstack(L, nfixargs - actual);
    for (; actual < nfixargs; ++actual)
      setnilvalue(L->top++);
  }
  actual -= nfixargs;  /* number of extra arguments */
  htab = mr_H_new(L, actual, 1);  /* create `arg' table */
  for (i=0; i<actual; i++)  /* put extra arguments into `arg' table */
    setobj2n(mr_H_setnum(L, htab, i+1), L->top - actual + i);
  /* store counter in field `n' */
  setsvalue(&nname, mr_S_newliteral(L, "n"));
  setnvalue(mr_H_set(L, htab, &nname), cast(mrp_Number, actual));
  L->top -= actual;  /* remove extra elements from the stack */
  sethvalue(L->top, htab);
  incr_top(L);
}


static StkId tryfuncTM (mrp_State *L, StkId func) {
  const TObject *tm = mr_T_gettmbyobj(L, func, TM_CALL);
  StkId p;
  ptrdiff_t funcr = savestack(L, func);
  if (!ttisfunction(tm))
    mr_G_typeerror(L, func, "call");
  /* Open a hole inside the stack at `func' */
  for (p = L->top; p > func; p--) setobjs2s(p, p-1);
  incr_top(L);
  func = restorestack(L, funcr);  /* previous call may change stack */
  setobj2s(func, tm);  /* tag method is the new function to be called */
  return func;
}


StkId mr_D_precall (mrp_State *L, StkId func) {
  LClosure *cl;
  ptrdiff_t funcr = savestack(L, func);
  if (!ttisfunction(func)) /* `func' is not a function? */
    func = tryfuncTM(L, func);  /* check the `function' tag method */
  if (L->ci + 1 == L->end_ci) mr_D_growCI(L);
  else condhardstacktests(mr_D_reallocCI(L, L->size_ci));
  cl = &clvalue(func)->l;
  if (!cl->isC) {  /* Lua function? prepare its call */
    CallInfo *ci;
    Proto *p = cl->p;
    if (p->is_vararg)  /* varargs? */
      adjust_varargs(L, p->numparams, func+1);
    mr_D_checkstack(L, p->maxstacksize);
    ci = ++L->ci;  /* now `enter' new function */
    L->base = L->ci->base = restorestack(L, funcr) + 1;
    ci->top = L->base + p->maxstacksize;
    ci->u.l.savedpc = p->code;  /* starting point */
    ci->u.l.tailcalls = 0;
    ci->state = CI_SAVEDPC;
    while (L->top < ci->top)
      setnilvalue(L->top++);
    L->top = ci->top;
    return NULL;
  }
  else {  /* if is a C function, call it */
    CallInfo *ci;
    int n;
    mr_D_checkstack(L, MRP_MINSTACK);  /* ensure minimum stack size */
    ci = ++L->ci;  /* now `enter' new function */
    L->base = L->ci->base = restorestack(L, funcr) + 1;
    ci->top = L->top + MRP_MINSTACK;
    ci->state = CI_C;  /* a C function */
    if (L->hookmask & MRP_MASKCALL)
      mr_D_callhook(L, MRP_HOOKCALL, -1);
    mrp_unlock(L);
#ifdef MRP_COMPATUPVALUES
    mrp_pushupvalues(L);
#endif
    n = (*clvalue(L->base - 1)->c.f)(L);  /* do the actual call */
    mrp_lock(L);
    return L->top - n;
  }
}


static StkId callrethooks (mrp_State *L, StkId firstResult) {
  ptrdiff_t fr = savestack(L, firstResult);  /* next call may change stack */
  mr_D_callhook(L, MRP_HOOKRET, -1);
  if (!(L->ci->state & CI_C)) {  /* Lua function? */
    while (L->ci->u.l.tailcalls--)  /* call hook for eventual tail calls */
      mr_D_callhook(L, MRP_HOOKTAILRET, -1);
  }
  return restorestack(L, fr);
}


void mr_D_poscall (mrp_State *L, int wanted, StkId firstResult) { 
  StkId res;
  if (L->hookmask & MRP_MASKRET)
    firstResult = callrethooks(L, firstResult);
  res = L->base - 1;  /* res == final position of 1st result */
  L->ci--;
  L->base = L->ci->base;  /* restore base */
  /* move results to correct place */
  while (wanted != 0 && firstResult < L->top) {
    setobjs2s(res++, firstResult++);
    wanted--;
  }
  while (wanted-- > 0)
    setnilvalue(res++);
  L->top = res;
}


/*
** Call a function (C or Lua). The function to be called is at *func.
** The arguments are on the stack, right after the function.
** When returns, all the results are on the stack, starting at the original
** function position.
*/ 
void mr_D_call (mrp_State *L, StkId func, int nResults) {
  StkId firstResult;
  mrp_assert(!(L->ci->state & CI_CALLING));
  if (++L->nCcalls >= MRP_MAXCCALLS) {
    if (L->nCcalls == MRP_MAXCCALLS)
      mr_G_runerror(L, "stack(C) overflow");
    else if (L->nCcalls >= (MRP_MAXCCALLS + (MRP_MAXCCALLS>>3)))
      mr_D_throw(L, MRP_ERRERR);  /* error while handing stack error */
  }
  firstResult = mr_D_precall(L, func);
  if (firstResult == NULL)  /* is a Lua function? */
    firstResult = mr_V_execute(L);  /* call it */
  mr_D_poscall(L, nResults, firstResult);
  L->nCcalls--;
  mr_C_checkGC(L);
}


static void resume (mrp_State *L, void *ud) {
  StkId firstResult;
  int nargs = *cast(int *, ud);
  CallInfo *ci = L->ci;
  if (ci == L->base_ci) {  /* no activation record? */
    mrp_assert(nargs < L->top - L->base);
    mr_D_precall(L, L->top - (nargs + 1));  /* start coroutine */
  }
  else {  /* inside a yield */
    mrp_assert(ci->state & CI_YIELD);
    if (ci->state & CI_C) {  /* `common' yield? */
      /* finish interrupted execution of `OP_CALL' */
      int nresults;
      mrp_assert((ci-1)->state & CI_SAVEDPC);
      mrp_assert(GET_OPCODE(*((ci-1)->u.l.savedpc - 1)) == OP_CALL ||
                 GET_OPCODE(*((ci-1)->u.l.savedpc - 1)) == OP_TAILCALL);
      nresults = GETARG_C(*((ci-1)->u.l.savedpc - 1)) - 1;
      mr_D_poscall(L, nresults, L->top - nargs);  /* complete it */
      if (nresults >= 0) L->top = L->ci->top;
    }
    else {  /* yielded inside a hook: just continue its execution */
      ci->state &= ~CI_YIELD;
    }
  }
  firstResult = mr_V_execute(L);
  if (firstResult != NULL)   /* return? */
    mr_D_poscall(L, MRP_MULTRET, firstResult);  /* finalize this coroutine */
}


static int resume_error (mrp_State *L, const char *msg) {
  L->top = L->ci->base;
  setsvalue2s(L->top, mr_S_new(L, msg));
  incr_top(L);
  mrp_unlock(L);
  return MRP_ERRRUN;
}


MRP_API int mrp_resume (mrp_State *L, int nargs) {
  int status;
  lu_byte old_allowhooks;
  mrp_lock(L);
  if (L->ci == L->base_ci) {
    if (nargs >= L->top - L->base)
      return resume_error(L, "cannot resume dead coroutine");
  }
  else if (!(L->ci->state & CI_YIELD))  /* not inside a yield? */
    return resume_error(L, "cannot resume non-suspended coroutine");
  old_allowhooks = L->allowhook;
  mrp_assert(L->errfunc == 0 && L->nCcalls == 0);
  status = mr_D_rawrunprotected(L, resume, &nargs);
  if (status != 0) {  /* error? */
    L->ci = L->base_ci;  /* go back to initial level */
    L->base = L->ci->base;
    L->nCcalls = 0;
    mr_F_close(L, L->base);  /* close eventual pending closures */
    seterrorobj(L, status, L->base);
    L->allowhook = old_allowhooks;
    restore_stack_limit(L);
  }
  mrp_unlock(L);
  return status;
}


MRP_API int mrp_yield (mrp_State *L, int nresults) {
  CallInfo *ci;
  mrp_lock(L);
  ci = L->ci;
  if (L->nCcalls > 0)
    mr_G_runerror(L, "yield err:2081"); //attempt to yield across metamethod/C-call boundary
  if (ci->state & CI_C) {  /* usual yield */
    if ((ci-1)->state & CI_C)
      mr_G_runerror(L, "yield err:2082"); //cannot yield a C function
    if (L->top - nresults > L->base) {  /* is there garbage in the stack? */
      int i;
      for (i=0; i<nresults; i++)  /* move down results */
        setobjs2s(L->base + i, L->top - nresults + i);
      L->top = L->base + nresults;
    }
  } /* else it's an yield inside a hook: nothing to do */
  ci->state |= CI_YIELD;
  mrp_unlock(L);
  return -1;
}


int mr_D_pcall (mrp_State *L, Pfunc func, void *u,
                ptrdiff_t old_top, ptrdiff_t ef) {
  int status;
  unsigned short oldnCcalls = L->nCcalls;
  ptrdiff_t old_ci = saveci(L, L->ci);
  lu_byte old_allowhooks = L->allowhook;
  ptrdiff_t old_errfunc = L->errfunc;
  L->errfunc = ef;
  
  status = mr_D_rawrunprotected(L, func, u);

  if (status != 0) {  /* an error occurred? */
    StkId oldtop = restorestack(L, old_top);
    mr_F_close(L, oldtop);  /* close eventual pending closures */
    seterrorobj(L, status, oldtop);
    L->nCcalls = oldnCcalls;
    L->ci = restoreci(L, old_ci);
    L->base = L->ci->base;
    L->allowhook = old_allowhooks;
    restore_stack_limit(L);
  }
  L->errfunc = old_errfunc;
  return status;
}



/*
** Execute a protected parser.
*/
struct SParser {  /* data to `f_parser' */
  ZIO *z;
  Mbuffer buff;  /* buffer to be used by the scanner */
  int bin;
};

static void f_parser (mrp_State *L, void *ud) {
  struct SParser *p;
  Proto *tf;
  Closure *cl;
  mr_C_checkGC(L);
  p = cast(struct SParser *, ud);

   LUADBGPRINTF("Before f_parser mr_Y_parser");
  tf = p->bin ? mr_U_undump(L, p->z, &p->buff) : mr_Y_parser(L, p->z, &p->buff);
  LUADBGPRINTF("After f_parser mr_Y_parser");


  cl = mr_F_newLclosure(L, 0, gt(L));
  cl->l.p = tf;
  setclvalue(L->top, cl);
  incr_top(L);
}


int mr_D_protectedparser (mrp_State *L, ZIO *z, int bin) {
  struct SParser p;
  int status;
  ptrdiff_t oldtopr = savestack(L, L->top);  /* save current top */
  p.z = z; p.bin = bin;
  mr_Z_initbuffer(L, &p.buff);
  status = mr_D_rawrunprotected(L, f_parser, &p);

   LUADBGPRINTF("After mr_D_protectedparser mr_D_rawrunprotected");

  mr_Z_freebuffer(L, &p.buff);

   LUADBGPRINTF("After mr_D_protectedparser mr_Z_freebuffer");

  if (status != 0) {  /* error? */
    StkId oldtop = restorestack(L, oldtopr);

   LUADBGPRINTF("mr_D_protectedparser mr_D_rawrunprotected error");

    seterrorobj(L, status, oldtop);
  }
  return status;
}


