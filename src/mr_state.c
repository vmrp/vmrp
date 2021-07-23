

//#define lstate_c


#include "./h/mr_debug.h"
#include "./h/mr_do.h"
#include "./h/mr_func.h"
#include "./h/mr_gc.h"
#include "./h/mr_lex.h"
#include "./h/mr_mem.h"
#include "./h/mr_state.h"
#include "./h/mr_string.h"
#include "./h/mr_table.h"
#include "./h/mr_tm.h"


/*
** macro to allow the inclusion of user information in Lua state
*/
#ifndef MRP_USERSTATE
#define EXTRASPACE	0
#else
union UEXTRASPACE {L_Umaxalign a; MRP_USERSTATE b;};
#define EXTRASPACE (sizeof(union UEXTRASPACE))
#endif



/*
** you can change this function through the official API:
** call `mrp_setpanicf'
*/
static int default_panic (mrp_State *L) {
  UNUSED(L);
  return 0;
}


static mrp_State *mallocstate (mrp_State *L) {
  lu_byte *block = (lu_byte *)mr_M_malloc(L, sizeof(mrp_State) + EXTRASPACE);
  if (block == NULL) return NULL;
  else {
    block += EXTRASPACE;
    return cast(mrp_State *, block);
  }
}


static void freestate (mrp_State *L, mrp_State *L1) {
  mr_M_free(L, cast(lu_byte *, L1) - EXTRASPACE,
               sizeof(mrp_State) + EXTRASPACE);
}


static void stack_init (mrp_State *L1, mrp_State *L) {
  L1->stack = mr_M_newvector(L, BASIC_STACK_SIZE + EXTRA_STACK, TObject);
  L1->stacksize = BASIC_STACK_SIZE + EXTRA_STACK;
  L1->top = L1->stack;
  L1->stack_last = L1->stack+(L1->stacksize - EXTRA_STACK)-1;
  L1->base_ci = mr_M_newvector(L, BASIC_CI_SIZE, CallInfo);
  L1->ci = L1->base_ci;
  L1->ci->state = CI_C;  /*  not a Lua function */
  setnilvalue(L1->top++);  /* `function' entry for this `ci' */
  L1->base = L1->ci->base = L1->top;
  L1->ci->top = L1->top + MRP_MINSTACK;
  L1->size_ci = BASIC_CI_SIZE;
  L1->end_ci = L1->base_ci + L1->size_ci;
}


static void freestack (mrp_State *L, mrp_State *L1) {
  mr_M_freearray(L, L1->base_ci, L1->size_ci, CallInfo);
  mr_M_freearray(L, L1->stack, L1->stacksize, TObject);
}


/*
** open parts that may cause memory-allocation errors
*/
static void f_mrpopen (mrp_State *L, void *ud) {
  /* create a new global state */
  global_State *g = mr_M_new(NULL, global_State);
  UNUSED(ud);
  if (g == NULL) mr_D_throw(L, MRP_ERRMEM);
  L->l_G = g;
  g->mainthread = L;
  g->GCthreshold = 0;  /* mark it as unfinished state */
  g->strt.size = 0;
  g->strt.nuse = 0;
  g->strt.hash = NULL;
  setnilvalue(defaultmeta(L));
  setnilvalue(registry(L));
  mr_Z_initbuffer(L, &g->buff);
  g->panic = default_panic;
  g->rootgc = NULL;
  g->rootudata = NULL;
  g->tmudata = NULL;
  setnilvalue(gkey(g->dummynode));
  setnilvalue(gval(g->dummynode));
  g->dummynode->next = NULL;
  g->nblocks = sizeof(mrp_State) + sizeof(global_State);
  stack_init(L, L);  /* init stack */
  /* create default meta table with a dummy table, and then close the loop */
  defaultmeta(L)->tt = MRP_TTABLE;
  sethvalue(defaultmeta(L), mr_H_new(L, 0, 0));
  hvalue(defaultmeta(L))->metatable = hvalue(defaultmeta(L));
  sethvalue(gt(L), mr_H_new(L, 0, 4));  /* table of globals */
  sethvalue(registry(L), mr_H_new(L, 4, 4));  /* registry */
  mr_S_resize(L, MINSTRTABSIZE);  /* initial size of string table */
  mr_T_init(L);
  mr_X_init(L);
  mr_S_fix(mr_S_newliteral(L, MEMERRMSG));
  g->GCthreshold = 4*G(L)->nblocks;
}


static void preinit_state (mrp_State *L) {
  L->stack = NULL;
  L->stacksize = 0;
  L->errorJmp = NULL;
  L->hook = NULL;
  L->hookmask = L->hookinit = 0;
  L->basehookcount = 0;
  L->allowhook = 1;
  resethookcount(L);
  L->openupval = NULL;
  L->size_ci = 0;
  L->nCcalls = 0;
  L->base_ci = L->ci = NULL;
  L->errfunc = 0;
  setnilvalue(gt(L));
}


static void close_state (mrp_State *L) {
  mr_F_close(L, L->stack);  /* close all upvalues for this thread */
  if (G(L)) {  /* close global state */
    mr_C_sweep(L, 1);  /* collect all elements */
    mrp_assert(G(L)->rootgc == NULL);
    mrp_assert(G(L)->rootudata == NULL);
    mr_S_freeall(L);
    mr_Z_freebuffer(L, &G(L)->buff);
  }
  freestack(L, L);
  if (G(L)) {
    mrp_assert(G(L)->nblocks == sizeof(mrp_State) + sizeof(global_State));
    mr_M_freelem(NULL, G(L));
  }
  freestate(NULL, L);
}


mrp_State *mr_E_newthread (mrp_State *L) {
  mrp_State *L1 = mallocstate(L);
  mr_C_link(L, valtogco(L1), MRP_TTHREAD);
  preinit_state(L1);
  L1->l_G = L->l_G;
  stack_init(L1, L);  /* init stack */
  setobj2n(gt(L1), gt(L));  /* share table of globals */
  return L1;
}


void mr_E_freethread (mrp_State *L, mrp_State *L1) {
  mr_F_close(L1, L1->stack);  /* close all upvalues for this thread */
  mrp_assert(L1->openupval == NULL);
  freestack(L, L1);
  freestate(L, L1);
}


MRP_API mrp_State *mrp_open (void) {
  mrp_State *L = mallocstate(NULL);
  if (L) {  /* allocation OK? */
    L->tt = MRP_TTHREAD;
    L->marked = 0;
    L->next = L->gclist = NULL;
    preinit_state(L);
    L->l_G = NULL;
    if (mr_D_rawrunprotected(L, f_mrpopen, NULL) != 0) {
      /* memory allocation error: free partial state */
      close_state(L);
      L = NULL;
    }
  }
  mrp_userstateopen(L);
  return L;
}


static void callallgcTM (mrp_State *L, void *ud) {
  UNUSED(ud);
  mr_C_callGCTM(L);  /* call GC metamethods for all udata */
}


MRP_API void mrp_close (mrp_State *L) {
  mrp_lock(L);
  L = G(L)->mainthread;  /* only the main thread can be closed */
  mr_F_close(L, L->stack);  /* close all upvalues for this thread */
  mr_C_separateudata(L);  /* separate udata that have GC metamethods */
  L->errfunc = 0;  /* no error function during GC metamethods */
  do {  /* repeat until no more errors */
    L->ci = L->base_ci;
    L->base = L->top = L->ci->base;
    L->nCcalls = 0;
  } while (mr_D_rawrunprotected(L, callallgcTM, NULL) != 0);
  mrp_assert(G(L)->tmudata == NULL);
  close_state(L);
}

