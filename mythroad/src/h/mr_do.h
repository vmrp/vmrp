
#ifndef mr_do_h
#define mr_do_h


#include "mr_object.h"
#include "mr_state.h"
#include "mr_zio.h"


/*
** macro to control inclusion of some hard tests on stack reallocation
*/ 
#ifndef HARDSTACKTESTS
#define condhardstacktests(x)	{ /* empty */ }
#else
#define condhardstacktests(x)	x
#endif


#define mr_D_checkstack(L,n)	\
  if ((char *)L->stack_last - (char *)L->top <= (n)*(int)sizeof(TObject)) \
    mr_D_growstack(L, n); \
  else condhardstacktests(mr_D_reallocstack(L, L->stacksize));


#define incr_top(L) {mr_D_checkstack(L,1); L->top++;}

#define savestack(L,p)		((char *)(p) - (char *)L->stack)
#define restorestack(L,n)	((TObject *)((char *)L->stack + (n)))

#define saveci(L,p)		((char *)(p) - (char *)L->base_ci)
#define restoreci(L,n)		((CallInfo *)((char *)L->base_ci + (n)))


/* type of protected functions, to be ran by `runprotected' */
typedef void (*Pfunc) (mrp_State *L, void *ud);

void mr_D_resetprotection (mrp_State *L);
int mr_D_protectedparser (mrp_State *L, ZIO *z, int bin);
void mr_D_callhook (mrp_State *L, int event, int line);
StkId mr_D_precall (mrp_State *L, StkId func);
void mr_D_call (mrp_State *L, StkId func, int nResults);
int mr_D_pcall (mrp_State *L, Pfunc func, void *u,
                ptrdiff_t oldtop, ptrdiff_t ef);
void mr_D_poscall (mrp_State *L, int wanted, StkId firstResult);
void mr_D_reallocCI (mrp_State *L, int newsize);
void mr_D_reallocstack (mrp_State *L, int newsize);
void mr_D_growstack (mrp_State *L, int n);

void mr_D_throw (mrp_State *L, int errcode);
int mr_D_rawrunprotected (mrp_State *L, Pfunc f, void *ud);


#endif
