
#ifndef mr_parser_h
#define mr_parser_h

#include "mr_limits.h"
#include "mr_object.h"
#include "mr_table.h"
#include "mr_zio.h"


/*
** Expression descriptor
*/

typedef enum {
  VVOID,	/* no value */
  VNIL,
  VTRUE,
  VFALSE,
  VK,		/* info = index of constant in `k' */
  VLOCAL,	/* info = local register */
  VUPVAL,       /* info = index of upvalue in `upvalues' */
  VGLOBAL,	/* info = index of table; aux = index of global name in `k' */
  VINDEXED,	/* info = table register; aux = index register (or `k') */
  VJMP,		/* info = instruction pc */
  VRELOCABLE,	/* info = instruction pc */
  VNONRELOC,	/* info = result register */
  VCALL		/* info = result register */
} expkind;

typedef struct expdesc {
  expkind k;
  int info, aux;
  int t;  /* patch list of `exit when true' */
  int f;  /* patch list of `exit when false' */
} expdesc;


struct BlockCnt;  /* defined in lparser.c */


/* state needed to generate code for a given function */
typedef struct FuncState {
  Proto *f;  /* current function header */
  Table *h;  /* table to find (and reuse) elements in `k' */
  struct FuncState *prev;  /* enclosing function */
  struct LexState *ls;  /* lexical state */
  struct mrp_State *L;  /* copy of the Lua state */
  struct BlockCnt *bl;  /* chain of current blocks */
  int pc;  /* next position to code (equivalent to `ncode') */
  int lasttarget;   /* `pc' of last `jump target' */
  int jpc;  /* list of pending jumps to `pc' */
  int freereg;  /* first free register */
  int nk;  /* number of elements in `k' */
  int np;  /* number of elements in `p' */
  int nlocvars;  /* number of elements in `locvars' */
  int nactvar;  /* number of active local variables */
  expdesc upvalues[MAXUPVALUES];  /* upvalues */
  int actvar[MAXVARS];  /* declared-variable stack */
} FuncState;


Proto *mr_Y_parser (mrp_State *L, ZIO *z, Mbuffer *buff);


#endif
