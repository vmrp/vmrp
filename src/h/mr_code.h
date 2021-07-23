
#ifndef mr_code_h
#define mr_code_h

#include "mr_lex.h"
#include "mr_object.h"
#include "mr_opcodes.h"
#include "mr_parser.h"


/*
** Marks the end of a patch list. It is an invalid value both as an absolute
** address, and as a list link (would link an element to itself).
*/
#define NO_JUMP (-1)


/*
** grep "ORDER OPR" if you change these enums
*/
typedef enum BinOpr {
  OPR_ADD, OPR_SUB, OPR_MULT, OPR_DIV, OPR_POW,
  OPR_CONCAT,
  OPR_NE, OPR_EQ,
  OPR_LT, OPR_LE, OPR_GT, OPR_GE,
  OPR_AND, OPR_OR,
#if 1
  OPR_BAND, OPR_BOR, OPR_BXOR,
#endif 
  OPR_NOBINOPR
} BinOpr;

#define binopistest(op)	((op) >= OPR_NE)

#if 0
typedef enum UnOpr { OPR_MINUS, OPR_NOT, OPR_NOUNOPR } UnOpr;
#else
typedef enum UnOpr { OPR_MINUS, OPR_NOT, OPR_BNOT, OPR_NOUNOPR } UnOpr;
#endif


#define getcode(fs,e)	((fs)->f->code[(e)->info])

#define mr_K_codeAsBx(fs,o,A,sBx)	mr_K_codeABx(fs,o,A,(sBx)+MAXARG_sBx)

int mr_K_code (FuncState *fs, Instruction i, int line);
int mr_K_codeABx (FuncState *fs, OpCode o, int A, unsigned int Bx);
int mr_K_codeABC (FuncState *fs, OpCode o, int A, int B, int C);
void mr_K_fixline (FuncState *fs, int line);
void mr_K_nil (FuncState *fs, int from, int n);
void mr_K_reserveregs (FuncState *fs, int n);
void mr_K_checkstack (FuncState *fs, int n);
int mr_K_stringK (FuncState *fs, TString *s);
int mr_K_numberK (FuncState *fs, mrp_Number r);
void mr_K_dischargevars (FuncState *fs, expdesc *e);
int mr_K_exp2anyreg (FuncState *fs, expdesc *e);
void mr_K_exp2nextreg (FuncState *fs, expdesc *e);
void mr_K_exp2val (FuncState *fs, expdesc *e);
int mr_K_exp2RK (FuncState *fs, expdesc *e);
void mr_K_self (FuncState *fs, expdesc *e, expdesc *key);
void mr_K_indexed (FuncState *fs, expdesc *t, expdesc *k);
void mr_K_goiftrue (FuncState *fs, expdesc *e);
void mr_K_goiffalse (FuncState *fs, expdesc *e);
void mr_K_storevar (FuncState *fs, expdesc *var, expdesc *e);
void mr_K_setcallreturns (FuncState *fs, expdesc *var, int nresults);
int mr_K_jump (FuncState *fs);
void mr_K_patchlist (FuncState *fs, int list, int target);
void mr_K_patchtohere (FuncState *fs, int list);
void mr_K_concat (FuncState *fs, int *l1, int l2);
int mr_K_getlabel (FuncState *fs);
void mr_K_prefix (FuncState *fs, UnOpr op, expdesc *v);
void mr_K_infix (FuncState *fs, BinOpr op, expdesc *v);
void mr_K_posfix (FuncState *fs, BinOpr op, expdesc *v1, expdesc *v2);


#endif
