/*
** $Id: lcode.c,v 1.117 2003/04/03 13:35:34 roberto Exp $
** Code generator for Lua
** See Copyright Notice in lua.h
*/


//#define lcode_c

#include "mr.h"

#include "mr_code.h"
#include "mr_debug.h"
#include "mr_do.h"
#include "mr_lex.h"
#include "mr_mem.h"
#include "mr_object.h"
#include "mr_opcodes.h"
#include "mr_parser.h"
#include "mr_table.h"




#define hasjumps(e)	((e)->t != (e)->f)


void mr_K_nil (FuncState *fs, int from, int n) {
  Instruction *previous;
  if (fs->pc > fs->lasttarget &&  /* no jumps to current position? */
      GET_OPCODE(*(previous = &fs->f->code[fs->pc-1])) == OP_LOADNIL) {
    int pfrom = GETARG_A(*previous);
    int pto = GETARG_B(*previous);
    if (pfrom <= from && from <= pto+1) {  /* can connect both? */
      if (from+n-1 > pto)
        SETARG_B(*previous, from+n-1);
      return;
    }
  }
  mr_K_codeABC(fs, OP_LOADNIL, from, from+n-1, 0);  /* else no optimization */
}


int mr_K_jump (FuncState *fs) {
  int jpc = fs->jpc;  /* save list of jumps to here */
  int j;
  fs->jpc = NO_JUMP;
  j = mr_K_codeAsBx(fs, OP_JMP, 0, NO_JUMP);
  mr_K_concat(fs, &j, jpc);  /* keep them on hold */
  return j;
}


static int mr_K_condjump (FuncState *fs, OpCode op, int A, int B, int C) {
  mr_K_codeABC(fs, op, A, B, C);
  return mr_K_jump(fs);
}


static void mr_K_fixjump (FuncState *fs, int pc, int dest) {
  Instruction *jmp = &fs->f->code[pc];
  int offset = dest-(pc+1);
  mrp_assert(dest != NO_JUMP);
  if (ABS(offset) > MAXARG_sBx) //ouli brew
    mr_X_syntaxerror(fs->ls, "control structure too long");
  SETARG_sBx(*jmp, offset);
}


/*
** returns current `pc' and marks it as a jump target (to avoid wrong
** optimizations with consecutive instructions not in the same basic block).
*/
int mr_K_getlabel (FuncState *fs) {
  fs->lasttarget = fs->pc;
  return fs->pc;
}


static int mr_K_getjump (FuncState *fs, int pc) {
  int offset = GETARG_sBx(fs->f->code[pc]);
  if (offset == NO_JUMP)  /* point to itself represents end of list */
    return NO_JUMP;  /* end of list */
  else
    return (pc+1)+offset;  /* turn offset into absolute position */
}


static Instruction *getjumpcontrol (FuncState *fs, int pc) {
  Instruction *pi = &fs->f->code[pc];
  if (pc >= 1 && testOpMode(GET_OPCODE(*(pi-1)), OpModeT))
    return pi-1;
  else
    return pi;
}


/*
** check whether list has any jump that do not produce a value
** (or produce an inverted value)
*/
static int need_value (FuncState *fs, int list, int cond) {
  for (; list != NO_JUMP; list = mr_K_getjump(fs, list)) {
    Instruction i = *getjumpcontrol(fs, list);
    if (GET_OPCODE(i) != OP_TEST || GETARG_C(i) != cond) return 1;
  }
  return 0;  /* not found */
}


static void patchtestreg (Instruction *i, int reg) {
  if (reg == NO_REG) reg = GETARG_B(*i);
  SETARG_A(*i, reg);
}


static void mr_K_patchlistmr_aux (FuncState *fs, int list,
          int ttarget, int treg, int ftarget, int freg, int dtarget) {
  while (list != NO_JUMP) {
    int next = mr_K_getjump(fs, list);
    Instruction *i = getjumpcontrol(fs, list);
    if (GET_OPCODE(*i) != OP_TEST) {
      mrp_assert(dtarget != NO_JUMP);
      mr_K_fixjump(fs, list, dtarget);  /* jump to default target */
    }
    else {
      if (GETARG_C(*i)) {
        mrp_assert(ttarget != NO_JUMP);
        patchtestreg(i, treg);
        mr_K_fixjump(fs, list, ttarget);
      }
      else {
        mrp_assert(ftarget != NO_JUMP);
        patchtestreg(i, freg);
        mr_K_fixjump(fs, list, ftarget);
      }
    }
    list = next;
  }
}


static void mr_K_dischargejpc (FuncState *fs) {
  mr_K_patchlistmr_aux(fs, fs->jpc, fs->pc, NO_REG, fs->pc, NO_REG, fs->pc);
  fs->jpc = NO_JUMP;
}


void mr_K_patchlist (FuncState *fs, int list, int target) {
  if (target == fs->pc)
    mr_K_patchtohere(fs, list);
  else {
    mrp_assert(target < fs->pc);
    mr_K_patchlistmr_aux(fs, list, target, NO_REG, target, NO_REG, target);
  }
}


void mr_K_patchtohere (FuncState *fs, int list) {
  mr_K_getlabel(fs);
  mr_K_concat(fs, &fs->jpc, list);
}


void mr_K_concat (FuncState *fs, int *l1, int l2) {
  if (l2 == NO_JUMP) return;
  else if (*l1 == NO_JUMP)
    *l1 = l2;
  else {
    int list = *l1;
    int next;
    while ((next = mr_K_getjump(fs, list)) != NO_JUMP)  /* find last element */
      list = next;
    mr_K_fixjump(fs, list, l2);
  }
}


void mr_K_checkstack (FuncState *fs, int n) {
  int newstack = fs->freereg + n;
  if (newstack > fs->f->maxstacksize) {
    if (newstack >= MAXSTACK)
      mr_X_syntaxerror(fs->ls, "function or expression too complex");
    fs->f->maxstacksize = cast(lu_byte, newstack);
  }
}


void mr_K_reserveregs (FuncState *fs, int n) {
  mr_K_checkstack(fs, n);
  fs->freereg += n;
}


static void freereg (FuncState *fs, int reg) {
  if (reg >= fs->nactvar && reg < MAXSTACK) {
    fs->freereg--;
    mrp_assert(reg == fs->freereg);
  }
}


static void freeexp (FuncState *fs, expdesc *e) {
  if (e->k == VNONRELOC)
    freereg(fs, e->info);
}


static int addk (FuncState *fs, TObject *k, TObject *v) {
  const TObject *idx = mr_H_get(fs->h, k);
  if (ttisnumber(idx)) {
    mrp_assert(mr_O_rawequalObj(&fs->f->k[cast(int, nvalue(idx))], v));
    return cast(int, nvalue(idx));
  }
  else {  /* constant not found; create a new entry */
    Proto *f = fs->f;
    mr_M_growvector(fs->L, f->k, fs->nk, f->sizek, TObject,
                    MAXARG_Bx, "constant table overflow");
    setobj2n(&f->k[fs->nk], v);
    setnvalue(mr_H_set(fs->L, fs->h, k), cast(mrp_Number, fs->nk));
    return fs->nk++;
  }
}


int mr_K_stringK (FuncState *fs, TString *s) {
  TObject o;
  setsvalue(&o, s);
  return addk(fs, &o, &o);
}


int mr_K_numberK (FuncState *fs, mrp_Number r) {
  TObject o;
  setnvalue(&o, r);
  return addk(fs, &o, &o);
}


static int nil_constant (FuncState *fs) {
  TObject k, v;
  setnilvalue(&v);
  sethvalue(&k, fs->h);  /* cannot use nil as key; instead use table itself */
  return addk(fs, &k, &v);
}


void mr_K_setcallreturns (FuncState *fs, expdesc *e, int nresults) {
  if (e->k == VCALL) {  /* expression is an open function call? */
    SETARG_C(getcode(fs, e), nresults+1);
    if (nresults == 1) {  /* `regular' expression? */
      e->k = VNONRELOC;
      e->info = GETARG_A(getcode(fs, e));
    }
  }
}


void mr_K_dischargevars (FuncState *fs, expdesc *e) {
  switch (e->k) {
    case VLOCAL: {
      e->k = VNONRELOC;
      break;
    }
    case VUPVAL: {
      e->info = mr_K_codeABC(fs, OP_GETUPVAL, 0, e->info, 0);
      e->k = VRELOCABLE;
      break;
    }
    case VGLOBAL: {
      e->info = mr_K_codeABx(fs, OP_GETGLOBAL, 0, e->info);
      e->k = VRELOCABLE;
      break;
    }
    case VINDEXED: {
      freereg(fs, e->aux);
      freereg(fs, e->info);
      e->info = mr_K_codeABC(fs, OP_GETTABLE, 0, e->info, e->aux);
      e->k = VRELOCABLE;
      break;
    }
    case VCALL: {
      mr_K_setcallreturns(fs, e, 1);
      break;
    }
    default: break;  /* there is one value available (somewhere) */
  }
}


static int code_label (FuncState *fs, int A, int b, int jump) {
  mr_K_getlabel(fs);  /* those instructions may be jump targets */
  return mr_K_codeABC(fs, OP_LOADBOOL, A, b, jump);
}


static void discharge2reg (FuncState *fs, expdesc *e, int reg) {
  mr_K_dischargevars(fs, e);
  switch (e->k) {
    case VNIL: {
      mr_K_nil(fs, reg, 1);
      break;
    }
    case VFALSE:  case VTRUE: {
      mr_K_codeABC(fs, OP_LOADBOOL, reg, e->k == VTRUE, 0);
      break;
    }
    case VK: {
      mr_K_codeABx(fs, OP_LOADK, reg, e->info);
      break;
    }
    case VRELOCABLE: {
      Instruction *pc = &getcode(fs, e);
      SETARG_A(*pc, reg);
      break;
    }
    case VNONRELOC: {
      if (reg != e->info)
        mr_K_codeABC(fs, OP_MOVE, reg, e->info, 0);
      break;
    }
    default: {
      mrp_assert(e->k == VVOID || e->k == VJMP);
      return;  /* nothing to do... */
    }
  }
  e->info = reg;
  e->k = VNONRELOC;
}


static void discharge2anyreg (FuncState *fs, expdesc *e) {
  if (e->k != VNONRELOC) {
    mr_K_reserveregs(fs, 1);
    discharge2reg(fs, e, fs->freereg-1);
  }
}


static void mr_K_exp2reg (FuncState *fs, expdesc *e, int reg) {
  discharge2reg(fs, e, reg);
  if (e->k == VJMP)
    mr_K_concat(fs, &e->t, e->info);  /* put this jump in `t' list */
  if (hasjumps(e)) {
    int final;  /* position after whole expression */
    int p_f = NO_JUMP;  /* position of an eventual LOAD false */
    int p_t = NO_JUMP;  /* position of an eventual LOAD true */
    if (need_value(fs, e->t, 1) || need_value(fs, e->f, 0)) {
      int fj = NO_JUMP;  /* first jump (over LOAD ops.) */
      if (e->k != VJMP)
        fj = mr_K_jump(fs);
      p_f = code_label(fs, reg, 0, 1);
      p_t = code_label(fs, reg, 1, 0);
      mr_K_patchtohere(fs, fj);
    }
    final = mr_K_getlabel(fs);
    mr_K_patchlistmr_aux(fs, e->f, p_f, NO_REG, final, reg, p_f);
    mr_K_patchlistmr_aux(fs, e->t, final, reg, p_t, NO_REG, p_t);
  }
  e->f = e->t = NO_JUMP;
  e->info = reg;
  e->k = VNONRELOC;
}


void mr_K_exp2nextreg (FuncState *fs, expdesc *e) {
  mr_K_dischargevars(fs, e);
  freeexp(fs, e);
  mr_K_reserveregs(fs, 1);
  mr_K_exp2reg(fs, e, fs->freereg - 1);
}


int mr_K_exp2anyreg (FuncState *fs, expdesc *e) {
  mr_K_dischargevars(fs, e);
  if (e->k == VNONRELOC) {
    if (!hasjumps(e)) return e->info;  /* exp is already in a register */ 
    if (e->info >= fs->nactvar) {  /* reg. is not a local? */
      mr_K_exp2reg(fs, e, e->info);  /* put value on it */
      return e->info;
    }
  }
  mr_K_exp2nextreg(fs, e);  /* default */
  return e->info;
}


void mr_K_exp2val (FuncState *fs, expdesc *e) {
  if (hasjumps(e))
    mr_K_exp2anyreg(fs, e);
  else
    mr_K_dischargevars(fs, e);
}


int mr_K_exp2RK (FuncState *fs, expdesc *e) {
  mr_K_exp2val(fs, e);
  switch (e->k) {
    case VNIL: {
      if (fs->nk + MAXSTACK <= MAXARG_C) {  /* constant fit in argC? */
        e->info = nil_constant(fs);
        e->k = VK;
        return e->info + MAXSTACK;
      }
      else break;
    }
    case VK: {
      if (e->info + MAXSTACK <= MAXARG_C)  /* constant fit in argC? */
        return e->info + MAXSTACK;
      else break;
    }
    default: break;
  }
  /* not a constant in the right range: put it in a register */
  return mr_K_exp2anyreg(fs, e);
}


void mr_K_storevar (FuncState *fs, expdesc *var, expdesc *exp) {
  switch (var->k) {
    case VLOCAL: {
      freeexp(fs, exp);
      mr_K_exp2reg(fs, exp, var->info);
      return;
    }
    case VUPVAL: {
      int e = mr_K_exp2anyreg(fs, exp);
      mr_K_codeABC(fs, OP_SETUPVAL, e, var->info, 0);
      break;
    }
    case VGLOBAL: {
      int e = mr_K_exp2anyreg(fs, exp);
      mr_K_codeABx(fs, OP_SETGLOBAL, e, var->info);
      break;
    }
    case VINDEXED: {
      int e = mr_K_exp2RK(fs, exp);
      mr_K_codeABC(fs, OP_SETTABLE, var->info, var->aux, e);
      break;
    }
    default: {
      mrp_assert(0);  /* invalid var kind to store */
      break;
    }
  }
  freeexp(fs, exp);
}


void mr_K_self (FuncState *fs, expdesc *e, expdesc *key) {
  int func;
  mr_K_exp2anyreg(fs, e);
  freeexp(fs, e);
  func = fs->freereg;
  mr_K_reserveregs(fs, 2);
  mr_K_codeABC(fs, OP_SELF, func, e->info, mr_K_exp2RK(fs, key));
  freeexp(fs, key);
  e->info = func;
  e->k = VNONRELOC;
}


static void invertjump (FuncState *fs, expdesc *e) {
  Instruction *pc = getjumpcontrol(fs, e->info);
  mrp_assert(testOpMode(GET_OPCODE(*pc), OpModeT) &&
             GET_OPCODE(*pc) != OP_TEST);
  SETARG_A(*pc, !(GETARG_A(*pc)));
}


static int jumponcond (FuncState *fs, expdesc *e, int cond) {
  if (e->k == VRELOCABLE) {
    Instruction ie = getcode(fs, e);
    if (GET_OPCODE(ie) == OP_NOT) {
      fs->pc--;  /* remove previous OP_NOT */
      return mr_K_condjump(fs, OP_TEST, NO_REG, GETARG_B(ie), !cond);
    }
    /* else go through */
  }
  discharge2anyreg(fs, e);
  freeexp(fs, e);
  return mr_K_condjump(fs, OP_TEST, NO_REG, e->info, cond);
}


void mr_K_goiftrue (FuncState *fs, expdesc *e) {
  int pc;  /* pc of last jump */
  mr_K_dischargevars(fs, e);
  switch (e->k) {
    case VK: case VTRUE: {
      pc = NO_JUMP;  /* always true; do nothing */
      break;
    }
    case VFALSE: {
      pc = mr_K_jump(fs);  /* always jump */
      break;
    }
    case VJMP: {
      invertjump(fs, e);
      pc = e->info;
      break;
    }
    default: {
      pc = jumponcond(fs, e, 0);
      break;
    }
  }
  mr_K_concat(fs, &e->f, pc);  /* insert last jump in `f' list */
}


void mr_K_goiffalse (FuncState *fs, expdesc *e) {
  int pc;  /* pc of last jump */
  mr_K_dischargevars(fs, e);
  switch (e->k) {
    case VNIL: case VFALSE: {
      pc = NO_JUMP;  /* always false; do nothing */
      break;
    }
    case VTRUE: {
      pc = mr_K_jump(fs);  /* always jump */
      break;
    }
    case VJMP: {
      pc = e->info;
      break;
    }
    default: {
      pc = jumponcond(fs, e, 1);
      break;
    }
  }
  mr_K_concat(fs, &e->t, pc);  /* insert last jump in `t' list */
}


static void codenot (FuncState *fs, expdesc *e) {
  mr_K_dischargevars(fs, e);
  switch (e->k) {
    case VNIL: case VFALSE: {
      e->k = VTRUE;
      break;
    }
    case VK: case VTRUE: {
      e->k = VFALSE;
      break;
    }
    case VJMP: {
      invertjump(fs, e);
      break;
    }
    case VRELOCABLE:
    case VNONRELOC: {
      discharge2anyreg(fs, e);
      freeexp(fs, e);
      e->info = mr_K_codeABC(fs, OP_NOT, 0, e->info, 0);
      e->k = VRELOCABLE;
      break;
    }
    default: {
      mrp_assert(0);  /* cannot happen */
      break;
    }
  }
  /* interchange true and false lists */
  { int temp = e->f; e->f = e->t; e->t = temp; }
}


void mr_K_indexed (FuncState *fs, expdesc *t, expdesc *k) {
  t->aux = mr_K_exp2RK(fs, k);
  t->k = VINDEXED;
}

#if 0
void mr_K_prefix (FuncState *fs, UnOpr op, expdesc *e) {
  if (op == OPR_MINUS) {
    mr_K_exp2val(fs, e);
    if (e->k == VK && ttisnumber(&fs->f->k[e->info]))
      e->info = mr_K_numberK(fs, -nvalue(&fs->f->k[e->info]));
    else {
      mr_K_exp2anyreg(fs, e);
      freeexp(fs, e);
      e->info = mr_K_codeABC(fs, OP_UNM, 0, e->info, 0);
      e->k = VRELOCABLE;
    }
  }
  else  /* op == NOT */
    codenot(fs, e);
}
#else
void mr_K_prefix (FuncState *fs, UnOpr op, expdesc *e) {
  if (op == OPR_MINUS) {
    mr_K_exp2val(fs, e);
    if (e->k == VK && ttisnumber(&fs->f->k[e->info]))
      e->info = mr_K_numberK(fs, -nvalue(&fs->f->k[e->info]));
    else {
      mr_K_exp2anyreg(fs, e);
      freeexp(fs, e);
      e->info = mr_K_codeABC(fs, OP_UNM, 0, e->info, 0);
          e->k = VRELOCABLE;
        }
      }
   else if (op == OPR_BNOT) {
      mr_K_exp2val(fs, e);
      if (e->k == VK && ttisnumber(&fs->f->k[e->info]))
         e->info = mr_K_numberK(fs, ~ (long) nvalue(&fs->f->k[e->info]));
      else {
         mr_K_exp2anyreg(fs, e);
      freeexp(fs, e);
      e->info = mr_K_codeABC(fs, OP_BNOT, 0, e->info, 0);
      e->k = VRELOCABLE;
      }
   }
  else  /* op == NOT */
    codenot(fs, e);
}
#endif


void mr_K_infix (FuncState *fs, BinOpr op, expdesc *v) {
  switch (op) {
    case OPR_AND: {
      mr_K_goiftrue(fs, v);
      mr_K_patchtohere(fs, v->t);
      v->t = NO_JUMP;
      break;
    }
    case OPR_OR: {
      mr_K_goiffalse(fs, v);
      mr_K_patchtohere(fs, v->f);
      v->f = NO_JUMP;
      break;
    }
    case OPR_CONCAT: {
      mr_K_exp2nextreg(fs, v);  /* operand must be on the `stack' */
      break;
    }
    default: {
      mr_K_exp2RK(fs, v);
      break;
    }
  }
}

static const OpCode ops[] = {OP_EQ, OP_EQ, OP_LT, OP_LE, OP_LT, OP_LE}; //ouli brew


static void codebinop (FuncState *fs, expdesc *res, BinOpr op,
                       int o1, int o2) {
  if (op <= OPR_POW) {  /* arithmetic operator? */
    OpCode opc = cast(OpCode, (op - OPR_ADD) + OP_ADD);  /* ORDER OP */
    res->info = mr_K_codeABC(fs, opc, 0, o1, o2);
    res->k = VRELOCABLE;
  }
#if 1
  else if ((op >= OPR_BAND) && (op <= OPR_BXOR)) {
     OpCode opc = cast(OpCode, (op - OPR_BAND) + OP_BAND);  /* ORDER OP */
     res->info = mr_K_codeABC(fs, opc, 0, o1, o2);
     res->k = VRELOCABLE;
  }
#endif
  else {  /* test operator */
    //static const OpCode ops[] = {OP_EQ, OP_EQ, OP_LT, OP_LE, OP_LT, OP_LE};


    //LUADBGPRINTF("addr of ops is 0x%x", ops);
    //LUADBGPRINTF("addr of &ops is 0x%x", &ops);


    int cond = 1;
    if (op >= OPR_GT) {  /* `>' or `>='? */
      int temp;  /* exchange args and replace by `<' or `<=' */
      temp = o1; o1 = o2; o2 = temp;  /* o1 <==> o2 */
    }
    else if (op == OPR_NE) cond = 0;
    res->info = mr_K_condjump(fs, ops[op - OPR_NE], cond, o1, o2);
    res->k = VJMP;
  }
}


void mr_K_posfix (FuncState *fs, BinOpr op, expdesc *e1, expdesc *e2) {
  switch (op) {
    case OPR_AND: {
      mrp_assert(e1->t == NO_JUMP);  /* list must be closed */
      mr_K_dischargevars(fs, e2);
      mr_K_concat(fs, &e1->f, e2->f);
      e1->k = e2->k; e1->info = e2->info; e1->aux = e2->aux; e1->t = e2->t;
      break;
    }
    case OPR_OR: {
      mrp_assert(e1->f == NO_JUMP);  /* list must be closed */
      mr_K_dischargevars(fs, e2);
      mr_K_concat(fs, &e1->t, e2->t);
      e1->k = e2->k; e1->info = e2->info; e1->aux = e2->aux; e1->f = e2->f;
      break;
    }
    case OPR_CONCAT: {
      mr_K_exp2val(fs, e2);
      if (e2->k == VRELOCABLE && GET_OPCODE(getcode(fs, e2)) == OP_CONCAT) {
        mrp_assert(e1->info == GETARG_B(getcode(fs, e2))-1);
        freeexp(fs, e1);
        SETARG_B(getcode(fs, e2), e1->info);
        e1->k = e2->k; e1->info = e2->info;
      }
      else {
        mr_K_exp2nextreg(fs, e2);
        freeexp(fs, e2);
        freeexp(fs, e1);
        e1->info = mr_K_codeABC(fs, OP_CONCAT, 0, e1->info, e2->info);
        e1->k = VRELOCABLE;
      }
      break;
    }
    default: {
      int o1 = mr_K_exp2RK(fs, e1);
      int o2 = mr_K_exp2RK(fs, e2);
      freeexp(fs, e2);
      freeexp(fs, e1);
      codebinop(fs, e1, op, o1, o2);
    }
  }
}


void mr_K_fixline (FuncState *fs, int line) {
  fs->f->lineinfo[fs->pc - 1] = line;
}


int mr_K_code (FuncState *fs, Instruction i, int line) {
  Proto *f = fs->f;
  mr_K_dischargejpc(fs);  /* `pc' will change */
  /* put new instruction in code array */
  mr_M_growvector(fs->L, f->code, fs->pc, f->sizecode, Instruction,
                  MAX_INT, "code size overflow");
  f->code[fs->pc] = i;
  /* save corresponding line information */
  mr_M_growvector(fs->L, f->lineinfo, fs->pc, f->sizelineinfo, int,
                  MAX_INT, "code size overflow");
  f->lineinfo[fs->pc] = line;
  return fs->pc++;
}


int mr_K_codeABC (FuncState *fs, OpCode o, int a, int b, int c) {
  mrp_assert(getOpMode(o) == iABC);
  return mr_K_code(fs, CREATE_ABC(o, a, b, c), fs->ls->lastline);
}


int mr_K_codeABx (FuncState *fs, OpCode o, int a, unsigned int bc) {
  mrp_assert(getOpMode(o) == iABx || getOpMode(o) == iAsBx);
  return mr_K_code(fs, CREATE_ABx(o, a, bc), fs->ls->lastline);
}

