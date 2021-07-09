

//#define ldebug_c

#include "../include/mr.h"

#include "./h/mr_api.h"
#include "./h/mr_code.h"
#include "./h/mr_debug.h"
#include "./h/mr_do.h"
#include "./h/mr_func.h"
#include "./h/mr_object.h"
#include "./h/mr_opcodes.h"
#include "./h/mr_state.h"
#include "./h/mr_string.h"
#include "./h/mr_table.h"
#include "./h/mr_tm.h"
#include "./h/mr_vm.h"



static const char *getfuncname (CallInfo *ci, const char **name);


#define isMrp(ci)	(!((ci)->state & CI_C))


static int currentpc (CallInfo *ci) {
  if (!isMrp(ci)) return -1;  /* function is not a Lua function? */
  if (ci->state & CI_HASFRAME)  /* function has a frame? */
    ci->u.l.savedpc = *ci->u.l.pc;  /* use `pc' from there */
  /* function's pc is saved */
  return pcRel(ci->u.l.savedpc, ci_func(ci)->l.p);
}


static int currentline (CallInfo *ci) {
  int pc = currentpc(ci);
  if (pc < 0)
    return -1;  /* only active lua functions have current-line information */
  else
    return getline(ci_func(ci)->l.p, pc);
}


void mr_G_inithooks (mrp_State *L) {
  CallInfo *ci;
  for (ci = L->ci; ci != L->base_ci; ci--)  /* update all `savedpc's */
    currentpc(ci);
  L->hookinit = 1;
}


/*
** this function can be called asynchronous (e.g. during a signal)
*/
MRP_API int mrp_sethook (mrp_State *L, mrp_Hook func, int mask, int count) {
  if (func == NULL || mask == 0) {  /* turn off hooks? */
    mask = 0;
    func = NULL;
  }
  L->hook = func;
  L->basehookcount = count;
  resethookcount(L);
  L->hookmask = cast(lu_byte, mask);
  L->hookinit = 0;
  return 1;
}


MRP_API mrp_Hook mrp_gethook (mrp_State *L) {
  return L->hook;
}


MRP_API int mrp_gethookmask (mrp_State *L) {
  return L->hookmask;
}


MRP_API int mrp_gethookcount (mrp_State *L) {
  return L->basehookcount;
}


MRP_API int mrp_getstack (mrp_State *L, int level, mrp_Debug *ar) {
  int status;
  CallInfo *ci;
  mrp_lock(L);
  for (ci = L->ci; level > 0 && ci > L->base_ci; ci--) {
    level--;
    if (!(ci->state & CI_C))  /* Lua function? */
      level -= ci->u.l.tailcalls;  /* skip lost tail calls */
  }
  if (level > 0 || ci == L->base_ci) status = 0;  /* there is no such level */
  else if (level < 0) {  /* level is of a lost tail call */
    status = 1;
    ar->i_ci = 0;
  }
  else {
    status = 1;
    ar->i_ci = ci - L->base_ci;
  }
  mrp_unlock(L);
  return status;
}


static Proto *getmythroadproto (CallInfo *ci) {
  return (isMrp(ci) ? ci_func(ci)->l.p : NULL);
}


MRP_API const char *mrp_getlocal (mrp_State *L, const mrp_Debug *ar, int n) {
  const char *name;
  CallInfo *ci;
  Proto *fp;
  mrp_lock(L);
  name = NULL;
  ci = L->base_ci + ar->i_ci;
  fp = getmythroadproto(ci);
  if (fp) {  /* is a Lua function? */
    name = mr_F_getlocalname(fp, n, currentpc(ci));
    if (name)
      mr_A_pushobject(L, ci->base+(n-1));  /* push value */
  }
  mrp_unlock(L);
  return name;
}


MRP_API const char *mrp_setlocal (mrp_State *L, const mrp_Debug *ar, int n) {
  const char *name;
  CallInfo *ci;
  Proto *fp;
  mrp_lock(L);
  name = NULL;
  ci = L->base_ci + ar->i_ci;
  fp = getmythroadproto(ci);
  L->top--;  /* pop new value */
  if (fp) {  /* is a Lua function? */
    name = mr_F_getlocalname(fp, n, currentpc(ci));
    if (!name || name[0] == '(')  /* `(' starts private locals */
      name = NULL;
    else
      setobjs2s(ci->base+(n-1), L->top);
  }
  mrp_unlock(L);
  return name;
}


static void funcinfo (mrp_Debug *ar, StkId func) {
  Closure *cl = clvalue(func);
  if (cl->c.isC) {
    ar->source = "=[Internal Func]";
    ar->linedefined = -1;
    ar->what = "C";
  }
  else {
    ar->source = getstr(cl->l.p->source);
    ar->linedefined = cl->l.p->lineDefined;
    ar->what = (ar->linedefined == 0) ? "main" : "Mr";
  }
  mr_O_chunkid(ar->short_src, ar->source, MRP_IDSIZE);
}


static const char *travglobals (mrp_State *L, const TObject *o) {
  Table *g = hvalue(gt(L));
  int i = sizenode(g);
  while (i--) {
    Node *n = gnode(g, i);
    if (mr_O_rawequalObj(o, gval(n)) && ttisstring(gkey(n)))
      return getstr(tsvalue(gkey(n)));
  }
  return NULL;
}


static void info_tailcall (mrp_State *L, mrp_Debug *ar) {
  ar->name = ar->namewhat = "";
  ar->what = "ignore";
  ar->linedefined = ar->currentline = -1;
  ar->source = "=[ignore]";
  mr_O_chunkid(ar->short_src, ar->source, MRP_IDSIZE);
  ar->nups = 0;
  setnilvalue(L->top);
}


static int mr_auxgetinfo (mrp_State *L, const char *what, mrp_Debug *ar,
                    StkId f, CallInfo *ci) {
  int status = 1;
  for (; *what; what++) {
    switch (*what) {
      case 'S': {
        funcinfo(ar, f);
        break;
      }
      case 'l': {
        ar->currentline = (ci) ? currentline(ci) : -1;
        break;
      }
      case 'u': {
        ar->nups = clvalue(f)->c.nupvalues;
        break;
      }
      case 'n': {
        ar->namewhat = (ci) ? getfuncname(ci, &ar->name) : NULL;
        if (ar->namewhat == NULL) {
          /* try to find a global name */
          if ((ar->name = travglobals(L, f)) != NULL)
            ar->namewhat = "global";
          else ar->namewhat = "";  /* not found */
        }
        break;
      }
      case 'f': {
        setobj2s(L->top, f);
        break;
      }
      default: status = 0;  /* invalid option */
    }
  }
  return status;
}


MRP_API int mrp_getinfo (mrp_State *L, const char *what, mrp_Debug *ar) {
  int status = 1;
  mrp_lock(L);
  if (*what == '>') {
    StkId f = L->top - 1;
    if (!ttisfunction(f))
      mr_G_runerror(L, "miss getinfo");
    status = mr_auxgetinfo(L, what + 1, ar, f, NULL);
    L->top--;  /* pop function */
  }
  else if (ar->i_ci != 0) {  /* no tail call? */
    CallInfo *ci = L->base_ci + ar->i_ci;
    mrp_assert(ttisfunction(ci->base - 1));
    status = mr_auxgetinfo(L, what, ar, ci->base - 1, ci);
  }
  else
    info_tailcall(L, ar);
  if (STRCHR(what, 'f')) incr_top(L); //ouli brew
  mrp_unlock(L);
  return status;
}


/*
** {======================================================
** Symbolic Execution and code checker
** =======================================================
*/

#define check(x)		if (!(x)) return 0;

#define checkjump(pt,pc)	check(0 <= pc && pc < pt->sizecode)

#define checkreg(pt,reg)	check((reg) < (pt)->maxstacksize)



static int precheck (const Proto *pt) {
  check(pt->maxstacksize <= MAXSTACK);
  check(pt->sizelineinfo == pt->sizecode || pt->sizelineinfo == 0);
  mrp_assert(pt->numparams+pt->is_vararg <= pt->maxstacksize);
  check(GET_OPCODE(pt->code[pt->sizecode-1]) == OP_RETURN);
  return 1;
}


static int checkopenop (const Proto *pt, int pc) {
  Instruction i = pt->code[pc+1];
  switch (GET_OPCODE(i)) {
    case OP_CALL:
    case OP_TAILCALL:
    case OP_RETURN: {
      check(GETARG_B(i) == 0);
      return 1;
    }
    case OP_SETLISTO: return 1;
    default: return 0;  /* invalid instruction after an open call */
  }
}


static int checkRK (const Proto *pt, int r) {
  return (r < pt->maxstacksize || (r >= MAXSTACK && r-MAXSTACK < pt->sizek));
}


static Instruction mr_G_symbexec (const Proto *pt, int lastpc, int reg) {
  int pc;
  int last;  /* stores position of last instruction that changed `reg' */
  last = pt->sizecode-1;  /* points to final return (a `neutral' instruction) */
  check(precheck(pt));
  for (pc = 0; pc < lastpc; pc++) {
    const Instruction i = pt->code[pc];
    OpCode op = GET_OPCODE(i);
    int a = GETARG_A(i);
    int b = 0;
    int c = 0;
    checkreg(pt, a);
    switch (getOpMode(op)) {
      case iABC: {
        b = GETARG_B(i);
        c = GETARG_C(i);
        if (testOpMode(op, OpModeBreg)) {
          checkreg(pt, b);
        }
        else if (testOpMode(op, OpModeBrk))
          check(checkRK(pt, b));
        if (testOpMode(op, OpModeCrk))
          check(checkRK(pt, c));
        break;
      }
      case iABx: {
        b = GETARG_Bx(i);
        if (testOpMode(op, OpModeK)) check(b < pt->sizek);
        break;
      }
      case iAsBx: {
        b = GETARG_sBx(i);
        break;
      }
    }
    if (testOpMode(op, OpModesetA)) {
      if (a == reg) last = pc;  /* change register `a' */
    }
    if (testOpMode(op, OpModeT)) {
      check(pc+2 < pt->sizecode);  /* check skip */
      check(GET_OPCODE(pt->code[pc+1]) == OP_JMP);
    }
    switch (op) {
      case OP_LOADBOOL: {
        check(c == 0 || pc+2 < pt->sizecode);  /* check its jump */
        break;
      }
      case OP_LOADNIL: {
        if (a <= reg && reg <= b)
          last = pc;  /* set registers from `a' to `b' */
        break;
      }
      case OP_GETUPVAL:
      case OP_SETUPVAL: {
        check(b < pt->nups);
        break;
      }
      case OP_GETGLOBAL:
      case OP_SETGLOBAL: {
        check(ttisstring(&pt->k[b]));
        break;
      }
      case OP_SELF: {
        checkreg(pt, a+1);
        if (reg == a+1) last = pc;
        break;
      }
      case OP_CONCAT: {
        /* `c' is a register, and at least two operands */
        check(c < MAXSTACK && b < c);
        break;
      }
      case OP_TFORLOOP:
        checkreg(pt, a+c+5);
        if (reg >= a) last = pc;  /* affect all registers above base */
        /* go through */
      case OP_FORLOOP:
        checkreg(pt, a+2);
        /* go through */
      case OP_JMP: {
        int dest = pc+1+b;
	check(0 <= dest && dest < pt->sizecode);
        /* not full check and jump is forward and do not skip `lastpc'? */
        if (reg != NO_REG && pc < dest && dest <= lastpc)
          pc += b;  /* do the jump */
        break;
      }
      case OP_CALL:
      case OP_TAILCALL: {
        if (b != 0) {
          checkreg(pt, a+b-1);
        }
        c--;  /* c = num. returns */
        if (c == MRP_MULTRET) {
          check(checkopenop(pt, pc));
        }
        else if (c != 0)
          checkreg(pt, a+c-1);
        if (reg >= a) last = pc;  /* affect all registers above base */
        break;
      }
      case OP_RETURN: {
        b--;  /* b = num. returns */
        if (b > 0) checkreg(pt, a+b-1);
        break;
      }
      case OP_SETLIST: {
        checkreg(pt, a + (b&(LFIELDS_PER_FLUSH-1)) + 1);
        break;
      }
      case OP_CLOSURE: {
        int nup;
        check(b < pt->sizep);
        nup = pt->p[b]->nups;
        check(pc + nup < pt->sizecode);
        for (; nup>0; nup--) {
          OpCode op1 = GET_OPCODE(pt->code[pc+nup]);
          check(op1 == OP_GETUPVAL || op1 == OP_MOVE);
        }
        break;
      }
      default: break;
    }
  }
  return pt->code[last];
}

#undef check
#undef checkjump
#undef checkreg

/* }====================================================== */


int mr_G_checkcode (const Proto *pt) {
  return mr_G_symbexec(pt, pt->sizecode, NO_REG);
}


static const char *kname (Proto *p, int c) {
  c = c - MAXSTACK;
  if (c >= 0 && ttisstring(&p->k[c]))
    return svalue(&p->k[c]);
  else
    return "?";
}


static const char *getobjname (CallInfo *ci, int stackpos, const char **name) {
  if (isMrp(ci)) {  /* a Lua function? */
    Proto *p = ci_func(ci)->l.p;
    int pc = currentpc(ci);
    Instruction i;
    *name = mr_F_getlocalname(p, stackpos+1, pc);
    if (*name)  /* is a local? */
      return "local";
    i = mr_G_symbexec(p, pc, stackpos);  /* try symbolic execution */
    mrp_assert(pc != -1);
    switch (GET_OPCODE(i)) {
      case OP_GETGLOBAL: {
        int g = GETARG_Bx(i);  /* global index */
        mrp_assert(ttisstring(&p->k[g]));
        *name = svalue(&p->k[g]);
        return "global";
      }
      case OP_MOVE: {
        int a = GETARG_A(i);
        int b = GETARG_B(i);  /* move from `b' to `a' */
        if (b < a)
          return getobjname(ci, b, name);  /* get name for `b' */
        break;
      }
      case OP_GETTABLE: {
        int k = GETARG_C(i);  /* key index */
        *name = kname(p, k);
        return "field";
      }
      case OP_SELF: {
        int k = GETARG_C(i);  /* key index */
        *name = kname(p, k);
        return "method";
      }
      default: break;
    }
  }
  return NULL;  /* no useful name found */
}


static const char *getfuncname (CallInfo *ci, const char **name) {
  Instruction i;
  if ((isMrp(ci) && ci->u.l.tailcalls > 0) || !isMrp(ci - 1))
    return NULL;  /* calling function is not Lua (or is unknown) */
  ci--;  /* calling function */
  i = ci_func(ci)->l.p->code[currentpc(ci)];
  if (GET_OPCODE(i) == OP_CALL || GET_OPCODE(i) == OP_TAILCALL)
    return getobjname(ci, GETARG_A(i), name);
  else
    return NULL;  /* no useful name can be found */
}


/* only ANSI way to check whether a pointer points to an array */
static int isinstack (CallInfo *ci, const TObject *o) {
  StkId p;
  for (p = ci->base; p < ci->top; p++)
    if (o == p) return 1;
  return 0;
}


void mr_G_typeerror (mrp_State *L, const TObject *o, const char *op) {
  const char *name = NULL;
  const char *t = mr_T_typenames[ttype(o)];
  const char *kind = (isinstack(L->ci, o)) ?
                         getobjname(L->ci, o - L->base, &name) : NULL;
  if (kind)
    mr_G_runerror(L, "err:%s %s `%s' (%s)", //attempt to %s %s `%s' (a %s value)
                op, kind, name, t);
  else
    mr_G_runerror(L, "err:%s a %s value", op, t);  //attempt to %s a %s value
}


void mr_G_concaterror (mrp_State *L, StkId p1, StkId p2) {
  if (ttisstring(p1)) p1 = p2;
  mrp_assert(!ttisstring(p1));
  mr_G_typeerror(L, p1, "cat(..)"); //concatenate
}


void mr_G_aritherror (mrp_State *L, const TObject *p1, const TObject *p2) {
  TObject temp;
  if (mr_V_tonumber(p1, &temp) == NULL)
    p2 = p1;  /* first operand is wrong */
  mr_G_typeerror(L, p2, "expect num(arith) but ");  //perform arithmetic on
}


int mr_G_ordererror (mrp_State *L, const TObject *p1, const TObject *p2) {
  const char *t1 = mr_T_typenames[ttype(p1)];
  const char *t2 = mr_T_typenames[ttype(p2)];
  mr_G_runerror(L, "err:compare %s with %s", t1, t2);
#if 0
  if (t1[2] == t2[2])
    mr_G_runerror(L, "attempt to compare two %s values", t1);
  else
    mr_G_runerror(L, "attempt to compare %s with %s", t1, t2);
#endif
  return 0;
}


static void addinfo (mrp_State *L, const char *msg) {
  CallInfo *ci = L->ci;
  if (isMrp(ci)) {  /* is Mythroad code? */
    char buff[MRP_IDSIZE];  /* add file:line information */
    int line = currentline(ci);
    mr_O_chunkid(buff, getstr(getmythroadproto(ci)->source), MRP_IDSIZE);
    mr_O_pushfstring(L, "%s:%d: %s", buff, line, msg);
  }
}


void mr_G_errormsg (mrp_State *L) {
  if (L->errfunc != 0) {  /* is there an error handling function? */
    StkId errfunc = restorestack(L, L->errfunc);
    if (!ttisfunction(errfunc)) mr_D_throw(L, MRP_ERRERR);
    setobjs2s(L->top, L->top - 1);  /* move argument */
    setobjs2s(L->top - 1, errfunc);  /* push function */
    incr_top(L);
    mr_D_call(L, L->top - 2, 1);  /* call it */
  }
  mr_D_throw(L, MRP_ERRRUN);
}


void mr_G_runerror (mrp_State *L, const char *fmt, ...) {
  va_list argp;
  va_start(argp, fmt);
  addinfo(L, mr_O_pushvfstring(L, fmt, argp));
  va_end(argp);
  mr_G_errormsg(L);
}

