


#define lvm_c


#include "./h/mr_debug.h"
#include "./h/mr_do.h"
#include "./h/mr_func.h"
#include "./h/mr_gc.h"
#include "./h/mr_object.h"
#include "./h/mr_opcodes.h"
#include "./h/mr_state.h"
#include "./h/mr_string.h"
#include "./h/mr_table.h"
#include "./h/mr_tm.h"
#include "./h/mr_vm.h"



/* function to convert a mrp_Number to a string */
#ifndef mrp_number2str
#define mrp_number2str(s,n)     SPRINTF((s), MRP_NUMBER_FMT, (n))
#endif


/* limit for table tag-method chains (to avoid loops) */
#define MAXTAGLOOP	100


const TObject *mr_V_tonumber (const TObject *obj, TObject *n) {
  mrp_Number num;
  if (ttisnumber(obj)) return obj;
  if (ttisstring(obj) && mr_O_str2d(svalue(obj), &num)) {
    setnvalue(n, num);
    return n;
  }
  else
    return NULL;
}


int mr_V_tostring (mrp_State *L, StkId obj) {
  if (!ttisnumber(obj))
    return 0;
  else {
    char s[32];  /* 16 digits, sign, point and \0  (+ some extra...) */
    mrp_number2str(s, nvalue(obj));
    setsvalue2s(obj, mr_S_new(L, s));
    return 1;
  }
}


static void traceexec (mrp_State *L) {
  lu_byte mask = L->hookmask;
  if (mask & MRP_MASKCOUNT) {  /* instruction-hook set? */
    if (L->hookcount == 0) {
      resethookcount(L);
      mr_D_callhook(L, MRP_HOOKCOUNT, -1);
      return;
    }
  }
  if (mask & MRP_MASKLINE) {
    CallInfo *ci = L->ci;
    Proto *p = ci_func(ci)->l.p;
    int newline = getline(p, pcRel(*ci->u.l.pc, p));
    if (!L->hookinit) {
      mr_G_inithooks(L);
      return;
    }
    mrp_assert(ci->state & CI_HASFRAME);
    if (pcRel(*ci->u.l.pc, p) == 0)  /* tracing may be starting now? */
      ci->u.l.savedpc = *ci->u.l.pc;  /* initialize `savedpc' */
    /* calls linehook when enters a new line or jumps back (loop) */
    if (*ci->u.l.pc <= ci->u.l.savedpc ||
        newline != getline(p, pcRel(ci->u.l.savedpc, p))) {
      mr_D_callhook(L, MRP_HOOKLINE, newline);
      ci = L->ci;  /* previous call may reallocate `ci' */
    }
    ci->u.l.savedpc = *ci->u.l.pc;
  }
}


static void callTMres (mrp_State *L, const TObject *f,
                       const TObject *p1, const TObject *p2) {
  setobj2s(L->top, f);  /* push function */
  setobj2s(L->top+1, p1);  /* 1st argument */
  setobj2s(L->top+2, p2);  /* 2nd argument */
  mr_D_checkstack(L, 3);  /* cannot check before (could invalidate p1, p2) */
  L->top += 3;
  mr_D_call(L, L->top - 3, 1);
  L->top--;  /* result will be in L->top */
}



static void callTM (mrp_State *L, const TObject *f,
                    const TObject *p1, const TObject *p2, const TObject *p3) {
  setobj2s(L->top, f);  /* push function */
  setobj2s(L->top+1, p1);  /* 1st argument */
  setobj2s(L->top+2, p2);  /* 2nd argument */
  setobj2s(L->top+3, p3);  /* 3th argument */
  mr_D_checkstack(L, 4);  /* cannot check before (could invalidate p1...p3) */
  L->top += 4;
  mr_D_call(L, L->top - 4, 0);
}


static const TObject *mr_V_index (mrp_State *L, const TObject *t,
                                  TObject *key, int loop) {
  const TObject *tm = fasttm(L, hvalue(t)->metatable, TM_INDEX);
  if (tm == NULL) return &mr_O_nilobject;  /* no TM */
  if (ttisfunction(tm)) {
    callTMres(L, tm, t, key);
    return L->top;
  }
  else return mr_V_gettable(L, tm, key, loop);
}

static const TObject *mr_V_getnotable (mrp_State *L, const TObject *t,
                                       TObject *key, int loop) {
  const TObject *tm = mr_T_gettmbyobj(L, t, TM_INDEX);
  if (ttisnil(tm))
    mr_G_typeerror(L, t, "index");
  if (ttisfunction(tm)) {
    callTMres(L, tm, t, key);
    return L->top;
  }
  else return mr_V_gettable(L, tm, key, loop);
}


/*
** Function to index a table.
** Receives the table at `t' and the key at `key'.
** leaves the result at `res'.
*/
const TObject *mr_V_gettable (mrp_State *L, const TObject *t, TObject *key,
                              int loop) {
  if (loop > MAXTAGLOOP)
    mr_G_runerror(L, "table err:2014"); //loop in gettable
  if (ttistable(t)) {  /* `t' is a table? */
    Table *h = hvalue(t);
    const TObject *v = mr_H_get(h, key);  /* do a primitive get */
    if (!ttisnil(v)) return v;
    else return mr_V_index(L, t, key, loop+1);
  }
  else return mr_V_getnotable(L, t, key, loop+1);
}


/*
** Receives table at `t', key at `key' and value at `val'.
*/
void mr_V_settable (mrp_State *L, const TObject *t, TObject *key, StkId val) {
  const TObject *tm;
  int loop = 0;
  do {
    if (ttistable(t)) {  /* `t' is a table? */
      Table *h = hvalue(t);
      TObject *oldval = mr_H_set(L, h, key); /* do a primitive set */
      if (!ttisnil(oldval) ||  /* result is no nil? */
          (tm = fasttm(L, h->metatable, TM_NEWINDEX)) == NULL) { /* or no TM? */
        setobj2t(oldval, val);  /* write barrier */
        return;
      }
      /* else will try the tag method */
    }
    else if (ttisnil(tm = mr_T_gettmbyobj(L, t, TM_NEWINDEX)))
      mr_G_typeerror(L, t, "index");
    if (ttisfunction(tm)) {
      callTM(L, tm, t, key, val);
      return;
    }
    t = tm;  /* else repeat with `tm' */ 
  } while (++loop <= MAXTAGLOOP);
  mr_G_runerror(L, "table err:2015");// loop in settable
}


static int call_binTM (mrp_State *L, const TObject *p1, const TObject *p2,
                       StkId res, TMS event) {
  ptrdiff_t result = savestack(L, res);
  const TObject *tm = mr_T_gettmbyobj(L, p1, event);  /* try first operand */
  if (ttisnil(tm))
    tm = mr_T_gettmbyobj(L, p2, event);  /* try second operand */
  if (!ttisfunction(tm)) return 0;
  callTMres(L, tm, p1, p2);
  res = restorestack(L, result);  /* previous call may change stack */
  setobjs2s(res, L->top);
  return 1;
}


static const TObject *get_compTM (mrp_State *L, Table *mt1, Table *mt2,
                                  TMS event) {
  const TObject *tm1 = fasttm(L, mt1, event);
  const TObject *tm2;
  if (tm1 == NULL) return NULL;  /* no metamethod */
  if (mt1 == mt2) return tm1;  /* same metatables => same metamethods */
  tm2 = fasttm(L, mt2, event);
  if (tm2 == NULL) return NULL;  /* no metamethod */
  if (mr_O_rawequalObj(tm1, tm2))  /* same metamethods? */
    return tm1;
  return NULL;
}


static int call_orderTM (mrp_State *L, const TObject *p1, const TObject *p2,
                         TMS event) {
  const TObject *tm1 = mr_T_gettmbyobj(L, p1, event);
  const TObject *tm2;
  if (ttisnil(tm1)) return -1;  /* no metamethod? */
  tm2 = mr_T_gettmbyobj(L, p2, event);
  if (!mr_O_rawequalObj(tm1, tm2))  /* different metamethods? */
    return -1;
  callTMres(L, tm1, p1, p2);
  return !l_isfalse(L->top);
}


static int mr_V_strcmp (const TString *ls, const TString *rs) {
  const char *l = getstr(ls);
  size_t ll = ls->tsv.len;
  const char *r = getstr(rs);
  size_t lr = rs->tsv.len;
  for (;;) {
    int temp = STRCOLL(l, r);
    if (temp != 0) return temp;
    else {  /* strings are equal up to a `\0' */
      size_t len = STRLEN(l);  /* index of first `\0' in both strings */
      if (len == lr)  /* r is finished? */
        return (len == ll) ? 0 : 1;
      else if (len == ll)  /* l is finished? */
        return -1;  /* l is smaller than r (because r is not finished) */
      /* both strings longer than `len'; go on comparing (after the `\0') */
      len++;
      l += len; ll -= len; r += len; lr -= len;
    }
  }
}


int mr_V_lessthan (mrp_State *L, const TObject *l, const TObject *r) {
  int res;
  if (ttype(l) != ttype(r))
    return mr_G_ordererror(L, l, r);
  else if (ttisnumber(l))
    return nvalue(l) < nvalue(r);
  else if (ttisstring(l))
    return mr_V_strcmp(tsvalue(l), tsvalue(r)) < 0;
  else if ((res = call_orderTM(L, l, r, TM_LT)) != -1)
    return res;
  return mr_G_ordererror(L, l, r);
}


static int mr_V_lessequal (mrp_State *L, const TObject *l, const TObject *r) {
  int res;
  if (ttype(l) != ttype(r))
    return mr_G_ordererror(L, l, r);
  else if (ttisnumber(l))
    return nvalue(l) <= nvalue(r);
  else if (ttisstring(l))
    return mr_V_strcmp(tsvalue(l), tsvalue(r)) <= 0;
  else if ((res = call_orderTM(L, l, r, TM_LE)) != -1)  /* first try `le' */
    return res;
  else if ((res = call_orderTM(L, r, l, TM_LT)) != -1)  /* else try `lt' */
    return !res;
  return mr_G_ordererror(L, l, r);
}


int mr_V_equalval (mrp_State *L, const TObject *t1, const TObject *t2) {
  const TObject *tm;
  mrp_assert(ttype(t1) == ttype(t2));
  switch (ttype(t1)) {
    case MRP_TNIL: return 1;
    case MRP_TNUMBER: return nvalue(t1) == nvalue(t2);
    case MRP_TBOOLEAN: return bvalue(t1) == bvalue(t2);  /* true must be 1 !! */
    case MRP_TLIGHTUSERDATA: return pvalue(t1) == pvalue(t2);
    case MRP_TUSERDATA: {
      if (uvalue(t1) == uvalue(t2)) return 1;
      tm = get_compTM(L, uvalue(t1)->uv.metatable, uvalue(t2)->uv.metatable,
                         TM_EQ);
      break;  /* will try TM */
    }
    case MRP_TTABLE: {
      if (hvalue(t1) == hvalue(t2)) return 1;
      tm = get_compTM(L, hvalue(t1)->metatable, hvalue(t2)->metatable, TM_EQ);
      break;  /* will try TM */
    }
    default: return gcvalue(t1) == gcvalue(t2);
  }
  if (tm == NULL) return 0;  /* no TM? */
  callTMres(L, tm, t1, t2);  /* call TM */
  return !l_isfalse(L->top);
}


void mr_V_concat (mrp_State *L, int total, int last) {
  do {
    StkId top = L->base + last + 1;
    int n = 2;  /* number of elements handled in this pass (at least 2) */
    if (!tostring(L, top-2) || !tostring(L, top-1)) {
      if (!call_binTM(L, top-2, top-1, top-2, TM_CONCAT))
        mr_G_concaterror(L, top-2, top-1);
    } else if (tsvalue(top-1)->tsv.len > 0) {  /* if len=0, do nothing */
      /* at least two string values; get as many as possible */
#if 0
      lu_mem tl = cast(lu_mem, tsvalue(top-1)->tsv.len) +
                  cast(lu_mem, tsvalue(top-2)->tsv.len);
#else
      size_t tl = tsvalue(top-1)->tsv.len;
#endif
      char *buffer;
      int i;
#if 0 
      while (n < total && tostring(L, top-n-1)) {  /* collect total length */
        tl += tsvalue(top-n-1)->tsv.len;
        n++;
#else
      /* collect total length */
      for (n = 1; n < total && tostring(L, top-n-1); n++) {
        size_t l = tsvalue(top-n-1)->tsv.len;
        if (l >= MAX_SIZET - tl) mr_G_runerror(L, "string err:2030");  //string length overflow
        tl += l;
#endif
      }
#if 0 
      if (tl > MAX_SIZET) mr_G_runerror(L, "string size overflow");
#endif
      buffer = mr_Z_openspace(L, &G(L)->buff, tl);
      tl = 0;
      for (i=n; i>0; i--) {  /* concat all strings */
        size_t l = tsvalue(top-i)->tsv.len;
        MEMCPY(buffer+tl, svalue(top-i), l);//ouli brew
        tl += l;
      }
      setsvalue2s(top-n, mr_S_newlstr(L, buffer, tl));
    }
    total -= n-1;  /* got `n' strings to create 1 new */
    last -= n-1;
  } while (total > 1);  /* repeat until only 1 result left */
}


static void Arith (mrp_State *L, StkId ra,
                   const TObject *rb, const TObject *rc, TMS op) {
  TObject tempb, tempc;
  const TObject *b, *c;
  if ((b = mr_V_tonumber(rb, &tempb)) != NULL &&
      (c = mr_V_tonumber(rc, &tempc)) != NULL) {
    switch (op) {
      case TM_ADD: setnvalue(ra, nvalue(b) + nvalue(c)); break;
      case TM_SUB: setnvalue(ra, nvalue(b) - nvalue(c)); break;
      case TM_MUL: setnvalue(ra, nvalue(b) * nvalue(c)); break;
      case TM_DIV: setnvalue(ra, nvalue(b) / nvalue(c)); break;
      case TM_POW: {
        const TObject *f = mr_H_getstr(hvalue(gt(L)), G(L)->tmname[TM_POW]);
        ptrdiff_t res = savestack(L, ra);
        if (!ttisfunction(f))
          mr_G_runerror(L, "err:1020"); //`__op' (`^' operator) is not a function
        callTMres(L, f, b, c);
        ra = restorestack(L, res);  /* previous call may change stack */
        setobjs2s(ra, L->top);
        break;
      }
      default: mrp_assert(0); break;
    }
  }
  else if (!call_binTM(L, rb, rc, ra, op))
    mr_G_aritherror(L, rb, rc);
}



/*
** some macros for common tasks in `mr_V_execute'
*/

#define runtime_check(L, c)	{ if (!(c)) return 0; }

#define RA(i)	(base+GETARG_A(i))
/* to be used after possible stack reallocation */
#define XRA(i)	(L->base+GETARG_A(i))
#define RB(i)	(base+GETARG_B(i))
#define RKB(i)	((GETARG_B(i) < MAXSTACK) ? RB(i) : k+GETARG_B(i)-MAXSTACK)
#define RC(i)	(base+GETARG_C(i))
#define RKC(i)	((GETARG_C(i) < MAXSTACK) ? RC(i) : k+GETARG_C(i)-MAXSTACK)
#define KBx(i)	(k+GETARG_Bx(i))


#define dojump(pc, i)	((pc) += (i))


StkId mr_V_execute (mrp_State *L) {
  LClosure *cl;
  TObject *k;
  const Instruction *pc;
 callentry:  /* entry point when calling new functions */
  if (L->hookmask & MRP_MASKCALL) {
    L->ci->u.l.pc = &pc;
    mr_D_callhook(L, MRP_HOOKCALL, -1);
  }
 retentry:  /* entry point when returning to old functions */
  L->ci->u.l.pc = &pc;
  mrp_assert(L->ci->state == CI_SAVEDPC ||
             L->ci->state == (CI_SAVEDPC | CI_CALLING));
  L->ci->state = CI_HASFRAME;  /* activate frame */
  pc = L->ci->u.l.savedpc;
  cl = &clvalue(L->base - 1)->l;
  k = cl->p->k;
  /* main loop of interpreter */
  for (;;) {
    const Instruction i = *pc++;
    StkId base, ra;
    if ((L->hookmask & (MRP_MASKLINE | MRP_MASKCOUNT)) &&
        (--L->hookcount == 0 || L->hookmask & MRP_MASKLINE)) {
      traceexec(L);
      if (L->ci->state & CI_YIELD) {  /* did hook yield? */
        L->ci->u.l.savedpc = pc - 1;
        L->ci->state = CI_YIELD | CI_SAVEDPC;
        return NULL;
      }
    }
    /* warning!! several calls may realloc the stack and invalidate `ra' */
    base = L->base;
    ra = RA(i);
    mrp_assert(L->ci->state & CI_HASFRAME);
    mrp_assert(base == L->ci->base);
    mrp_assert(L->top <= L->stack + L->stacksize && L->top >= base);
    mrp_assert(L->top == L->ci->top ||
         GET_OPCODE(i) == OP_CALL ||   GET_OPCODE(i) == OP_TAILCALL ||
         GET_OPCODE(i) == OP_RETURN || GET_OPCODE(i) == OP_SETLISTO);
    switch (GET_OPCODE(i)) {
      case OP_MOVE: {
        setobjs2s(ra, RB(i));
        break;
      }
      case OP_LOADK: {
        setobj2s(ra, KBx(i));
        break;
      }
      case OP_LOADBOOL: {
        setbvalue(ra, GETARG_B(i));
        if (GETARG_C(i)) pc++;  /* skip next instruction (if C) */
        break;
      }
      case OP_LOADNIL: {
        TObject *rb = RB(i);
        do {
          setnilvalue(rb--);
        } while (rb >= ra);
        break;
      }
      case OP_GETUPVAL: {
        int b = GETARG_B(i);
        setobj2s(ra, cl->upvals[b]->v);
        break;
      }
      case OP_GETGLOBAL: {
        TObject *rb = KBx(i);
        const TObject *v;
        mrp_assert(ttisstring(rb) && ttistable(&cl->g));
        v = mr_H_getstr(hvalue(&cl->g), tsvalue(rb));
        if (!ttisnil(v)) { setobj2s(ra, v); }
        else
          setobj2s(XRA(i), mr_V_index(L, &cl->g, rb, 0));
        break;
      }
      case OP_GETTABLE: {
        StkId rb = RB(i);
        TObject *rc = RKC(i);
        if (ttistable(rb)) {
          const TObject *v = mr_H_get(hvalue(rb), rc);
          if (!ttisnil(v)) { setobj2s(ra, v); }
          else
            setobj2s(XRA(i), mr_V_index(L, rb, rc, 0));
        }
        else
          setobj2s(XRA(i), mr_V_getnotable(L, rb, rc, 0));
        break;
      }
      case OP_SETGLOBAL: {
        mrp_assert(ttisstring(KBx(i)) && ttistable(&cl->g));
        mr_V_settable(L, &cl->g, KBx(i), ra);
        break;
      }
      case OP_SETUPVAL: {
        int b = GETARG_B(i);
        setobj(cl->upvals[b]->v, ra);  /* write barrier */
        break;
      }
      case OP_SETTABLE: {
        mr_V_settable(L, ra, RKB(i), RKC(i));
        break;
      }
      case OP_NEWTABLE: {
        int b = GETARG_B(i);
        b = fb2int(b);
        sethvalue(ra, mr_H_new(L, b, GETARG_C(i)));
        mr_C_checkGC(L);
        break;
      }
      case OP_SELF: {
        StkId rb = RB(i);
        TObject *rc = RKC(i);
        runtime_check(L, ttisstring(rc));
        setobjs2s(ra+1, rb);
        if (ttistable(rb)) {
          const TObject *v = mr_H_getstr(hvalue(rb), tsvalue(rc));
          if (!ttisnil(v)) { setobj2s(ra, v); }
          else
            setobj2s(XRA(i), mr_V_index(L, rb, rc, 0));
        }
        else
          setobj2s(XRA(i), mr_V_getnotable(L, rb, rc, 0));
        break;
      }
      case OP_ADD: {
        TObject *rb = RKB(i);
        TObject *rc = RKC(i);
        if (ttisnumber(rb) && ttisnumber(rc)) {
          setnvalue(ra, nvalue(rb) + nvalue(rc));
        }
        else
          Arith(L, ra, rb, rc, TM_ADD);
        break;
      }
      case OP_SUB: {
        TObject *rb = RKB(i);
        TObject *rc = RKC(i);
        if (ttisnumber(rb) && ttisnumber(rc)) {
          setnvalue(ra, nvalue(rb) - nvalue(rc));
        }
        else
          Arith(L, ra, rb, rc, TM_SUB);
        break;
      }
      case OP_MUL: {
        TObject *rb = RKB(i);
        TObject *rc = RKC(i);
        if (ttisnumber(rb) && ttisnumber(rc)) {
          setnvalue(ra, nvalue(rb) * nvalue(rc));
        }
        else
          Arith(L, ra, rb, rc, TM_MUL);
        break;
      }
      case OP_DIV: {
        TObject *rb = RKB(i);
        TObject *rc = RKC(i);
        if (ttisnumber(rb) && ttisnumber(rc)) {
          setnvalue(ra, nvalue(rb) / nvalue(rc));
        }
        else
          Arith(L, ra, rb, rc, TM_DIV);
        break;
      }
      case OP_POW: {
        Arith(L, ra, RKB(i), RKC(i), TM_POW);
        break;
      }
      case OP_UNM: {
        const TObject *rb = RB(i);
        TObject temp;
        if (tonumber(rb, &temp)) {
          setnvalue(ra, -nvalue(rb));
        }
        else {
          setnilvalue(&temp);
          if (!call_binTM(L, RB(i), &temp, ra, TM_UNM))
            mr_G_aritherror(L, RB(i), &temp);
        }
        break;
      }
      case OP_NOT: {
        int res = l_isfalse(RB(i));  /* next assignment may change this value */
        setbvalue(ra, res);
        break;
      }
      case OP_CONCAT: {
        int b = GETARG_B(i);
        int c = GETARG_C(i);
        mr_V_concat(L, c-b+1, c);  /* may change `base' (and `ra') */
        base = L->base;
        setobjs2s(RA(i), base+b);
        mr_C_checkGC(L);
        break;
      }
      case OP_JMP: {
        dojump(pc, GETARG_sBx(i));
        break;
      }
      case OP_EQ: {
        if (equalobj(L, RKB(i), RKC(i)) != GETARG_A(i)) pc++;
        else dojump(pc, GETARG_sBx(*pc) + 1);
        break;
      }
      case OP_LT: {
        if (mr_V_lessthan(L, RKB(i), RKC(i)) != GETARG_A(i)) pc++;
        else dojump(pc, GETARG_sBx(*pc) + 1);
        break;
      }
      case OP_LE: {
        if (mr_V_lessequal(L, RKB(i), RKC(i)) != GETARG_A(i)) pc++;
        else dojump(pc, GETARG_sBx(*pc) + 1);
        break;
      }
      case OP_TEST: {
        TObject *rb = RB(i);
        if (l_isfalse(rb) == GETARG_C(i)) pc++;
        else {
          setobjs2s(ra, rb);
          dojump(pc, GETARG_sBx(*pc) + 1);
        }
        break;
      }
      case OP_CALL:
      case OP_TAILCALL: {
        StkId firstResult;
        int b = GETARG_B(i);
        int nresults;
        if (b != 0) L->top = ra+b;  /* else previous instruction set top */
        nresults = GETARG_C(i) - 1;
        firstResult = mr_D_precall(L, ra);
        if (firstResult) {
          if (firstResult > L->top) {  /* yield? */
            mrp_assert(L->ci->state == (CI_C | CI_YIELD));
            (L->ci - 1)->u.l.savedpc = pc;
            (L->ci - 1)->state = CI_SAVEDPC;
            return NULL;
          }
          /* it was a C function (`precall' called it); adjust results */
          mr_D_poscall(L, nresults, firstResult);
          if (nresults >= 0) L->top = L->ci->top;
        }
        else {  /* it is a Lua function */
          if (GET_OPCODE(i) == OP_CALL) {  /* regular call? */
            (L->ci-1)->u.l.savedpc = pc;  /* save `pc' to return later */
            (L->ci-1)->state = (CI_SAVEDPC | CI_CALLING);
          }
          else {  /* tail call: put new frame in place of previous one */
            int aux;
            base = (L->ci - 1)->base;  /* `mr_D_precall' may change the stack */
            ra = RA(i);
            if (L->openupval) mr_F_close(L, base);
            for (aux = 0; ra+aux < L->top; aux++)  /* move frame down */
              setobjs2s(base+aux-1, ra+aux);
            (L->ci - 1)->top = L->top = base+aux;  /* correct top */
            mrp_assert(L->ci->state & CI_SAVEDPC);
            (L->ci - 1)->u.l.savedpc = L->ci->u.l.savedpc;
            (L->ci - 1)->u.l.tailcalls++;  /* one more call lost */
            (L->ci - 1)->state = CI_SAVEDPC;
            L->ci--;  /* remove new frame */
            L->base = L->ci->base;
          }
          goto callentry;
        }
        break;
      }
      case OP_RETURN: {
        CallInfo *ci = L->ci - 1;  /* previous function frame */
        int b = GETARG_B(i);
        if (b != 0) L->top = ra+b-1;
        mrp_assert(L->ci->state & CI_HASFRAME);
        if (L->openupval) mr_F_close(L, base);
        L->ci->state = CI_SAVEDPC;  /* deactivate current function */
        L->ci->u.l.savedpc = pc;
        /* previous function was running `here'? */
        if (!(ci->state & CI_CALLING)) {
          mrp_assert((ci->state & CI_C) || ci->u.l.pc != &pc);
          return ra;  /* no: return */
        }
        else {  /* yes: continue its execution */
          int nresults;
          mrp_assert(ttisfunction(ci->base - 1) && (ci->state & CI_SAVEDPC));
          mrp_assert(GET_OPCODE(*(ci->u.l.savedpc - 1)) == OP_CALL);
          nresults = GETARG_C(*(ci->u.l.savedpc - 1)) - 1;
          mr_D_poscall(L, nresults, ra);
          if (nresults >= 0) L->top = L->ci->top;
          goto retentry;
        }
      }
      case OP_FORLOOP: {
        mrp_Number step, idx, limit;
        const TObject *plimit = ra+1;
        const TObject *pstep = ra+2;
        if (!ttisnumber(ra))
          mr_G_runerror(L, "err:1021"); //`for' initial value must be a number
        if (!tonumber(plimit, ra+1))
          mr_G_runerror(L, "err:1022");  //`for' limit must be a number
        if (!tonumber(pstep, ra+2))
          mr_G_runerror(L, "err:1023");  //`for' step must be a number
        step = nvalue(pstep);
        idx = nvalue(ra) + step;  /* increment index */
        limit = nvalue(plimit);
        if (step > 0 ? idx <= limit : idx >= limit) {
          dojump(pc, GETARG_sBx(i));  /* jump back */
          chgnvalue(ra, idx);  /* update index */
        }
        break;
      }
      case OP_TFORLOOP: {
        int nvar = GETARG_C(i) + 1;
        StkId cb = ra + nvar + 2;  /* call base */
        setobjs2s(cb, ra);
        setobjs2s(cb+1, ra+1);
        setobjs2s(cb+2, ra+2);
        L->top = cb+3;  /* func. + 2 args (state and index) */
        mr_D_call(L, cb, nvar);
        L->top = L->ci->top;
        ra = XRA(i) + 2;  /* final position of first result */
        cb = ra + nvar;
        do {  /* move results to proper positions */
          nvar--;
          setobjs2s(ra+nvar, cb+nvar);
        } while (nvar > 0);
        if (ttisnil(ra))  /* break loop? */
          pc++;  /* skip jump (break loop) */
        else
          dojump(pc, GETARG_sBx(*pc) + 1);  /* jump back */
        break;
      }
      case OP_TFORPREP: {  /* for compatibility only */
        if (ttistable(ra)) {
          setobjs2s(ra+1, ra);
          setobj2s(ra, mr_H_getstr(hvalue(gt(L)), mr_S_new(L, "_next")));
        }
        dojump(pc, GETARG_sBx(i));
        break;
      }
      case OP_SETLIST:
      case OP_SETLISTO: {
        int bc;
        int n;
        Table *h;
        runtime_check(L, ttistable(ra));
        h = hvalue(ra);
        bc = GETARG_Bx(i);
        if (GET_OPCODE(i) == OP_SETLIST)
          n = (bc&(LFIELDS_PER_FLUSH-1)) + 1;
        else {
          n = L->top - ra - 1;
          L->top = L->ci->top;
        }
        bc &= ~(LFIELDS_PER_FLUSH-1);  /* bc = bc - bc%FPF */
        for (; n > 0; n--)
          setobj2t(mr_H_setnum(L, h, bc+n), ra+n);  /* write barrier */
        break;
      }
      case OP_CLOSE: {
        mr_F_close(L, ra);
        break;
      }
      case OP_CLOSURE: {
        Proto *p;
        Closure *ncl;
        int nup, j;
        p = cl->p->p[GETARG_Bx(i)];
        nup = p->nups;
        ncl = mr_F_newLclosure(L, nup, &cl->g);
        ncl->l.p = p;
        for (j=0; j<nup; j++, pc++) {
          if (GET_OPCODE(*pc) == OP_GETUPVAL)
            ncl->l.upvals[j] = cl->upvals[GETARG_B(*pc)];
          else {
            mrp_assert(GET_OPCODE(*pc) == OP_MOVE);
            ncl->l.upvals[j] = mr_F_findupval(L, base + GETARG_B(*pc));
          }
        }
        setclvalue(ra, ncl);
        mr_C_checkGC(L);
        break;
      }
#if 1
      case OP_BNOT: {
        const TObject *rb = RKB(i);
        if (ttisnumber(rb)) {
          setnvalue(ra, ~ (long) nvalue(rb));
        }
        break;
      }
      case OP_BAND: {
        TObject *rb = RKB(i);
        TObject *rc = RKC(i);
        if (ttisnumber(rb) && ttisnumber(rc)) {
          setnvalue(ra, (long) nvalue(rb) & (long) nvalue(rc));
        }
        break;
      }
      case OP_BOR: {
        TObject *rb = RKB(i);
        TObject *rc = RKC(i);
        if (ttisnumber(rb) && ttisnumber(rc)) {
          setnvalue(ra, (long) nvalue(rb) | (long) nvalue(rc));
        }
        break;
      }
      case OP_BXOR: {
        TObject *rb = RKB(i);
        TObject *rc = RKC(i);
        if (ttisnumber(rb) && ttisnumber(rc)) {
          setnvalue(ra, (long) nvalue(rb) ^ (long) nvalue(rc));
        }
        break;
      }
#endif
    }
  }
}


