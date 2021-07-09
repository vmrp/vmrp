

//#define lparser_c

#include "mr.h"

#include "mr_code.h"
#include "mr_debug.h"
#include "mr_func.h"
#include "mr_lex.h"
#include "mr_mem.h"
#include "mr_object.h"
#include "mr_opcodes.h"
#include "mr_parser.h"
#include "mr_state.h"
#include "mr_string.h"




#define getlocvar(fs, i)	((fs)->f->locvars[(fs)->actvar[i]])


#define enterlevel(ls)	if (++(ls)->nestlevel > MRP_MAXPARSERLEVEL) \
		mr_X_syntaxerror(ls, "too many syntax levels");
#define leavelevel(ls)	((ls)->nestlevel--)


/*
** nodes for block list (list of active blocks)
*/
typedef struct BlockCnt {
  struct BlockCnt *previous;  /* chain */
  int breaklist;  /* list of jumps out of this loop */
  int nactvar;  /* # active local variables outside the breakable structure */
  int upval;  /* true if some variable in the block is an upvalue */
  int isbreakable;  /* true if `block' is a loop */
} BlockCnt;



/*
** prototypes for recursive non-terminal functions
*/
static void chunk (LexState *ls);
static void expr (LexState *ls, expdesc *v);



static void next (LexState *ls) {
   LUADBGPRINTF("next start");

  ls->lastline = ls->linenumber;
  if (ls->lookahead.token != TK_EOS) {  /* is there a look-ahead token? */
    ls->t = ls->lookahead;  /* use this one */
    ls->lookahead.token = TK_EOS;  /* and discharge it */
  }
  else
  {
     LUADBGPRINTF("before next mr_X_lex");

    ls->t.token = mr_X_lex(ls, &ls->t.seminfo);  /* read next token */
  }

  LUADBGPRINTF("next end");
}


static void lookahead (LexState *ls) {
  mrp_assert(ls->lookahead.token == TK_EOS);
  ls->lookahead.token = mr_X_lex(ls, &ls->lookahead.seminfo);
}


static void error_expected (LexState *ls, int token) {
  mr_X_syntaxerror(ls,
         mr_O_pushfstring(ls->L, "`%s' expected", mr_X_token2str(ls, token)));
}


static int testnext (LexState *ls, int c) {
  if (ls->t.token == c) {
    next(ls);
    return 1;
  }
  else return 0;
}


static void check (LexState *ls, int c) {
  if (!testnext(ls, c))
    error_expected(ls, c);
}


#define check_condition(ls,c,msg)	{ if (!(c)) mr_X_syntaxerror(ls, msg); }



static void check_match (LexState *ls, int what, int who, int where) {
  if (!testnext(ls, what)) {
    if (where == ls->linenumber)
      error_expected(ls, what);
    else {
      mr_X_syntaxerror(ls, mr_O_pushfstring(ls->L,
             "`%s' expected (to close `%s' at line %d)",
              mr_X_token2str(ls, what), mr_X_token2str(ls, who), where));
    }
  }
}


static TString *str_checkname (LexState *ls) {
  TString *ts;
  check_condition(ls, (ls->t.token == TK_NAME), "<name> expected");
  ts = ls->t.seminfo.ts;
  next(ls);
   LUADBGPRINTF("After str_checkname next");
  return ts;
}


static void init_exp (expdesc *e, expkind k, int i) {
  e->f = e->t = NO_JUMP;
  e->k = k;
  e->info = i;
}


static void codestring (LexState *ls, expdesc *e, TString *s) {
  init_exp(e, VK, mr_K_stringK(ls->fs, s));
}


static void checkname(LexState *ls, expdesc *e) {
  codestring(ls, e, str_checkname(ls));
}


static int mr_I_registerlocalvar (LexState *ls, TString *varname) {
  FuncState *fs = ls->fs;
  Proto *f = fs->f;
  mr_M_growvector(ls->L, f->locvars, fs->nlocvars, f->sizelocvars,
                  LocVar, MAX_INT, "");
  f->locvars[fs->nlocvars].varname = varname;
  return fs->nlocvars++;
}


static void new_localvar (LexState *ls, TString *name, int n) {
  FuncState *fs = ls->fs;
  mr_X_checklimit(ls, fs->nactvar+n+1, MAXVARS, "local variables");
  fs->actvar[fs->nactvar+n] = mr_I_registerlocalvar(ls, name);
}


static void adjustlocalvars (LexState *ls, int nvars) {
  FuncState *fs = ls->fs;
  fs->nactvar += nvars;
  for (; nvars; nvars--) {
    getlocvar(fs, fs->nactvar - nvars).startpc = fs->pc;
  }
}


static void removevars (LexState *ls, int tolevel) {
  FuncState *fs = ls->fs;
  while (fs->nactvar > tolevel)
    getlocvar(fs, --fs->nactvar).endpc = fs->pc;
}


static void new_localvarstr (LexState *ls, const char *name, int n) {
  new_localvar(ls, mr_S_new(ls->L, name), n);
}


static void create_local (LexState *ls, const char *name) {
  new_localvarstr(ls, name, 0);
  adjustlocalvars(ls, 1);
}


static int indexupvalue (FuncState *fs, TString *name, expdesc *v) {
  int i;
  Proto *f = fs->f;
  for (i=0; i<f->nups; i++) {
    if (fs->upvalues[i].k == v->k && fs->upvalues[i].info == v->info) {
      mrp_assert(fs->f->upvalues[i] == name);
      return i;
    }
  }
  /* new one */
  mr_X_checklimit(fs->ls, f->nups + 1, MAXUPVALUES, "upvalues");
  mr_M_growvector(fs->L, fs->f->upvalues, f->nups, fs->f->sizeupvalues,
                  TString *, MAX_INT, "");
  fs->f->upvalues[f->nups] = name;
  fs->upvalues[f->nups] = *v;
  return f->nups++;
}


static int searchvar (FuncState *fs, TString *n) {
  int i;
  for (i=fs->nactvar-1; i >= 0; i--) {
    if (n == getlocvar(fs, i).varname)
      return i;
  }
  return -1;  /* not found */
}


static void markupval (FuncState *fs, int level) {
  BlockCnt *bl = fs->bl;
  while (bl && bl->nactvar > level) bl = bl->previous;
  if (bl) bl->upval = 1;
}


static void singlevarmr_aux (FuncState *fs, TString *n, expdesc *var, int base) {
  if (fs == NULL)  /* no more levels? */
    init_exp(var, VGLOBAL, NO_REG);  /* default is global variable */
  else {
    int v = searchvar(fs, n);  /* look up at current level */
    if (v >= 0) {
      init_exp(var, VLOCAL, v);
      if (!base)
        markupval(fs, v);  /* local will be used as an upval */
    }
    else {  /* not found at current level; try upper one */
      singlevarmr_aux(fs->prev, n, var, 0);
      if (var->k == VGLOBAL) {
        if (base)
          var->info = mr_K_stringK(fs, n);  /* info points to global name */
      }
      else {  /* LOCAL or UPVAL */
        var->info = indexupvalue(fs, n, var);
        var->k = VUPVAL;  /* upvalue in this level */
      }
    }
  }
}


static TString *singlevar (LexState *ls, expdesc *var, int base) {
  TString *varname = str_checkname(ls);
   LUADBGPRINTF("After singlevar str_checkname");
  singlevarmr_aux(ls->fs, varname, var, base);
   LUADBGPRINTF("After singlevar singlevarmr_aux");
  return varname;
}


static void adjust_assign (LexState *ls, int nvars, int nexps, expdesc *e) {
  FuncState *fs = ls->fs;
  int extra = nvars - nexps;
  if (e->k == VCALL) {
    extra++;  /* includes call itself */
    if (extra <= 0) extra = 0;
    else mr_K_reserveregs(fs, extra-1);
    mr_K_setcallreturns(fs, e, extra);  /* call provides the difference */
  }
  else {
    if (e->k != VVOID) mr_K_exp2nextreg(fs, e);  /* close last expression */
    if (extra > 0) {
      int reg = fs->freereg;
      mr_K_reserveregs(fs, extra);
      mr_K_nil(fs, reg, extra);
    }
  }
}


static void code_params (LexState *ls, int nparams, int dots) {
  FuncState *fs = ls->fs;
  adjustlocalvars(ls, nparams);
  mr_X_checklimit(ls, fs->nactvar, MAXPARAMS, "parameters");
  fs->f->numparams = cast(lu_byte, fs->nactvar);
  fs->f->is_vararg = cast(lu_byte, dots);
  if (dots)
    create_local(ls, "arg");
  mr_K_reserveregs(fs, fs->nactvar);  /* reserve register for parameters */
}


static void enterblock (FuncState *fs, BlockCnt *bl, int isbreakable) {
  bl->breaklist = NO_JUMP;
  bl->isbreakable = isbreakable;
  bl->nactvar = fs->nactvar;
  bl->upval = 0;
  bl->previous = fs->bl;
  fs->bl = bl;
  mrp_assert(fs->freereg == fs->nactvar);
}


static void leaveblock (FuncState *fs) {
  BlockCnt *bl = fs->bl;
  fs->bl = bl->previous;
  removevars(fs->ls, bl->nactvar);
  if (bl->upval)
    mr_K_codeABC(fs, OP_CLOSE, bl->nactvar, 0, 0);
  mrp_assert(bl->nactvar == fs->nactvar);
  fs->freereg = fs->nactvar;  /* free registers */
  mr_K_patchtohere(fs, bl->breaklist);
}


static void pushclosure (LexState *ls, FuncState *func, expdesc *v) {
  FuncState *fs = ls->fs;
  Proto *f = fs->f;
  int i;
  mr_M_growvector(ls->L, f->p, fs->np, f->sizep, Proto *,
                  MAXARG_Bx, "constant table overflow");
  f->p[fs->np++] = func->f;
  init_exp(v, VRELOCABLE, mr_K_codeABx(fs, OP_CLOSURE, 0, fs->np-1));
  for (i=0; i<func->f->nups; i++) {
    OpCode o = (func->upvalues[i].k == VLOCAL) ? OP_MOVE : OP_GETUPVAL;
    mr_K_codeABC(fs, o, 0, func->upvalues[i].info, 0);
  }
}


static void open_func (LexState *ls, FuncState *fs) {
  Proto *f = mr_F_newproto(ls->L);
  fs->f = f;
  fs->prev = ls->fs;  /* linked list of funcstates */
  fs->ls = ls;
  fs->L = ls->L;
  ls->fs = fs;
  fs->pc = 0;
  fs->lasttarget = 0;
  fs->jpc = NO_JUMP;
  fs->freereg = 0;
  fs->nk = 0;
  fs->h = mr_H_new(ls->L, 0, 0);
  fs->np = 0;
  fs->nlocvars = 0;
  fs->nactvar = 0;
  fs->bl = NULL;
  f->source = ls->source;
  f->maxstacksize = 2;  /* registers 0/1 are always valid */
}


static void close_func (LexState *ls) {
  mrp_State *L = ls->L;
  FuncState *fs = ls->fs;
  Proto *f = fs->f;
  removevars(ls, 0);
  mr_K_codeABC(fs, OP_RETURN, 0, 1, 0);  /* final return */
  mr_M_reallocvector(L, f->code, f->sizecode, fs->pc, Instruction);
  f->sizecode = fs->pc;
  mr_M_reallocvector(L, f->lineinfo, f->sizelineinfo, fs->pc, int);
  f->sizelineinfo = fs->pc;
  mr_M_reallocvector(L, f->k, f->sizek, fs->nk, TObject);
  f->sizek = fs->nk;
  mr_M_reallocvector(L, f->p, f->sizep, fs->np, Proto *);
  f->sizep = fs->np;
  mr_M_reallocvector(L, f->locvars, f->sizelocvars, fs->nlocvars, LocVar);
  f->sizelocvars = fs->nlocvars;
  mr_M_reallocvector(L, f->upvalues, f->sizeupvalues, f->nups, TString *);
  f->sizeupvalues = f->nups;
  mrp_assert(mr_G_checkcode(f));
  mrp_assert(fs->bl == NULL);
  ls->fs = fs->prev;
}


Proto *mr_Y_parser (mrp_State *L, ZIO *z, Mbuffer *buff) {
  struct LexState lexstate;
  struct FuncState funcstate;
  lexstate.buff = buff;
  lexstate.nestlevel = 0;
  mr_X_setinput(L, &lexstate, z, mr_S_new(L, zname(z)));
   LUADBGPRINTF("After mr_Y_parser mr_X_setinput");

  open_func(&lexstate, &funcstate);
   LUADBGPRINTF("After mr_Y_parser open_func");

  next(&lexstate);  /* read first token */
   LUADBGPRINTF("After mr_Y_parser next");

  chunk(&lexstate);
   LUADBGPRINTF("After mr_Y_parser chunk");

  check_condition(&lexstate, (lexstate.t.token == TK_EOS), "<eof> expected");
   LUADBGPRINTF("After mr_Y_parser check_condition");

  close_func(&lexstate);
   LUADBGPRINTF("After mr_Y_parser close_func");

  mrp_assert(funcstate.prev == NULL);
  mrp_assert(funcstate.f->nups == 0);
  mrp_assert(lexstate.nestlevel == 0);
  return funcstate.f;
}



/*============================================================*/
/* GRAMMAR RULES */
/*============================================================*/


static void mr_Y_field (LexState *ls, expdesc *v) {
  /* field -> ['.' | ':'] NAME */
  FuncState *fs = ls->fs;
  expdesc key;
  mr_K_exp2anyreg(fs, v);
  next(ls);  /* skip the dot or colon */
  checkname(ls, &key);
  mr_K_indexed(fs, v, &key);
}


static void mr_Y_index (LexState *ls, expdesc *v) {
  /* index -> '[' expr ']' */
  next(ls);  /* skip the '[' */
  expr(ls, v);
  mr_K_exp2val(ls->fs, v);
  check(ls, ']');
}


/*
** {======================================================================
** Rules for Constructors
** =======================================================================
*/


struct ConsControl {
  expdesc v;  /* last list item read */
  expdesc *t;  /* table descriptor */
  int nh;  /* total number of `record' elements */
  int na;  /* total number of array elements */
  int tostore;  /* number of array elements pending to be stored */
};


static void recfield (LexState *ls, struct ConsControl *cc) {
  /* recfield -> (NAME | `['exp1`]') = exp1 */
  FuncState *fs = ls->fs;
  int reg = ls->fs->freereg;
  expdesc key, val;
  if (ls->t.token == TK_NAME) {
    mr_X_checklimit(ls, cc->nh, MAX_INT, "items in a constructor");
    cc->nh++;
    checkname(ls, &key);
  }
  else  /* ls->t.token == '[' */
    mr_Y_index(ls, &key);
  check(ls, '=');
  mr_K_exp2RK(fs, &key);
  expr(ls, &val);
  mr_K_codeABC(fs, OP_SETTABLE, cc->t->info, mr_K_exp2RK(fs, &key),
                                             mr_K_exp2RK(fs, &val));
  fs->freereg = reg;  /* free registers */
}


static void closelistfield (FuncState *fs, struct ConsControl *cc) {
  if (cc->v.k == VVOID) return;  /* there is no list item */
  mr_K_exp2nextreg(fs, &cc->v);
  cc->v.k = VVOID;
  if (cc->tostore == LFIELDS_PER_FLUSH) {
    mr_K_codeABx(fs, OP_SETLIST, cc->t->info, cc->na-1);  /* flush */
    cc->tostore = 0;  /* no more items pending */
    fs->freereg = cc->t->info + 1;  /* free registers */
  }
}


static void lastlistfield (FuncState *fs, struct ConsControl *cc) {
  if (cc->tostore == 0) return;
  if (cc->v.k == VCALL) {
    mr_K_setcallreturns(fs, &cc->v, MRP_MULTRET);
    mr_K_codeABx(fs, OP_SETLISTO, cc->t->info, cc->na-1);
  }
  else {
    if (cc->v.k != VVOID)
      mr_K_exp2nextreg(fs, &cc->v);
    mr_K_codeABx(fs, OP_SETLIST, cc->t->info, cc->na-1);
  }
  fs->freereg = cc->t->info + 1;  /* free registers */
}


static void listfield (LexState *ls, struct ConsControl *cc) {
  expr(ls, &cc->v);
  mr_X_checklimit(ls, cc->na, MAXARG_Bx, "items in a constructor");
  cc->na++;
  cc->tostore++;
}


static void constructor (LexState *ls, expdesc *t) {
  /* constructor -> ?? */
  FuncState *fs = ls->fs;
  int line = ls->linenumber;
  int pc = mr_K_codeABC(fs, OP_NEWTABLE, 0, 0, 0);
  struct ConsControl cc;
  cc.na = cc.nh = cc.tostore = 0;
  cc.t = t;
  init_exp(t, VRELOCABLE, pc);
  init_exp(&cc.v, VVOID, 0);  /* no value (yet) */
  mr_K_exp2nextreg(ls->fs, t);  /* fix it at stack top (for gc) */
  check(ls, '{');
  do {
    mrp_assert(cc.v.k == VVOID || cc.tostore > 0);
    testnext(ls, ';');  /* compatibility only */
    if (ls->t.token == '}') break;
    closelistfield(fs, &cc);
    switch(ls->t.token) {
      case TK_NAME: {  /* may be listfields or recfields */
        lookahead(ls);
        if (ls->lookahead.token != '=')  /* expression? */
          listfield(ls, &cc);
        else
          recfield(ls, &cc);
        break;
      }
      case '[': {  /* constructor_item -> recfield */
        recfield(ls, &cc);
        break;
      }
      default: {  /* constructor_part -> listfield */
        listfield(ls, &cc);
        break;
      }
    }
  } while (testnext(ls, ',') || testnext(ls, ';'));
  check_match(ls, '}', '{', line);
  lastlistfield(fs, &cc);
  SETARG_B(fs->f->code[pc], mr_O_int2fb(cc.na)); /* set initial array size */
  SETARG_C(fs->f->code[pc], mr_O_log2(cc.nh)+1);  /* set initial table size */
}

/* }====================================================================== */



static void parlist (LexState *ls) {
  /* parlist -> [ param { `,' param } ] */
  int nparams = 0;
  int dots = 0;
  if (ls->t.token != ')') {  /* is `parlist' not empty? */
    do {
      switch (ls->t.token) {
        case TK_DOTS: dots = 1; next(ls); break;
        case TK_NAME: new_localvar(ls, str_checkname(ls), nparams++); break;
        default: mr_X_syntaxerror(ls, "<name> or `...' expected");
      }
    } while (!dots && testnext(ls, ','));
  }
  code_params(ls, nparams, dots);
}


static void body (LexState *ls, expdesc *e, int needself, int line) {
  /* body ->  `(' parlist `)' chunk END */
  FuncState new_fs;
  open_func(ls, &new_fs);
  new_fs.f->lineDefined = line;
  check(ls, '(');
  if (needself)
    create_local(ls, "self");
  parlist(ls);
  check(ls, ')');
  chunk(ls);
  check_match(ls, TK_END, TK_FUNCTION, line);
  close_func(ls);
  pushclosure(ls, &new_fs, e);
}


static int explist1 (LexState *ls, expdesc *v) {
  /* explist1 -> expr { `,' expr } */
  int n = 1;  /* at least one expression */
  expr(ls, v);
  while (testnext(ls, ',')) {
    mr_K_exp2nextreg(ls->fs, v);
    expr(ls, v);
    n++;
  }
  return n;
}


static void funcargs (LexState *ls, expdesc *f) {
  FuncState *fs = ls->fs;
  expdesc args;
  int base, nparams;
  int line = ls->linenumber;
  switch (ls->t.token) {
    case '(': {  /* funcargs -> `(' [ explist1 ] `)' */
      if (line != ls->lastline)
        mr_X_syntaxerror(ls,"ambiguous syntax (function call x new statement)");
      next(ls);
      if (ls->t.token == ')')  /* arg list is empty? */
        args.k = VVOID;
      else {
        explist1(ls, &args);
        mr_K_setcallreturns(fs, &args, MRP_MULTRET);
      }
      check_match(ls, ')', '(', line);
      break;
    }
    case '{': {  /* funcargs -> constructor */
      constructor(ls, &args);
      break;
    }
    case TK_STRING: {  /* funcargs -> STRING */
      codestring(ls, &args, ls->t.seminfo.ts);
      next(ls);  /* must use `seminfo' before `next' */
      break;
    }
    default: {
      mr_X_syntaxerror(ls, "function arguments expected");
      return;
    }
  }
  mrp_assert(f->k == VNONRELOC);
  base = f->info;  /* base register for call */
  if (args.k == VCALL)
    nparams = MRP_MULTRET;  /* open call */
  else {
    if (args.k != VVOID)
      mr_K_exp2nextreg(fs, &args);  /* close last argument */
    nparams = fs->freereg - (base+1);
  }
  init_exp(f, VCALL, mr_K_codeABC(fs, OP_CALL, base, nparams+1, 2));
  mr_K_fixline(fs, line);
  fs->freereg = base+1;  /* call remove function and arguments and leaves
                            (unless changed) one result */
}




/*
** {======================================================================
** Expression parsing
** =======================================================================
*/


static void prefixexp (LexState *ls, expdesc *v) {
  /* prefixexp -> NAME | '(' expr ')' */
  switch (ls->t.token) {
    case '(': {
      int line = ls->linenumber;
      next(ls);
      expr(ls, v);
      check_match(ls, ')', '(', line);
      mr_K_dischargevars(ls->fs, v);
      return;
    }
    case TK_NAME: {
      singlevar(ls, v, 1);
      return;
    }
#ifdef MRP_COMPATUPSYNTAX
    case '%': {  /* for compatibility only */
      TString *varname;
      int line = ls->linenumber;
      next(ls);  /* skip `%' */
      varname = singlevar(ls, v, 1);
      if (v->k != VUPVAL)
        mr_X_errorline(ls, "global upvalues are obsolete",
                           getstr(varname), line);
      return;
    }
#endif
    default: {
      mr_X_syntaxerror(ls, "unexpected symbol");
      return;
    }
  }
}


static void primaryexp (LexState *ls, expdesc *v) {
  /* primaryexp ->
        prefixexp { `.' NAME | `[' exp `]' | `:' NAME funcargs | funcargs } */
  FuncState *fs = ls->fs;
  prefixexp(ls, v);
  for (;;) {
    switch (ls->t.token) {
      case '.': {  /* field */
        mr_Y_field(ls, v);
        break;
      }
      case '[': {  /* `[' exp1 `]' */
        expdesc key;
        mr_K_exp2anyreg(fs, v);
        mr_Y_index(ls, &key);
        mr_K_indexed(fs, v, &key);
        break;
      }
      case ':': {  /* `:' NAME funcargs */
        expdesc key;
        next(ls);
        checkname(ls, &key);
        mr_K_self(fs, v, &key);
        funcargs(ls, v);
        break;
      }
      case '(': case TK_STRING: case '{': {  /* funcargs */
        mr_K_exp2nextreg(fs, v);
        funcargs(ls, v);
        break;
      }
      default: return;
    }
  }
}


static void simpleexp (LexState *ls, expdesc *v) {
  /* simpleexp -> NUMBER | STRING | NIL | constructor | FUNCTION body
               | primaryexp */
  switch (ls->t.token) {
    case TK_NUMBER: {
      init_exp(v, VK, mr_K_numberK(ls->fs, ls->t.seminfo.r));
      next(ls);  /* must use `seminfo' before `next' */
      break;
    }
    case TK_STRING: {
      codestring(ls, v, ls->t.seminfo.ts);
      next(ls);  /* must use `seminfo' before `next' */
      break;
    }
    case TK_NIL: {
      init_exp(v, VNIL, 0);
      next(ls);
      break;
    }
    case TK_TRUE: {
      init_exp(v, VTRUE, 0);
      next(ls);
      break;
    }
    case TK_FALSE: {
      init_exp(v, VFALSE, 0);
      next(ls);
      break;
    }
    case '{': {  /* constructor */
      constructor(ls, v);
      break;
    }
    case TK_FUNCTION: {
      next(ls);
      body(ls, v, 0, ls->linenumber);
      break;
    }
    default: {
      primaryexp(ls, v);
      break;
    }
  }
}


static UnOpr getunopr (int op) {
  switch (op) {
    case TK_NOT: return OPR_NOT;
    case '-': return OPR_MINUS;
#if 1
    case '~': return OPR_BNOT;
#endif
    default: return OPR_NOUNOPR;
  }
}


static BinOpr getbinopr (int op) {
  switch (op) {
    case '+': return OPR_ADD;
    case '-': return OPR_SUB;
    case '*': return OPR_MULT;
    case '/': return OPR_DIV;
    case '#': return OPR_POW;
    case TK_CONCAT: return OPR_CONCAT;
    case TK_NE: return OPR_NE;
    case TK_EQ: return OPR_EQ;
    case '<': return OPR_LT;
    case TK_LE: return OPR_LE;
    case '>': return OPR_GT;
    case TK_GE: return OPR_GE;
    case TK_AND: return OPR_AND;
    case TK_OR: return OPR_OR;
#if 1
    case '&': return OPR_BAND;
    case '|': return OPR_BOR;
    case '^': return OPR_BXOR;
#endif
    default: return OPR_NOBINOPR;
  }
}


static const struct {
  lu_byte left;  /* left priority for each binary operator */
  lu_byte right; /* right priority */
} priority[] = {  /* ORDER OPR */
   {6, 6}, {6, 6}, {7, 7}, {7, 7},  /* arithmetic */
   {10, 9}, {5, 4},                 /* power and concat (right associative) */
   {3, 3}, {3, 3},                  /* equality */
   {3, 3}, {3, 3}, {3, 3}, {3, 3},  /* order */
#if 0
   {2, 2}, {1, 1}                   /* logical (and/or) */
#else
   {2, 2}, {1, 1},                  /* logical (and/or) */
   {6, 6}, {6, 6}, {6, 6}           /* bit-wise (band/bor/bxor) */
#endif
};

#define UNARY_PRIORITY	8  /* priority for unary operators */


/*
** subexpr -> (simplexep | unop subexpr) { binop subexpr }
** where `binop' is any binary operator with a priority higher than `limit'
*/
static BinOpr subexpr (LexState *ls, expdesc *v, int limit) {
  BinOpr op;
  UnOpr uop;
  enterlevel(ls);
  uop = getunopr(ls->t.token);
  if (uop != OPR_NOUNOPR) {
    next(ls);
    subexpr(ls, v, UNARY_PRIORITY);
    mr_K_prefix(ls->fs, uop, v);
  }
  else simpleexp(ls, v);
  /* expand while operators have priorities higher than `limit' */
  op = getbinopr(ls->t.token);
  while (op != OPR_NOBINOPR && cast(int, priority[op].left) > limit) {
    expdesc v2;
    BinOpr nextop;
    next(ls);
    mr_K_infix(ls->fs, op, v);
    /* read sub-expression with higher priority */
    nextop = subexpr(ls, &v2, cast(int, priority[op].right));
    mr_K_posfix(ls->fs, op, v, &v2);
    op = nextop;
  }
  leavelevel(ls);
  return op;  /* return first untreated operator */
}


static void expr (LexState *ls, expdesc *v) {
  subexpr(ls, v, -1);
}

/* }==================================================================== */



/*
** {======================================================================
** Rules for Statements
** =======================================================================
*/


static int block_follow (int token) {
  switch (token) {
    case TK_ELSE: case TK_ELSEIF: case TK_END:
    case TK_UNTIL: case TK_EOS:
      return 1;
    default: return 0;
  }
}


static void block (LexState *ls) {
  /* block -> chunk */
  FuncState *fs = ls->fs;
  BlockCnt bl;
  enterblock(fs, &bl, 0);
  chunk(ls);
  mrp_assert(bl.breaklist == NO_JUMP);
  leaveblock(fs);
}


/*
** structure to chain all variables in the left-hand side of an
** assignment
*/
struct LHS_assign {
  struct LHS_assign *prev;
  expdesc v;  /* variable (global, local, upvalue, or indexed) */
};


/*
** check whether, in an assignment to a local variable, the local variable
** is needed in a previous assignment (to a table). If so, save original
** local value in a safe place and use this safe copy in the previous
** assignment.
*/
static void check_conflict (LexState *ls, struct LHS_assign *lh, expdesc *v) {
  FuncState *fs = ls->fs;
  int extra = fs->freereg;  /* eventual position to save local variable */
  int conflict = 0;
  for (; lh; lh = lh->prev) {
    if (lh->v.k == VINDEXED) {
      if (lh->v.info == v->info) {  /* conflict? */
        conflict = 1;
        lh->v.info = extra;  /* previous assignment will use safe copy */
      }
      if (lh->v.aux == v->info) {  /* conflict? */
        conflict = 1;
        lh->v.aux = extra;  /* previous assignment will use safe copy */
      }
    }
  }
  if (conflict) {
    mr_K_codeABC(fs, OP_MOVE, fs->freereg, v->info, 0);  /* make copy */
    mr_K_reserveregs(fs, 1);
  }
}


static void assignment (LexState *ls, struct LHS_assign *lh, int nvars) {
  expdesc e;
  check_condition(ls, VLOCAL <= lh->v.k && lh->v.k <= VINDEXED,
                      "syntax error");
  if (testnext(ls, ',')) {  /* assignment -> `,' primaryexp assignment */
    struct LHS_assign nv;
    nv.prev = lh;
    primaryexp(ls, &nv.v);
    if (nv.v.k == VLOCAL)
      check_conflict(ls, lh, &nv.v);
    assignment(ls, &nv, nvars+1);
  }
  else {  /* assignment -> `=' explist1 */
    int nexps;
    check(ls, '=');
    nexps = explist1(ls, &e);
    if (nexps != nvars) {
      adjust_assign(ls, nvars, nexps, &e);
      if (nexps > nvars)
        ls->fs->freereg -= nexps - nvars;  /* remove extra values */
    }
    else {
      mr_K_setcallreturns(ls->fs, &e, 1);  /* close last expression */
      mr_K_storevar(ls->fs, &lh->v, &e);
      return;  /* avoid default */
    }
  }
  init_exp(&e, VNONRELOC, ls->fs->freereg-1);  /* default assignment */
  mr_K_storevar(ls->fs, &lh->v, &e);
}


static void cond (LexState *ls, expdesc *v) {
  /* cond -> exp */
  expr(ls, v);  /* read condition */
  if (v->k == VNIL) v->k = VFALSE;  /* `falses' are all equal here */
  mr_K_goiftrue(ls->fs, v);
  mr_K_patchtohere(ls->fs, v->t);
}


/*
** The while statement optimizes its code by coding the condition
** after its body (and thus avoiding one jump in the loop).
*/

/*
** maximum size of expressions for optimizing `while' code
*/
#ifndef MAXEXPWHILE
#define MAXEXPWHILE	100
#endif

/*
** the call `mr_K_goiffalse' may grow the size of an expression by
** at most this:
*/
#define EXTRAEXP	5

static void whilestat (LexState *ls, int line) {
  /* whilestat -> WHILE cond DO block END */
  Instruction codeexp[MAXEXPWHILE + EXTRAEXP];
  int lineexp;
  int i;
  int sizeexp;
  FuncState *fs = ls->fs;
  int whileinit, blockinit, expinit;
  expdesc v;
  BlockCnt bl;
  next(ls);  /* skip WHILE */
  whileinit = mr_K_jump(fs);  /* jump to condition (which will be moved) */
  expinit = mr_K_getlabel(fs);
  expr(ls, &v);  /* parse condition */
  if (v.k == VK) v.k = VTRUE;  /* `trues' are all equal here */
  lineexp = ls->linenumber;
  mr_K_goiffalse(fs, &v);
  mr_K_concat(fs, &v.f, fs->jpc);
  fs->jpc = NO_JUMP;
  sizeexp = fs->pc - expinit;  /* size of expression code */
  if (sizeexp > MAXEXPWHILE) 
    mr_X_syntaxerror(ls, "`while' condition too complex");
  for (i = 0; i < sizeexp; i++)  /* save `exp' code */
    codeexp[i] = fs->f->code[expinit + i];
  fs->pc = expinit;  /* remove `exp' code */
  enterblock(fs, &bl, 1);
  check(ls, TK_DO);
  blockinit = mr_K_getlabel(fs);
  block(ls);
  mr_K_patchtohere(fs, whileinit);  /* initial jump jumps to here */
  /* move `exp' back to code */
  if (v.t != NO_JUMP) v.t += fs->pc - expinit;
  if (v.f != NO_JUMP) v.f += fs->pc - expinit;
  for (i=0; i<sizeexp; i++)
    mr_K_code(fs, codeexp[i], lineexp);
  check_match(ls, TK_END, TK_WHILE, line);
  leaveblock(fs);
  mr_K_patchlist(fs, v.t, blockinit);  /* true conditions go back to loop */
  mr_K_patchtohere(fs, v.f);  /* false conditions finish the loop */
}


static void repeatstat (LexState *ls, int line) {
  /* repeatstat -> REPEAT block UNTIL cond */
  FuncState *fs = ls->fs;
  int repeat_init = mr_K_getlabel(fs);
  expdesc v;
  BlockCnt bl;
  enterblock(fs, &bl, 1);
  next(ls);
  block(ls);
  check_match(ls, TK_UNTIL, TK_REPEAT, line);
  cond(ls, &v);
  mr_K_patchlist(fs, v.f, repeat_init);
  leaveblock(fs);
}


static int exp1 (LexState *ls) {
  expdesc e;
  int k;
  expr(ls, &e);
  k = e.k;
  mr_K_exp2nextreg(ls->fs, &e);
  return k;
}


static void forbody (LexState *ls, int base, int line, int nvars, int isnum) {
  BlockCnt bl;
  FuncState *fs = ls->fs;
  int prep, endfor;
  adjustlocalvars(ls, nvars);  /* scope for all variables */
  check(ls, TK_DO);
  enterblock(fs, &bl, 1);  /* loop block */
  prep = mr_K_getlabel(fs);
  block(ls);
  mr_K_patchtohere(fs, prep-1);
  endfor = (isnum) ? mr_K_codeAsBx(fs, OP_FORLOOP, base, NO_JUMP) :
                     mr_K_codeABC(fs, OP_TFORLOOP, base, 0, nvars - 3);
  mr_K_fixline(fs, line);  /* pretend that `OP_FOR' starts the loop */
  mr_K_patchlist(fs, (isnum) ? endfor : mr_K_jump(fs), prep);
  leaveblock(fs);
}


static void fornum (LexState *ls, TString *varname, int line) {
  /* fornum -> NAME = exp1,exp1[,exp1] DO body */
  FuncState *fs = ls->fs;
  int base = fs->freereg;
  new_localvar(ls, varname, 0);
  new_localvarstr(ls, "(for limit)", 1);
  new_localvarstr(ls, "(for step)", 2);
  check(ls, '=');
  exp1(ls);  /* initial value */
  check(ls, ',');
  exp1(ls);  /* limit */
  if (testnext(ls, ','))
    exp1(ls);  /* optional step */
  else {  /* default step = 1 */
    mr_K_codeABx(fs, OP_LOADK, fs->freereg, mr_K_numberK(fs, 1));
    mr_K_reserveregs(fs, 1);
  }
  mr_K_codeABC(fs, OP_SUB, fs->freereg - 3, fs->freereg - 3, fs->freereg - 1);
  mr_K_jump(fs);
  forbody(ls, base, line, 3, 1);
}


static void forlist (LexState *ls, TString *indexname) {
  /* forlist -> NAME {,NAME} IN explist1 DO body */
  FuncState *fs = ls->fs;
  expdesc e;
  int nvars = 0;
  int line;
  int base = fs->freereg;
  new_localvarstr(ls, "(for generator)", nvars++);
  new_localvarstr(ls, "(for state)", nvars++);
  new_localvar(ls, indexname, nvars++);
  while (testnext(ls, ','))
    new_localvar(ls, str_checkname(ls), nvars++);
  check(ls, TK_IN);
  line = ls->linenumber;
  adjust_assign(ls, nvars, explist1(ls, &e), &e);
  mr_K_checkstack(fs, 3);  /* extra space to call generator */
  mr_K_codeAsBx(fs, OP_TFORPREP, base, NO_JUMP);
  forbody(ls, base, line, nvars, 0);
}


static void forstat (LexState *ls, int line) {
  /* forstat -> fornum | forlist */
  FuncState *fs = ls->fs;
  TString *varname;
  BlockCnt bl;
  enterblock(fs, &bl, 0);  /* block to control variable scope */
  next(ls);  /* skip `for' */
  varname = str_checkname(ls);  /* first variable name */
  switch (ls->t.token) {
    case '=': fornum(ls, varname, line); break;
    case ',': case TK_IN: forlist(ls, varname); break;
    default: mr_X_syntaxerror(ls, "`=' or `in' expected");
  }
  check_match(ls, TK_END, TK_FOR, line);
  leaveblock(fs);
}


static void test_then_block (LexState *ls, expdesc *v) {
  /* test_then_block -> [IF | ELSEIF] cond THEN block */
  next(ls);  /* skip IF or ELSEIF */
  cond(ls, v);
  check(ls, TK_THEN);
  block(ls);  /* `then' part */
}


static void ifstat (LexState *ls, int line) {
  /* ifstat -> IF cond THEN block {ELSEIF cond THEN block} [ELSE block] END */
  FuncState *fs = ls->fs;
  expdesc v;
  int escapelist = NO_JUMP;
  test_then_block(ls, &v);  /* IF cond THEN block */
  while (ls->t.token == TK_ELSEIF) {
    mr_K_concat(fs, &escapelist, mr_K_jump(fs));
    mr_K_patchtohere(fs, v.f);
    test_then_block(ls, &v);  /* ELSEIF cond THEN block */
  }
  if (ls->t.token == TK_ELSE) {
    mr_K_concat(fs, &escapelist, mr_K_jump(fs));
    mr_K_patchtohere(fs, v.f);
    next(ls);  /* skip ELSE (after patch, for correct line info) */
    block(ls);  /* `else' part */
  }
  else
    mr_K_concat(fs, &escapelist, v.f);
  mr_K_patchtohere(fs, escapelist);
  check_match(ls, TK_END, TK_IF, line);
}


static void localfunc (LexState *ls) {
  expdesc v, b;
  FuncState *fs = ls->fs;
  new_localvar(ls, str_checkname(ls), 0);
  init_exp(&v, VLOCAL, fs->freereg);
  mr_K_reserveregs(fs, 1);
  adjustlocalvars(ls, 1);
  body(ls, &b, 0, ls->linenumber);
  mr_K_storevar(fs, &v, &b);
  /* debug information will only see the variable after this point! */
  getlocvar(fs, fs->nactvar - 1).startpc = fs->pc;
}


static void localstat (LexState *ls) {
  /* stat -> LOCAL NAME {`,' NAME} [`=' explist1] */
  int nvars = 0;
  int nexps;
  expdesc e;
  do {
    new_localvar(ls, str_checkname(ls), nvars++);
  } while (testnext(ls, ','));
  if (testnext(ls, '='))
    nexps = explist1(ls, &e);
  else {
    e.k = VVOID;
    nexps = 0;
  }
  adjust_assign(ls, nvars, nexps, &e);
  adjustlocalvars(ls, nvars);
}


static int funcname (LexState *ls, expdesc *v) {
  /* funcname -> NAME {field} [`:' NAME] */
  int needself = 0;
  singlevar(ls, v, 1);
  while (ls->t.token == '.')
    mr_Y_field(ls, v);
  if (ls->t.token == ':') {
    needself = 1;
    mr_Y_field(ls, v);
  }
  return needself;
}


static void funcstat (LexState *ls, int line) {
  /* funcstat -> FUNCTION funcname body */
  int needself;
  expdesc v, b;
  next(ls);  /* skip FUNCTION */
  needself = funcname(ls, &v);
  body(ls, &b, needself, line);
  mr_K_storevar(ls->fs, &v, &b);
  mr_K_fixline(ls->fs, line);  /* definition `happens' in the first line */
}


static void exprstat (LexState *ls) {
  /* stat -> func | assignment */
  FuncState *fs = ls->fs;
  struct LHS_assign v;
  primaryexp(ls, &v.v);
  if (v.v.k == VCALL) {  /* stat -> func */
    mr_K_setcallreturns(fs, &v.v, 0);  /* call statement uses no results */
  }
  else {  /* stat -> assignment */
    v.prev = NULL;
    assignment(ls, &v, 1);
  }
}


static void retstat (LexState *ls) {
  /* stat -> RETURN explist */
  FuncState *fs = ls->fs;
  expdesc e;
  int first, nret;  /* registers with returned values */
  next(ls);  /* skip RETURN */
  if (block_follow(ls->t.token) || ls->t.token == ';')
    first = nret = 0;  /* return no values */
  else {
    nret = explist1(ls, &e);  /* optional return values */
    if (e.k == VCALL) {
      mr_K_setcallreturns(fs, &e, MRP_MULTRET);
      if (nret == 1) {  /* tail call? */
        SET_OPCODE(getcode(fs,&e), OP_TAILCALL);
        mrp_assert(GETARG_A(getcode(fs,&e)) == fs->nactvar);
      }
      first = fs->nactvar;
      nret = MRP_MULTRET;  /* return all values */
    }
    else {
      if (nret == 1)  /* only one single value? */
        first = mr_K_exp2anyreg(fs, &e);
      else {
        mr_K_exp2nextreg(fs, &e);  /* values must go to the `stack' */
        first = fs->nactvar;  /* return all `active' values */
        mrp_assert(nret == fs->freereg - first);
      }
    }
  }
  mr_K_codeABC(fs, OP_RETURN, first, nret+1, 0);
}


static void breakstat (LexState *ls) {
  /* stat -> BREAK [NAME] */
  FuncState *fs = ls->fs;
  BlockCnt *bl = fs->bl;
  int upval = 0;
  next(ls);  /* skip BREAK */
  while (bl && !bl->isbreakable) {
    upval |= bl->upval;
    bl = bl->previous;
  }
  if (!bl)
    mr_X_syntaxerror(ls, "no loop to break");
  if (upval)
    mr_K_codeABC(fs, OP_CLOSE, bl->nactvar, 0, 0);
  mr_K_concat(fs, &bl->breaklist, mr_K_jump(fs));
}


static int statement (LexState *ls) {
  int line = ls->linenumber;  /* may be needed for error messages */
  switch (ls->t.token) {
    case TK_IF: {  /* stat -> ifstat */
      ifstat(ls, line);
      return 0;
    }
    case TK_WHILE: {  /* stat -> whilestat */
      whilestat(ls, line);
      return 0;
    }
    case TK_DO: {  /* stat -> DO block END */
      next(ls);  /* skip DO */
      block(ls);
      check_match(ls, TK_END, TK_DO, line);
      return 0;
    }
    case TK_FOR: {  /* stat -> forstat */
      forstat(ls, line);
      return 0;
    }
    case TK_REPEAT: {  /* stat -> repeatstat */
      repeatstat(ls, line);
      return 0;
    }
    case TK_FUNCTION: {
      funcstat(ls, line);  /* stat -> funcstat */
      return 0;
    }
    case TK_LOCAL: {  /* stat -> localstat */
      next(ls);  /* skip LOCAL */
      if (testnext(ls, TK_FUNCTION))  /* local function? */
        localfunc(ls);
      else
        localstat(ls);
      return 0;
    }
    case TK_RETURN: {  /* stat -> retstat */
      retstat(ls);
      return 1;  /* must be last statement */
    }
    case TK_BREAK: {  /* stat -> breakstat */
      breakstat(ls);
      return 1;  /* must be last statement */
    }
    default: {
      exprstat(ls);
      return 0;  /* to avoid warnings */
    }
  }
}


static void chunk (LexState *ls) {
  /* chunk -> { stat [`;'] } */
  int islast = 0;
   LUADBGPRINTF("chunk start");


  enterlevel(ls);
  while (!islast && !block_follow(ls->t.token)) {
    islast = statement(ls);
    testnext(ls, ';');
    mrp_assert(ls->fs->freereg >= ls->fs->nactvar);
    ls->fs->freereg = ls->fs->nactvar;  /* free registers */
  }
  leavelevel(ls);

  LUADBGPRINTF("chunk end");
}

/* }====================================================================== */
