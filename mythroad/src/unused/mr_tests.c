/*
** $Id: ltests.c,v 1.158 2003/04/07 14:35:00 roberto Exp $
** Internal Module for Debugging of the Lua Implementation
** See Copyright Notice in lua.h
*/



//#define ltests_c

#include "mr.h"

#include "mr_api.h"
#include "mr_auxlib.h"
#include "mr_code.h"
#include "mr_debug.h"
#include "mr_do.h"
#include "mr_func.h"
#include "mr_mem.h"
#include "mr_opcodes.h"
#include "mr_state.h"
#include "mr_string.h"
#include "mr_table.h"
#include "mr_lib.h"



/*
** The whole module only makes sense with MRP_DEBUG on
*/
#ifdef MRP_DEBUG


#define mrp_pushintegral(L,i)	mrp_pushnumber(L, cast(mrp_Number, (i)))


static mrp_State *mrp_state = NULL;

int islocked = 0;


#define func_at(L,k)	(L->ci->base+(k) - 1)


static void setnameval (mrp_State *L, const char *name, int val) {
  mrp_pushstring(L, name);
  mrp_pushintegral(L, val);
  mrp_settable(L, -3);
}


/*
** {======================================================================
** Controlled version for realloc.
** =======================================================================
*/

#define MARK		0x55  /* 01010101 (a nice pattern) */

#ifndef EXTERNMEMCHECK
/* full memory check */
#define HEADER	(sizeof(L_Umaxalign)) /* ensures maximum alignment for HEADER */
#define MARKSIZE	16  /* size of marks after each block */
#define blockhead(b)	(cast(char *, b) - HEADER)
#define setsize(newblock, size)	(*cast(size_t *, newblock) = size)
#define checkblocksize(b, size) (size == (*cast(size_t *, blockhead(b))))
#define fillmem(mem,size)	MEMSET(mem, -MARK, size)
#else
/* external memory check: don't do it twice */
#define HEADER		0
#define MARKSIZE	0
#define blockhead(b)	(b)
#define setsize(newblock, size)	/* empty */
#define checkblocksize(b,size)	(1)
#define fillmem(mem,size)	/* empty */
#endif

unsigned long memdebug_numblocks = 0;
unsigned long memdebug_total = 0;
unsigned long memdebug_maxmem = 0;
unsigned long memdebug_memlimit = ULONG_MAX;


static void *checkblock (void *block, size_t size) {
  void *b = blockhead(block);
  int i;
  for (i=0;i<MARKSIZE;i++)
    mrp_assert(*(cast(char *, b)+HEADER+size+i) == MARK+i); /* corrupted block? */
  return b;
}


static void freeblock (void *block, size_t size) {
  if (block) {
    mrp_assert(checkblocksize(block, size));
    block = checkblock(block, size);
    fillmem(block, size+HEADER+MARKSIZE);  /* erase block */
    free(block);  /* free original block */
    memdebug_numblocks--;
    memdebug_total -= size;
  }
}


void *debug_realloc (void *block, size_t oldsize, size_t size) {
  mrp_assert(oldsize == 0 || checkblocksize(block, oldsize));
  /* ISO does not specify what realloc(NULL, 0) does */
  mrp_assert(block != NULL || size > 0);
  if (size == 0) {
    freeblock(block, oldsize);
    return NULL;
  }
  else if (size > oldsize && memdebug_total+size-oldsize > memdebug_memlimit)
    return NULL;  /* to test memory allocation errors */
  else {
    void *newblock;
    int i;
    size_t realsize = HEADER+size+MARKSIZE;
    size_t commonsize = (oldsize < size) ? oldsize : size;
    if (realsize < size) return NULL;  /* overflow! */
    newblock = malloc(realsize);  /* alloc a new block */
    if (newblock == NULL) return NULL;
    if (block) {
      MEMCPY(cast(char *, newblock)+HEADER, block, commonsize);//ouli brew
      freeblock(block, oldsize);  /* erase (and check) old copy */
    }
    /* initialize new part of the block with something `weird' */
    fillmem(cast(char *, newblock)+HEADER+commonsize, size-commonsize);
    memdebug_total += size;
    if (memdebug_total > memdebug_maxmem)
      memdebug_maxmem = memdebug_total;
    memdebug_numblocks++;
    setsize(newblock, size);
    for (i=0;i<MARKSIZE;i++)
      *(cast(char *, newblock)+HEADER+size+i) = cast(char, MARK+i);
    return cast(char *, newblock)+HEADER;
  }
}


/* }====================================================================== */



/*
** {======================================================
** Disassembler
** =======================================================
*/


static char *buildop (Proto *p, int pc, char *buff) {
  Instruction i = p->code[pc];
  OpCode o = GET_OPCODE(i);
  const char *name = mr_P_opnames[o];
  int line = getline(p, pc);
  sprintf(buff, "(%4d) %4d - ", line, pc);
  switch (getOpMode(o)) {  
    case iABC:
      sprintf(buff+STRLEN(buff), "%-12s%4d %4d %4d", name,
              GETARG_A(i), GETARG_B(i), GETARG_C(i));
      break;
    case iABx:
      sprintf(buff+STRLEN(buff), "%-12s%4d %4d", name, GETARG_A(i), GETARG_Bx(i));
      break;
    case iAsBx:
      sprintf(buff+STRLEN(buff), "%-12s%4d %4d", name, GETARG_A(i), GETARG_sBx(i));
      break;
  }
  return buff;
}


#if 0
void mr_I_printcode (Proto *pt, int size) {
  int pc;
  for (pc=0; pc<size; pc++) {
    char buff[100];
    printf("%s\n", buildop(pt, pc, buff));
  }
  printf("-------\n");
}
#endif


static int listcode (mrp_State *L) {
  int pc;
  Proto *p;
  mr_L_argcheck(L, mrp_isfunction(L, 1) && !mrp_iscfunction(L, 1),
                 1, "Mythroad function expected");
  p = clvalue(func_at(L, 1))->l.p;
  mrp_newtable(L);
  setnameval(L, "maxstack", p->maxstacksize);
  setnameval(L, "numparams", p->numparams);
  for (pc=0; pc<p->sizecode; pc++) {
    char buff[100];
    mrp_pushintegral(L, pc+1);
    mrp_pushstring(L, buildop(p, pc, buff));
    mrp_settable(L, -3);
  }
  return 1;
}


static int listk (mrp_State *L) {
  Proto *p;
  int i;
  mr_L_argcheck(L, mrp_isfunction(L, 1) && !mrp_iscfunction(L, 1),
                 1, "Mythroad function expected");
  p = clvalue(func_at(L, 1))->l.p;
  mrp_newtable(L);
  for (i=0; i<p->sizek; i++) {
    mrp_pushintegral(L, i+1);
    mr_A_pushobject(L, p->k+i);
    mrp_settable(L, -3);
  }
  return 1;
}


static int listlocals (mrp_State *L) {
  Proto *p;
  int pc = mr_L_checkint(L, 2) - 1;
  int i = 0;
  const char *name;
  mr_L_argcheck(L, mrp_isfunction(L, 1) && !mrp_iscfunction(L, 1),
                 1, "Mythroad function expected");
  p = clvalue(func_at(L, 1))->l.p;
  while ((name = mr_F_getlocalname(p, ++i, pc)) != NULL)
    mrp_pushstring(L, name);
  return i-1;
}

/* }====================================================== */




static int get_limits (mrp_State *L) {
  mrp_newtable(L);
  setnameval(L, "BITS_INT", BITS_INT);
  setnameval(L, "LFPF", LFIELDS_PER_FLUSH);
  setnameval(L, "MAXVARS", MAXVARS);
  setnameval(L, "MAXPARAMS", MAXPARAMS);
  setnameval(L, "MAXSTACK", MAXSTACK);
  setnameval(L, "MAXUPVALUES", MAXUPVALUES);
  return 1;
}


static int mem_query (mrp_State *L) {
  if (mrp_isnone(L, 1)) {
    mrp_pushintegral(L, memdebug_total);
    mrp_pushintegral(L, memdebug_numblocks);
    mrp_pushintegral(L, memdebug_maxmem);
    return 3;
  }
  else {
    memdebug_memlimit = mr_L_checkint(L, 1);
    return 0;
  }
}


static int hash_query (mrp_State *L) {
  if (mrp_isnone(L, 2)) {
    mr_L_argcheck(L, mrp_type(L, 1) == MRP_TSTRING, 1, "string expected");
    mrp_pushintegral(L, tsvalue(func_at(L, 1))->tsv.hash);
  }
  else {
    TObject *o = func_at(L, 1);
    Table *t;
    mr_L_checktype(L, 2, MRP_TTABLE);
    t = hvalue(func_at(L, 2));
    mrp_pushintegral(L, mr_H_mainposition(t, o) - t->node);
  }
  return 1;
}


static int stacklevel (mrp_State *L) {
  unsigned long a = 0;
  mrp_pushintegral(L, (int)(L->top - L->stack));
  mrp_pushintegral(L, (int)(L->stack_last - L->stack));
  mrp_pushintegral(L, (int)(L->ci - L->base_ci));
  mrp_pushintegral(L, (int)(L->end_ci - L->base_ci));
  mrp_pushintegral(L, (unsigned long)&a);
  return 5;
}


static int table_query (mrp_State *L) {
  const Table *t;
  int i = mr_L_optint(L, 2, -1);
  mr_L_checktype(L, 1, MRP_TTABLE);
  t = hvalue(func_at(L, 1));
  if (i == -1) {
    mrp_pushintegral(L, t->sizearray);
    mrp_pushintegral(L, sizenode(t));
    mrp_pushintegral(L, t->firstfree - t->node);
  }
  else if (i < t->sizearray) {
    mrp_pushintegral(L, i);
    mr_A_pushobject(L, &t->array[i]);
    mrp_pushnil(L); 
  }
  else if ((i -= t->sizearray) < sizenode(t)) {
    if (!ttisnil(gval(gnode(t, i))) ||
        ttisnil(gkey(gnode(t, i))) ||
        ttisnumber(gkey(gnode(t, i)))) {
      mr_A_pushobject(L, gkey(gnode(t, i)));
    }
    else
      mrp_pushstring(L, "<undef>");
    mr_A_pushobject(L, gval(gnode(t, i)));
    if (t->node[i].next)
      mrp_pushintegral(L, t->node[i].next - t->node);
    else
      mrp_pushnil(L);
  }
  return 3;
}


static int string_query (mrp_State *L) {
  stringtable *tb = &G(L)->strt;
  int s = mr_L_optint(L, 2, 0) - 1;
  if (s==-1) {
    mrp_pushintegral(L ,tb->nuse);
    mrp_pushintegral(L ,tb->size);
    return 2;
  }
  else if (s < tb->size) {
    GCObject *ts;
    int n = 0;
    for (ts = tb->hash[s]; ts; ts = ts->gch.next) {
      setsvalue2s(L->top, gcotots(ts));
      incr_top(L);
      n++;
    }
    return n;
  }
  return 0;
}


static int tref (mrp_State *L) {
  int level = mrp_gettop(L);
  int lock = mr_L_optint(L, 2, 1);
  mr_L_checkany(L, 1);
  mrp_pushvalue(L, 1);
  mrp_pushintegral(L, mrp_ref(L, lock));
  assert(mrp_gettop(L) == level+1);  /* +1 for result */
  return 1;
}

static int getref (mrp_State *L) {
  int level = mrp_gettop(L);
  mrp_getref(L, mr_L_checkint(L, 1));
  assert(mrp_gettop(L) == level+1);
  return 1;
}

static int unref (mrp_State *L) {
  int level = mrp_gettop(L);
  mrp_unref(L, mr_L_checkint(L, 1));
  assert(mrp_gettop(L) == level);
  return 0;
}

static int metatable (mrp_State *L) {
  mr_L_checkany(L, 1);
  if (mrp_isnone(L, 2)) {
    if (mrp_getmetatable(L, 1) == 0)
      mrp_pushnil(L);
  }
  else {
    mrp_settop(L, 2);
    mr_L_checktype(L, 2, MRP_TTABLE);
    mrp_setmetatable(L, 1);
  }
  return 1;
}


static int upvalue (mrp_State *L) {
  int n = mr_L_checkint(L, 2);
  mr_L_checktype(L, 1, MRP_TFUNCTION);
  if (mrp_isnone(L, 3)) {
    const char *name = mrp_getupvalue(L, 1, n);
    if (name == NULL) return 0;
    mrp_pushstring(L, name);
    return 2;
  }
  else {
    const char *name = mrp_setupvalue(L, 1, n);
    mrp_pushstring(L, name);
    return 1;
  }
}


static int newuserdata (mrp_State *L) {
  size_t size = mr_L_checkint(L, 1);
  char *p = cast(char *, mrp_newuserdata(L, size));
  while (size--) *p++ = '\0';
  return 1;
}


static int pushuserdata (mrp_State *L) {
  mrp_pushlightuserdata(L, cast(void *, mr_L_checkint(L, 1)));
  return 1;
}


static int udataval (mrp_State *L) {
  mrp_pushintegral(L, cast(int, mrp_touserdata(L, 1)));
  return 1;
}


static int doonnewstack (mrp_State *L) {
  mrp_State *L1 = mrp_newthread(L);
  size_t l;
  const char *s = mr_L_checklstring(L, 1, &l);
  int status = mr_L_loadbuffer(L1, s, l, s);
  if (status == 0)
    status = mrp_pcall(L1, 0, 0, 0);
  mrp_pushintegral(L, status);
  return 1;
}


static int s2d (mrp_State *L) {
  mrp_pushnumber(L, *cast(const double *, mr_L_checkstring(L, 1)));
  return 1;
}

static int d2s (mrp_State *L) {
  double d = mr_L_checknumber(L, 1);
  mrp_pushlstring(L, cast(char *, &d), sizeof(d));
  return 1;
}


static int newstate (mrp_State *L) {
  mrp_State *L1 = mrp_open();
  if (L1) {
    mrp_userstateopen(L1);  /* init lock */
    mrp_pushintegral(L, (unsigned long)L1);
  }
  else
    mrp_pushnil(L);
  return 1;
}


static int loadlib (mrp_State *L) {
  static const mr_L_reg libs[] = {
    {"mathlibopen", mrp_open_math},
    {"strlibopen", mrp_open_string},
    {"iolibopen", mrp_open_file},
    {"tablibopen", mrp_open_table},
    {"dblibopen", mrp_open_debug},
    {"baselibopen", mrp_open_base},
    {NULL, NULL}
  }; 
  mrp_State *L1 = cast(mrp_State *,
                       cast(unsigned long, mr_L_checknumber(L, 1)));
  mrp_pushvalue(L1, MRP_GLOBALSINDEX);
  mr_L_openlib(L1, NULL, libs, 0);
  return 0;
}

static int closestate (mrp_State *L) {
  mrp_State *L1 = cast(mrp_State *, cast(unsigned long, mr_L_checknumber(L, 1)));
  mrp_close(L1);
  mrp_unlock(L);  /* close cannot unlock that */
  return 0;
}

static int doremote (mrp_State *L) {
  mrp_State *L1 = cast(mrp_State *,cast(unsigned long,mr_L_checknumber(L, 1)));
  size_t lcode;
  const char *code = mr_L_checklstring(L, 2, &lcode);
  int status;
  mrp_settop(L1, 0);
  status = mr_L_loadbuffer(L1, code, lcode, code);
  if (status == 0)
    status = mrp_pcall(L1, 0, MRP_MULTRET, 0);
  if (status != 0) {
    mrp_pushnil(L);
    mrp_pushintegral(L, status);
    mrp_pushstring(L, mrp_tostring(L1, -1));
    return 3;
  }
  else {
    int i = 0;
    while (!mrp_isnone(L1, ++i))
      mrp_pushstring(L, mrp_tostring(L1, i));
    mrp_pop(L1, i-1);
    return i-1;
  }
}


static int log2_mr_aux (mrp_State *L) {
  mrp_pushintegral(L, mr_O_log2(mr_L_checkint(L, 1)));
  return 1;
}

static int int2fb_mr_aux (mrp_State *L) {
  int b = mr_O_int2fb(mr_L_checkint(L, 1));
  mrp_pushintegral(L, b);
  mrp_pushintegral(L, fb2int(b));
  return 2;
}


static int test_do (mrp_State *L) {
  const char *p = mr_L_checkstring(L, 1);
  if (*p == '@')
    mrp_dofile(L, p+1);
  else
    mrp_dostring(L, p);
  return mrp_gettop(L);
}



/*
** {======================================================
** function to test the API with C. It interprets a kind of assembler
** language with calls to the API, so the test can be driven by Lua code
** =======================================================
*/

static const char *const delimits = " \t\n,;";

static void skip (const char **pc) {
  while (**pc != '\0' && STRCHR(delimits, **pc)) (*pc)++;
}

static int getnum_mr_aux (mrp_State *L, const char **pc) {
  int res = 0;
  int sig = 1;
  skip(pc);
  if (**pc == '.') {
    res = cast(int, mrp_tonumber(L, -1));
    mrp_pop(L, 1);
    (*pc)++;
    return res;
  }
  else if (**pc == '-') {
    sig = -1;
    (*pc)++;
  }
  while (mr_isdigit(cast(int, **pc))) res = res*10 + (*(*pc)++) - '0';
  return sig*res;
}
  
static const char *getname_mr_aux (char *buff, const char **pc) {
  int i = 0;
  skip(pc);
  while (**pc != '\0' && !STRCHR(delimits, **pc))
    buff[i++] = *(*pc)++;
  buff[i] = '\0';
  return buff;
}


#define EQ(s1)	(STRCMP(s1, inst) == 0)

#define getnum	(getnum_mr_aux(L, &pc))
#define getname	(getname_mr_aux(buff, &pc))


static int testC (mrp_State *L) {
  char buff[30];
  const char *pc = mr_L_checkstring(L, 1);
  for (;;) {
    const char *inst = getname;
    if EQ("") return 0;
    else if EQ("isnumber") {
      mrp_pushintegral(L, mrp_isnumber(L, getnum));
    }
    else if EQ("isstring") {
      mrp_pushintegral(L, mrp_isstring(L, getnum));
    }
    else if EQ("istable") {
      mrp_pushintegral(L, mrp_istable(L, getnum));
    }
    else if EQ("iscfunction") {
      mrp_pushintegral(L, mrp_iscfunction(L, getnum));
    }
    else if EQ("isfunction") {
      mrp_pushintegral(L, mrp_isfunction(L, getnum));
    }
    else if EQ("isuserdata") {
      mrp_pushintegral(L, mrp_isuserdata(L, getnum));
    }
    else if EQ("isudataval") {
      mrp_pushintegral(L, mrp_islightuserdata(L, getnum));
    }
    else if EQ("isnil") {
      mrp_pushintegral(L, mrp_isnil(L, getnum));
    }
    else if EQ("isnull") {
      mrp_pushintegral(L, mrp_isnone(L, getnum));
    }
    else if EQ("tonumber") {
      mrp_pushnumber(L, mrp_tonumber(L, getnum));
    }
    else if EQ("tostring") {
      const char *s = mrp_tostring(L, getnum);
      mrp_pushstring(L, s);
    }
    else if EQ("strlen") {
      mrp_pushintegral(L, mrp_strlen(L, getnum));
    }
    else if EQ("tocfunction") {
      mrp_pushcfunction(L, mrp_tocfunction(L, getnum));
    }
    else if EQ("return") {
      return getnum;
    }
    else if EQ("gettop") {
      mrp_pushintegral(L, mrp_gettop(L));
    }
    else if EQ("settop") {
      mrp_settop(L, getnum);
    }
    else if EQ("pop") {
      mrp_pop(L, getnum);
    }
    else if EQ("pushnum") {
      mrp_pushintegral(L, getnum);
    }
    else if EQ("pushnil") {
      mrp_pushnil(L);
    }
    else if EQ("pushbool") {
      mrp_pushboolean(L, getnum);
    }
    else if EQ("tobool") {
      mrp_pushintegral(L, mrp_toboolean(L, getnum));
    }
    else if EQ("pushvalue") {
      mrp_pushvalue(L, getnum);
    }
    else if EQ("pushcclosure") {
      mrp_pushcclosure(L, testC, getnum);
    }
    else if EQ("pushupvalues") {
      mrp_pushupvalues(L);
    }
    else if EQ("remove") {
      mrp_remove(L, getnum);
    }
    else if EQ("insert") {
      mrp_insert(L, getnum);
    }
    else if EQ("replace") {
      mrp_replace(L, getnum);
    }
    else if EQ("gettable") {
      mrp_gettable(L, getnum);
    }
    else if EQ("settable") {
      mrp_settable(L, getnum);
    }
    else if EQ("next") {
      mrp_next(L, -2);
    }
    else if EQ("concat") {
      mrp_concat(L, getnum);
    }
    else if EQ("lessthan") {
      int a = getnum;
      mrp_pushboolean(L, mrp_lessthan(L, a, getnum));
    }
    else if EQ("equal") {
      int a = getnum;
      mrp_pushboolean(L, mrp_equal(L, a, getnum));
    }
    else if EQ("rawcall") {
      int narg = getnum;
      int nres = getnum;
      mrp_call(L, narg, nres);
    }
    else if EQ("call") {
      int narg = getnum;
      int nres = getnum;
      mrp_pcall(L, narg, nres, 0);
    }
    else if EQ("loadstring") {
      size_t sl;
      const char *s = mr_L_checklstring(L, getnum, &sl);
      mr_L_loadbuffer(L, s, sl, s);
    }
    else if EQ("loadfile") {
      mr_L_loadfile(L, mr_L_checkstring(L, getnum));
    }
    else if EQ("setmetatable") {
      mrp_setmetatable(L, getnum);
    }
    else if EQ("getmetatable") {
      if (mrp_getmetatable(L, getnum) == 0)
        mrp_pushnil(L);
    }
    else if EQ("type") {
      mrp_pushstring(L, mrp_typename(L, mrp_type(L, getnum)));
    }
    else if EQ("getn") {
      int i = getnum;
      mrp_pushintegral(L, mr_L_getn(L, i));
    }
    else if EQ("setn") {
      int i = getnum;
      int n = cast(int, mrp_tonumber(L, -1));
      mr_L_setn(L, i, n);
      mrp_pop(L, 1);
    }
    else mr_L_error(L, "unknown instruction %s", buff);
  }
  return 0;
}

/* }====================================================== */


/*
** {======================================================
** tests for yield inside hooks
** =======================================================
*/

static void yieldf (mrp_State *L, mrp_Debug *ar) {
  mrp_yield(L, 0);
}

static int setyhook (mrp_State *L) {
  if (mrp_isnoneornil(L, 1))
    mrp_sethook(L, NULL, 0, 0);  /* turn off hooks */
  else {
    const char *smask = mr_L_checkstring(L, 1);
    int count = mr_L_optint(L, 2, 0);
    int mask = 0;
    if (STRCHR(smask, 'l')) mask |= MRP_MASKLINE;
    if (count > 0) mask |= MRP_MASKCOUNT;
    mrp_sethook(L, yieldf, mask, count);
  }
  return 0;
}


static int coresume (mrp_State *L) {
  int status;
  mrp_State *co = mrp_tothread(L, 1);
  mr_L_argcheck(L, co, 1, "coroutine expected");
  status = mrp_resume(co, 0);
  if (status != 0) {
    mrp_pushboolean(L, 0);
    mrp_insert(L, -2);
    return 2;  /* return false + error message */
  }
  else {
    mrp_pushboolean(L, 1);
    return 1;
  }
}

/* }====================================================== */



static const struct mr_L_reg tests_funcs[] = {
  {"hash", hash_query},
  {"limits", get_limits},
  {"listcode", listcode},
  {"listk", listk},
  {"listlocals", listlocals},
  {"loadlib", loadlib},
  {"stacklevel", stacklevel},
  {"querystr", string_query},
  {"querytab", table_query},
  {"doit", test_do},
  {"testC", testC},
  {"ref", tref},
  {"getref", getref},
  {"unref", unref},
  {"d2s", d2s},
  {"s2d", s2d},
  {"metatable", metatable},
  {"upvalue", upvalue},
  {"newuserdata", newuserdata},
  {"pushuserdata", pushuserdata},
  {"udataval", udataval},
  {"doonnewstack", doonnewstack},
  {"newstate", newstate},
  {"closestate", closestate},
  {"doremote", doremote},
  {"log2", log2_mr_aux},
  {"int2fb", int2fb_mr_aux},
  {"totalmem", mem_query},
  {"resume", coresume},
  {"setyhook", setyhook},
  {NULL, NULL}
};


static void fim (void) {
  if (!islocked)
    mrp_close(mrp_state);
  mrp_assert(memdebug_numblocks == 0);
  mrp_assert(memdebug_total == 0);
}


static int l_panic (mrp_State *L) {
  UNUSED(L);
  fprintf(stderr, "unable to recover; exiting\n");
  return 0;
}


int mr_B_opentests (mrp_State *L) {
  mrp_atpanic(L, l_panic);
  mrp_userstateopen(L);  /* init lock */
  mrp_state = L;  /* keep first state to be opened */
  mr_L_openlib(L, "T", tests_funcs, 0);
  atexit(fim);
  return 0;
}


#undef main
int main (int argc, char *argv[]) {
  char *limit = getenv("MEMLIMIT");
  if (limit)
    memdebug_memlimit = strtoul(limit, NULL, 10);
  l_main(argc, argv);
  return 0;
}

#endif
