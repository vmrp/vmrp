/*
** $Id: lbaselib.c,v 1.130b 2003/04/03 13:35:34 roberto Exp $
** Basic library
** See Copyright Notice in lua.h
*/


#define lbaselib_c


#include "../../include/mr_auxlib.h"
#include "../../include/mr_lib.h"


static mr_L_reg base_funcs[29];
static mr_L_reg co_funcs[6];


/*
** If your system does not support `stdout', you can just remove this function.
** If you need, you can define your own `print' function, following this
** model but changing `fputs' to put the strings at a proper place
** (a console window or a log file, for instance).
*/
static int mr_B_print (mrp_State *L) {
  int n = mrp_gettop(L);  /* number of arguments */
  int i;
  mrp_getglobal(L, "tostring");
  for (i=1; i<=n; i++) {
    const char *s;
    mrp_pushvalue(L, -1);  /* function to be called */
    mrp_pushvalue(L, i);   /* value to print */
    mrp_call(L, 1, 1);
    s = mrp_tostring(L, -1);  /* get result */
    if (s == NULL)
      return mr_L_error(L, "`tostring' must return a string to `print'");
//    if (i>1) fputs("\t", stdout);
//    fputs(s, stdout);    //ouli
    //if (i>1) MRDBGPRINTF("\t");  //ouli brew ,at phone,print auto add return(line change)
    if (STRLEN(s)>190){
      MRDBGPRINTF("print string too long!");
      mr_L_error(L, "attemp to print too long string!");
      return 0;
    }else{
       MRDBGPRINTF(s);
    }
    mrp_pop(L, 1);  /* pop result */
  }
  //fputs("\n", stdout);
  //MRDBGPRINTF("\n");  //ouli brew ,at phone,print auto add return(line change)
  return 0;
}


static int mr_B_tonumber (mrp_State *L) {
  int base = mr_L_optint(L, 2, 10);
  if (base == 10) {  /* standard conversion */
    mr_L_checkany(L, 1);
    if (mrp_isnumber(L, 1)) {
      mrp_pushnumber(L, mrp_tonumber(L, 1));
      return 1;
    }
  }
  else {
    const char *s1 = mr_L_checkstring(L, 1);
    char *s2;
    unsigned long n;
    mr_L_argcheck(L, 2 <= base && base <= 36, 2, "base out of range");
    n = STRTOUL(s1, &s2, base);  //ouli brew
    if (s1 != s2) {  /* at least one valid digit? */
      while (mr_isspace((unsigned char)(*s2))) s2++;  /* skip trailing spaces */
      if (*s2 == '\0') {  /* no invalid trailing characters? */
        mrp_pushnumber(L, (mrp_Number)n);
        return 1;
      }
    }
  }
  mrp_pushnil(L);  /* else not a number */
  return 1;
}


static int mr_B_error (mrp_State *L) {
  int level = mr_L_optint(L, 2, 1);
  mr_L_checkany(L, 1);
  if (!mrp_isstring(L, 1) || level == 0)
    mrp_pushvalue(L, 1);  /* propagate error message without changes */
  else {  /* add extra information */
    mr_L_where(L, level);
    mrp_pushvalue(L, 1);
    mrp_concat(L, 2);
  }
  return mrp_error(L);
}


static int mr_B_getmetatable (mrp_State *L) {
  mr_L_checkany(L, 1);
  if (!mrp_getmetatable(L, 1)) {
    mrp_pushnil(L);
    return 1;  /* no metatable */
  }
  mr_L_getmetafield(L, 1, "__metatable");
  return 1;  /* returns either __metatable field (if present) or metatable */
}


static int mr_B_setmetatable (mrp_State *L) {
  int t = mrp_type(L, 2);
  mr_L_checktype(L, 1, MRP_TTABLE);
  mr_L_argcheck(L, t == MRP_TNIL || t == MRP_TTABLE, 2,
                    "nil or table expected");
  if (mr_L_getmetafield(L, 1, "__metatable"))
    mr_L_error(L, "cannot change a protected metatable");
  mrp_settop(L, 2);
  mrp_setmetatable(L, 1);
  return 1;
}


static void getfunc (mrp_State *L) {
  if (mrp_isfunction(L, 1)) mrp_pushvalue(L, 1);
  else {
    mrp_Debug ar;
    int level = mr_L_optint(L, 1, 1);
    mr_L_argcheck(L, level >= 0, 1, "level must be non-negative");
    if (mrp_getstack(L, level, &ar) == 0)
      mr_L_argerror(L, 1, "invalid level");
    mrp_getinfo(L, "f", &ar);
    if (mrp_isnil(L, -1))
      mr_L_error(L, "no function environment for tail call at level %d",
                    level);
  }
}


static int mr_aux_getfenv (mrp_State *L) {
  mrp_getfenv(L, -1);
  mrp_pushliteral(L, "__fenv");
  mrp_rawget(L, -2);
  return !mrp_isnil(L, -1);
}


static int mr_B_getfenv (mrp_State *L) {
  getfunc(L);
  if (!mr_aux_getfenv(L))  /* __fenv not defined? */
    mrp_pop(L, 1);  /* remove it, to return real environment */
  return 1;
}


static int mr_B_setfenv (mrp_State *L) {
  mr_L_checktype(L, 2, MRP_TTABLE);
  getfunc(L);
  if (mr_aux_getfenv(L))  /* __fenv defined? */
    mr_L_error(L, "`setfenv' cannot change a protected environment");
  else
    mrp_pop(L, 2);  /* remove __fenv and real environment table */
  mrp_pushvalue(L, 2);
  if (mrp_isnumber(L, 1) && mrp_tonumber(L, 1) == 0)
    mrp_replace(L, MRP_GLOBALSINDEX);
  else if (mrp_setfenv(L, -2) == 0)
    mr_L_error(L, "`setfenv' cannot change environment of given function");
  return 0;
}


static int mr_B_rawequal (mrp_State *L) {
  mr_L_checkany(L, 1);
  mr_L_checkany(L, 2);
  mrp_pushboolean(L, mrp_rawequal(L, 1, 2));
  return 1;
}


int mr_B_rawget (mrp_State *L) {
  mr_L_checktype(L, 1, MRP_TTABLE);
  mr_L_checkany(L, 2);
  mrp_rawget(L, 1);
  return 1;
}

int mr_B_rawset (mrp_State *L) {
  mr_L_checktype(L, 1, MRP_TTABLE);
  mr_L_checkany(L, 2);
  mr_L_checkany(L, 3);
  mrp_rawset(L, 1);
  return 1;
}

#if 0
static int mr_B_gcinfo (mrp_State *L) {
  mrp_pushnumber(L, (mrp_Number)mrp_getgccount(L));
  mrp_pushnumber(L, (mrp_Number)mrp_getgcthreshold(L));
  return 2;
}
#endif


static int mr_B_collectgarbage (mrp_State *L) {
  mrp_setgcthreshold(L, mr_L_optint(L, 1, 0));
  return 0;
}

static int mr_B_type (mrp_State *L) {
  mr_L_checkany(L, 1);
  mrp_pushstring(L, mrp_typename(L, mrp_type(L, 1)));
  return 1;
}

static int mr_B_short_type (mrp_State *L) {
  mr_L_checkany(L, 1);
  mrp_pushstring(L, mrp_shorttypename(L, mrp_type(L, 1)));
  return 1;
}


int mr_B_next (mrp_State *L) {
  mr_L_checktype(L, 1, MRP_TTABLE);
  mrp_settop(L, 2);  /* create a 2nd argument if there isn't one */
  if (mrp_next(L, 1))
    return 2;
  else {
    mrp_pushnil(L);
    return 1;
  }
}

int mr_B_pairs (mrp_State *L) {
  mr_L_checktype(L, 1, MRP_TTABLE);
  mrp_pushliteral(L, "_next");
  mrp_rawget(L, MRP_GLOBALSINDEX);  /* return generator, */
  mrp_pushvalue(L, 1);  /* state, */
  mrp_pushnil(L);  /* and initial value */
  return 3;
}

int mr_B_ipairs (mrp_State *L) {
  mrp_Number i = mrp_tonumber(L, 2);
  mr_L_checktype(L, 1, MRP_TTABLE);
  if (i == 0 && mrp_isnone(L, 2)) {  /* `for' start? */
    mrp_pushliteral(L, "_iPairs");
    mrp_rawget(L, MRP_GLOBALSINDEX);  /* return generator, */
    mrp_pushvalue(L, 1);  /* state, */
    mrp_pushnumber(L, 0);  /* and initial value */
    return 3;
  }
  else {  /* `for' step */
    i++;  /* next value */
    mrp_pushnumber(L, i);
    mrp_rawgeti(L, 1, (int)i);
    return (mrp_isnil(L, -1)) ? 0 : 2;
  }
}


static int load_mr_aux (mrp_State *L, int status) {
  if (status == 0)  /* OK? */
    return 1;
  else {
    mrp_pushnil(L);
    mrp_insert(L, -2);  /* put before error message */
    return 2;  /* return nil plus error message */
  }
}


static int mr_B_loadstring (mrp_State *L) {
  size_t l;
  const char *s = mr_L_checklstring(L, 1, &l);
  const char *chunkname = mr_L_optstring(L, 2, s);
  return load_mr_aux(L, mr_L_loadbuffer(L, s, l, chunkname));
}


static int mr_B_loadfile (mrp_State *L) {
  const char *fname = mr_L_optstring(L, 1, NULL);
  return load_mr_aux(L, mr_L_loadfile(L, fname));
}


static int mr_B_dofile (mrp_State *L) {
  const char *fname = mr_L_optstring(L, 1, NULL);
  int n = mrp_gettop(L);
  int status = mr_L_loadfile(L, fname);
  if (status != 0) mrp_error(L);
  mrp_call(L, 0, MRP_MULTRET);
  return mrp_gettop(L) - n;
}


static int mr_B_assert (mrp_State *L) {
  mr_L_checkany(L, 1);
  if (!mrp_toboolean(L, 1))
    return mr_L_error(L, "%s", mr_L_optstring(L, 2, "assert() meet false or nil."));
  mrp_settop(L, 1);
  return 1;
}


int mr_B_unpack (mrp_State *L) {
  int n, i;
  mr_L_checktype(L, 1, MRP_TTABLE);
  n = mr_L_getn(L, 1);
  mr_L_checkstack(L, n, "table too big to unpack");
  for (i=1; i<=n; i++)  /* push arg[1...n] */
    mrp_rawgeti(L, 1, i);
  return n;
}


static int mr_B_pcall (mrp_State *L) {
  int status;
  mr_L_checkany(L, 1);
  status = mrp_pcall(L, mrp_gettop(L) - 1, MRP_MULTRET, 0);
  mrp_pushboolean(L, (status == 0));
  mrp_insert(L, 1);
  return mrp_gettop(L);  /* return status + all results */
}


static int mr_B_xpcall (mrp_State *L) {
  int status;
  mr_L_checkany(L, 2);
  mrp_settop(L, 2);
  mrp_insert(L, 1);  /* put error function under function to be called */
  status = mrp_pcall(L, 0, MRP_MULTRET, 1);
  mrp_pushboolean(L, (status == 0));
  mrp_replace(L, 1);
  return mrp_gettop(L);  /* return status + all results */
}


static int mr_B_tostring (mrp_State *L) {
  char buff[128];
  mr_L_checkany(L, 1);
  if (mr_L_callmeta(L, 1, "__str"))  /* is there a metafield? */
    return 1;  /* use its value */
  switch (mrp_type(L, 1)) {
    case MRP_TNUMBER:
      mrp_pushstring(L, mrp_tostring(L, 1));
      return 1;
    case MRP_TSTRING:
      mrp_pushvalue(L, 1);
      return 1;
    case MRP_TBOOLEAN:
      mrp_pushstring(L, (mrp_toboolean(L, 1) ? "true" : "false"));
      return 1;
    case MRP_TTABLE:
      SPRINTF(buff, "table: %p", mrp_topointer(L, 1));//ouli brew
      break;
    case MRP_TFUNCTION:
      SPRINTF(buff, "function: %p", mrp_topointer(L, 1));//ouli brew
      break;
    case MRP_TUSERDATA:
    case MRP_TLIGHTUSERDATA:
      SPRINTF(buff, "object: %p", mrp_touserdata(L, 1));//ouli brew
      break;
    case MRP_TTHREAD:
      SPRINTF(buff, "thread: %p", (void *)mrp_tothread(L, 1));//ouli brew
      break;
    case MRP_TNIL:
      mrp_pushliteral(L, "nil");
      return 1;
  }
  mrp_pushstring(L, buff);
  return 1;
}

#if 0
static int mr_B_newproxy (mrp_State *L) {
  mrp_settop(L, 1);
  mrp_newuserdata(L, 0);  /* create proxy */
  if (mrp_toboolean(L, 1) == 0)
    return 1;  /* no metatable */
  else if (mrp_isboolean(L, 1)) {
    mrp_newtable(L);  /* create a new metatable `m' ... */
    mrp_pushvalue(L, -1);  /* ... and mark `m' as a valid metatable */
    mrp_pushboolean(L, 1);
    mrp_rawset(L, mrp_upvalueindex(1));  /* weaktable[m] = true */
  }
  else {
    int validproxy = 0;  /* to check if weaktable[metatable(u)] == true */
    if (mrp_getmetatable(L, 1)) {
      mrp_rawget(L, mrp_upvalueindex(1));
      validproxy = mrp_toboolean(L, -1);
      mrp_pop(L, 1);  /* remove value */
    }
    mr_L_argcheck(L, validproxy, 1, "boolean or proxy expected");
    mrp_getmetatable(L, 1);  /* metatable is valid; get it */
  }
  mrp_setmetatable(L, 2);
  return 1;
}
#endif


/*
** {======================================================
** `require' function
** =======================================================
*/


/* name of global that holds table with loaded packages */
#define REQTAB		"_MODULE"

/* name of global that holds the search path for packages */
#define MRP_PATH	"MR_PATH"

#ifndef MRP_PATH_SEP
#define MRP_PATH_SEP	';'
#endif

#ifndef MRP_PATH_MARK
#define MRP_PATH_MARK	'?'
#endif

#ifndef MRP_PATH_DEFAULT
#define MRP_PATH_DEFAULT	"?;?.mr"
#endif


#if 0
static const char *getpath (mrp_State *L) {
  const char *path;
  mrp_getglobal(L, MRP_PATH);  /* try global variable */
  path = mrp_tostring(L, -1);
  mrp_pop(L, 1);
  if (path) return path;
  //path = getenv(MRP_PATH);  /* else try environment variable */ //ouli brew
  //if (path) return path;  //ouli brew
  return MRP_PATH_DEFAULT;  /* else use default */
}


static const char *pushnextpath (mrp_State *L, const char *path) {
  const char *l;
  if (*path == '\0') return NULL;  /* no more paths */
  if (*path == MRP_PATH_SEP) path++;  /* skip separator */
  l = STRCHR(path, MRP_PATH_SEP);  /* find next separator */
  if (l == NULL) l = path+STRLEN(path);
  mrp_pushlstring(L, path, l - path);  /* directory name */
  return l;
}


static void pushcomposename (mrp_State *L) {
  const char *path = mrp_tostring(L, -1);
  const char *wild;
  int n = 1;
  while ((wild = STRCHR(path, MRP_PATH_MARK)) != NULL) {
    /* is there stack space for prefix, name, and eventual last sufix? */
    mr_L_checkstack(L, 3, "too many marks in a path component");
    mrp_pushlstring(L, path, wild - path);  /* push prefix */
    mrp_pushvalue(L, 1);  /* push package name (in place of MARK) */
    path = wild + 1;  /* continue after MARK */
    n += 2;
  }
  mrp_pushstring(L, path);  /* push last sufix (`n' already includes this) */
  mrp_concat(L, n);
}

static int mr_B_require (mrp_State *L) {
  const char *path;
  int status = MRP_ERRFILE;  /* not found (yet) */
  mr_L_checkstring(L, 1);
  mrp_settop(L, 1);
  mrp_getglobal(L, REQTAB);
  if (!mrp_istable(L, 2)) return mr_L_error(L, "`" REQTAB "' is not a table");
  path = getpath(L);
  mrp_pushvalue(L, 1);  /* check package's name in book-keeping table */
  mrp_rawget(L, 2);
  if (mrp_toboolean(L, -1))  /* is it there? */
    return 1;  /* package is already loaded; return its result */
  else {  /* must load it */
    while (status == MRP_ERRFILE) {
      mrp_settop(L, 3);  /* reset stack position */
      if ((path = pushnextpath(L, path)) == NULL) break;
      pushcomposename(L);
      status = mr_L_loadfile(L, mrp_tostring(L, -1));  /* try to load it */
    }
  }
  switch (status) {
    case 0: {
      mrp_getglobal(L, "_REQUIREDNAME");  /* save previous name */
      mrp_insert(L, -2);  /* put it below function */
      mrp_pushvalue(L, 1);
      mrp_setglobal(L, "_REQUIREDNAME");  /* set new name */
      mrp_call(L, 0, 1);  /* run loaded module */
      mrp_insert(L, -2);  /* put result below previous name */
      mrp_setglobal(L, "_REQUIREDNAME");  /* reset to previous name */
      if (mrp_isnil(L, -1)) {  /* no/nil return? */
        mrp_pushboolean(L, 1);
        mrp_replace(L, -2);  /* replace to true */
      }
      mrp_pushvalue(L, 1);
      mrp_pushvalue(L, -2);
      mrp_rawset(L, 2);  /* mark it as loaded */
      return 1;  /* return value */
    }
    case MRP_ERRFILE: {  /* file not found */
      return mr_L_error(L, "could not load package `%s' from path `%s'",
                            mrp_tostring(L, 1), getpath(L));
    }
    default: {
      return mr_L_error(L, "error loading package `%s' (%s)",
                           mrp_tostring(L, 1), mrp_tostring(L, -1));
    }
  }
}
#endif

/* }====================================================== */




/*
** {======================================================
** Coroutine library
** =======================================================
*/

static int mr_auxresume (mrp_State *L, mrp_State *co, int narg) {
  int status;
  if (!mrp_checkstack(co, narg))
    mr_L_error(L, "too many arguments to resume");
  mrp_xmove(L, co, narg);
  status = mrp_resume(co, narg);
  if (status == 0) {
    int nres = mrp_gettop(co);
    if (!mrp_checkstack(L, nres))
      mr_L_error(L, "too many results to resume");
    mrp_xmove(co, L, nres);  /* move yielded values */
    return nres;
  }
  else {
   //ouli
    //MRDBGPRINTF(mrp_tostring(L, -1));
   //ouli
    mrp_xmove(co, L, 1);  /* move error message */
    return -1;  /* error flag */
  }
}


static int mr_B_coresume (mrp_State *L) {
  mrp_State *co = mrp_tothread(L, 1);
  int r;
  mr_L_argcheck(L, co, 1, "coroutine expected");
  r = mr_auxresume(L, co, mrp_gettop(L) - 1);
  if (r < 0) {
    mrp_pushboolean(L, 0);
    mrp_insert(L, -2);
    return 2;  /* return false + error message */
  }
  else {
    mrp_pushboolean(L, 1);
    mrp_insert(L, -(r + 1));
    return r + 1;  /* return true + `resume' returns */
  }
}


static int mr_B_mr_auxwrap (mrp_State *L) {
  mrp_State *co = mrp_tothread(L, mrp_upvalueindex(1));
  int r = mr_auxresume(L, co, mrp_gettop(L));
  if (r < 0) {
    if (mrp_isstring(L, -1)) {  /* error object is a string? */
      mr_L_where(L, 1);  /* add extra info */
      mrp_insert(L, -2);
      mrp_concat(L, 2);
    }
    mrp_error(L);  /* propagate error */
  }
  return r;
}


static int mr_B_cocreate (mrp_State *L) {
  mrp_State *NL = mrp_newthread(L);
  mr_L_argcheck(L, mrp_isfunction(L, 1) && !mrp_iscfunction(L, 1), 1,
    "Mythroad function expected");
  mrp_pushvalue(L, 1);  /* move function to top */
  mrp_xmove(L, NL, 1);  /* move function from L to NL */
  return 1;
}


static int mr_B_cowrap (mrp_State *L) {
  mr_B_cocreate(L);
  mrp_pushcclosure(L, mr_B_mr_auxwrap, 1);
  return 1;
}


static int mr_B_yield (mrp_State *L) {
  return mrp_yield(L, mrp_gettop(L));
}


static int mr_B_costatus (mrp_State *L) {
  mrp_State *co = mrp_tothread(L, 1);
  mr_L_argcheck(L, co, 1, "coroutine expected");
  if (L == co) mrp_pushliteral(L, "running");
  else {
    mrp_Debug ar;
    if (mrp_getstack(co, 0, &ar) == 0 && mrp_gettop(co) == 0)
      mrp_pushliteral(L, "dead");
    else
      mrp_pushliteral(L, "suspended");
  }
  return 1;
}



/* }====================================================== */

void mr_baselib_init (void) {
    co_funcs[0].name = "create";
    co_funcs[0].func = mr_B_cocreate;
    co_funcs[1].name = "wrap";
    co_funcs[1].func = mr_B_cowrap;
    co_funcs[2].name = "resume";
    co_funcs[2].func = mr_B_coresume;
    co_funcs[3].name = "yield";
    co_funcs[3].func = mr_B_yield;
    co_funcs[4].name = "status";
    co_funcs[4].func = mr_B_costatus;
    co_funcs[5].name = NULL;
    co_funcs[5].func = NULL;

    base_funcs[0].name ="_error";
    base_funcs[0].func =  mr_B_error;
    base_funcs[1].name ="_getTab";
    base_funcs[1].func = mr_B_getmetatable;
    base_funcs[2].name ="_setTab";
    base_funcs[2].func = mr_B_setmetatable;
    base_funcs[3].name ="_getEnv";
    base_funcs[3].func = mr_B_getfenv;
    base_funcs[4].name ="_setEnv";
    base_funcs[4].func = mr_B_setfenv;
    // base_funcs[].name ="_next";
    // base_funcs[].func = mr_B_next;
    base_funcs[5].name ="_iPairs";
    base_funcs[5].func = mr_B_ipairs;
    // base_funcs[].name ="_pairs";
    // base_funcs[].func = mr_B_pairs;
    base_funcs[6].name ="print";
    base_funcs[6].func = mr_B_print;
    base_funcs[7].name ="_num";
    base_funcs[7].func = mr_B_tonumber;
    base_funcs[8].name ="_str";
    base_funcs[8].func = mr_B_tostring;
    base_funcs[9].name ="_next";
    base_funcs[9].func = mr_B_next;
#ifdef COMPATIBILITY01
    base_funcs[10].name ="tonumber";
    base_funcs[10].func = mr_B_tonumber;
    base_funcs[11].name ="tostring";
    base_funcs[11].func = mr_B_tostring;
    base_funcs[12].name ="type";
    base_funcs[12].func = mr_B_type;
    base_funcs[13].name ="next";
    base_funcs[13].func = mr_B_next;
    base_funcs[14].name ="print";
    base_funcs[14].func = mr_B_print;
    base_funcs[15].name ="pcall";
    base_funcs[15].func = mr_B_pcall;
    base_funcs[16].name ="loadfile";
    base_funcs[16].func = mr_B_loadfile;
    base_funcs[17].name ="dofile";
    base_funcs[17].func = mr_B_dofile;
    base_funcs[18].name ="_loads";
    base_funcs[18].func = mr_B_loadstring;
#endif
    base_funcs[19].name ="_t";
    base_funcs[19].func = mr_B_short_type;
    base_funcs[20].name ="_assert";
    base_funcs[20].func = mr_B_assert;
    base_funcs[21].name ="_rawEq";
    base_funcs[21].func = mr_B_rawequal;
    base_funcs[22].name ="_pCall";
    base_funcs[22].func = mr_B_pcall;
    base_funcs[23].name ="_pCallEx";
    base_funcs[23].func = mr_B_xpcall;
    base_funcs[24].name ="_gc";
    base_funcs[24].func = mr_B_collectgarbage;
    // base_funcs[].name ="_gcInfo";
    // base_funcs[].func = mr_B_gcinfo;
    base_funcs[25].name ="_loadFile";
    base_funcs[25].func = mr_B_loadfile;
    base_funcs[26].name ="_execFile";
    base_funcs[26].func = mr_B_dofile;
    base_funcs[27].name ="_loadBuf";
    base_funcs[27].func = mr_B_loadstring;
    // base_funcs[].name ="_require";
    // base_funcs[].func = mr_B_require;
    base_funcs[28].name =NULL;
    base_funcs[28].func = NULL;

}


static void base_lib_open (mrp_State *L) {
  LUADBGPRINTF("global");
  mrp_pushliteral(L, "_R");
  mrp_pushvalue(L, MRP_GLOBALSINDEX);
  mr_L_openlib(L, NULL, base_funcs, 0);  /* open lib into global table */
  /* `newproxy' needs a weaktable as upvalue */
#if 0
  mrp_pushliteral(L, "newproxy");
  mrp_newtable(L);  /* new table `w' */
  mrp_pushvalue(L, -1);  /* `w' will be its own metatable */
  mrp_setmetatable(L, -2);
  mrp_pushliteral(L, "__mode");
  mrp_pushliteral(L, "k");
  mrp_rawset(L, -3);  /* metatable(w).__mode = "k" */
  mrp_pushcclosure(L, mr_B_newproxy, 1);
  mrp_rawset(L, -3);  /* set global `newproxy' */
#endif
  mrp_rawset(L, -1);  /* set global _R */
}


MRPLIB_API int mrp_open_base (mrp_State *L) {
  base_lib_open(L);
  mr_L_openlib(L, MRP_COLIBNAME, co_funcs, 0);
  mrp_newtable(L);
  mrp_setglobal(L, REQTAB);
  LUADBGPRINTF("base lib");
  return 0;
}

