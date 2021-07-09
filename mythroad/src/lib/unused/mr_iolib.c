

//#define liolib_c

#include "mr.h"

#include "mr_auxlib.h"
#include "mr_lib.h"



/*
** by default, gcc does not get `tmpname'
*/
#ifndef USE_TMPNAME
#ifdef __GNUC__
#define USE_TMPNAME	0
#else
#define USE_TMPNAME	1
#endif
#endif


/*
** by default, posix systems get `popen'
*/
#ifndef USE_POPEN
#ifdef _POSIX_C_SOURCE
#if _POSIX_C_SOURCE >= 2
#define USE_POPEN	1
#endif
#endif
#endif

#ifndef USE_POPEN
#define USE_POPEN	0
#endif




/*
** {======================================================
** FILE Operations
** =======================================================
*/


#if !USE_POPEN
#define pclose(f)    (-1)
#endif


#define FILEHANDLE		"FILE*"

#define IO_INPUT		"_input"
#define IO_OUTPUT		"_output"


static int pushresult (mrp_State *L, int i, const char *filename) {
  if (i) {
    mrp_pushboolean(L, 1);
    return 1;
  }
  else {
    mrp_pushnil(L);
    if (filename)
      mrp_pushfstring(L, "%s: %s", filename, strerror(errno));
    else
      mrp_pushfstring(L, "%s", strerror(errno));
    mrp_pushnumber(L, errno);
    return 3;
  }
}


static FILE **topfile (mrp_State *L, int findex) {
  FILE **f = (FILE **)mr_L_checkudata(L, findex, FILEHANDLE);
  if (f == NULL) mr_L_argerror(L, findex, "bad file");
  return f;
}


static int io_type (mrp_State *L) {
  FILE **f = (FILE **)mr_L_checkudata(L, 1, FILEHANDLE);
  if (f == NULL) mrp_pushnil(L);
  else if (*f == NULL)
    mrp_pushliteral(L, "closed file");
  else
    mrp_pushliteral(L, "file");
  return 1;
}


static FILE *tofile (mrp_State *L, int findex) {
  FILE **f = topfile(L, findex);
  if (*f == NULL)
    mr_L_error(L, "attempt to use a closed file");
  return *f;
}



/*
** When creating file handles, always creates a `closed' file handle
** before opening the actual file; so, if there is a memory error, the
** file is not left opened.
*/
static FILE **newfile (mrp_State *L) {
  FILE **pf = (FILE **)mrp_newuserdata(L, sizeof(FILE *));
  *pf = NULL;  /* file handle is currently `closed' */
  mr_L_getmetatable(L, FILEHANDLE);
  mrp_setmetatable(L, -2);
  return pf;
}


/*
** assumes that top of the stack is the `io' library, and next is
** the `io' metatable
*/
static void registerfile (mrp_State *L, FILE *f, const char *name,
                                                 const char *impname) {
  mrp_pushstring(L, name);
  *newfile(L) = f;
  if (impname) {
    mrp_pushstring(L, impname);
    mrp_pushvalue(L, -2);
    mrp_settable(L, -6);  /* metatable[impname] = file */
  }
  mrp_settable(L, -3);  /* io[name] = file */
}


static int aux_close (mrp_State *L) {
  FILE *f = tofile(L, 1);
  if (f == stdin || f == stdout || f == stderr)
    return 0;  /* file cannot be closed */
  else {
    int ok = (pclose(f) != -1) || (fclose(f) == 0);
    if (ok)
      *(FILE **)mrp_touserdata(L, 1) = NULL;  /* mark file as closed */
    return ok;
  }
}


static int io_close (mrp_State *L) {
  if (mrp_isnone(L, 1) && mrp_type(L, mrp_upvalueindex(1)) == MRP_TTABLE) {
    mrp_pushstring(L, IO_OUTPUT);
    mrp_rawget(L, mrp_upvalueindex(1));
  }
  return pushresult(L, aux_close(L), NULL);
}


static int io_gc (mrp_State *L) {
  FILE **f = topfile(L, 1);
  if (*f != NULL)  /* ignore closed files */
    aux_close(L);
  return 0;
}


static int io_tostring (mrp_State *L) {
  char buff[128];
  FILE **f = topfile(L, 1);
  if (*f == NULL)
    STRCPY(buff, "closed");
  else
    sprintf(buff, "%p", mrp_touserdata(L, 1));
  mrp_pushfstring(L, "file (%s)", buff);
  return 1;
}


static int io_open (mrp_State *L) {
  const char *filename = mr_L_checkstring(L, 1);
  const char *mode = mr_L_optstring(L, 2, "r");
  FILE **pf = newfile(L);
  *pf = fopen(filename, mode);
  return (*pf == NULL) ? pushresult(L, 0, filename) : 1;
}


static int io_popen (mrp_State *L) {
#if !USE_POPEN
  mr_L_error(L, "`popen' not supported");
  return 0;
#else
  const char *filename = mr_L_checkstring(L, 1);
  const char *mode = mr_L_optstring(L, 2, "r");
  FILE **pf = newfile(L);
  *pf = popen(filename, mode);
  return (*pf == NULL) ? pushresult(L, 0, filename) : 1;
#endif
}


static int io_tmpfile (mrp_State *L) {
  FILE **pf = newfile(L);
  *pf = tmpfile();
  return (*pf == NULL) ? pushresult(L, 0, NULL) : 1;
}


static FILE *getiofile (mrp_State *L, const char *name) {
  mrp_pushstring(L, name);
  mrp_rawget(L, mrp_upvalueindex(1));
  return tofile(L, -1);
}


static int g_iofile (mrp_State *L, const char *name, const char *mode) {
  if (!mrp_isnoneornil(L, 1)) {
    const char *filename = mrp_tostring(L, 1);
    mrp_pushstring(L, name);
    if (filename) {
      FILE **pf = newfile(L);
      *pf = fopen(filename, mode);
      if (*pf == NULL) {
        mrp_pushfstring(L, "%s: %s", filename, strerror(errno));
        mr_L_argerror(L, 1, mrp_tostring(L, -1));
      }
    }
    else {
      tofile(L, 1);  /* check that it's a valid file handle */
      mrp_pushvalue(L, 1);
    }
    mrp_rawset(L, mrp_upvalueindex(1));
  }
  /* return current value */
  mrp_pushstring(L, name);
  mrp_rawget(L, mrp_upvalueindex(1));
  return 1;
}


static int io_input (mrp_State *L) {
  return g_iofile(L, IO_INPUT, "r");
}


static int io_output (mrp_State *L) {
  return g_iofile(L, IO_OUTPUT, "w");
}


static int io_readline (mrp_State *L);


static void aux_lines (mrp_State *L, int idx, int close) {
  mrp_pushliteral(L, FILEHANDLE);
  mrp_rawget(L, MRP_REGISTRYINDEX);
  mrp_pushvalue(L, idx);
  mrp_pushboolean(L, close);  /* close/not close file when finished */
  mrp_pushcclosure(L, io_readline, 3);
}


static int f_lines (mrp_State *L) {
  tofile(L, 1);  /* check that it's a valid file handle */
  aux_lines(L, 1, 0);
  return 1;
}


static int io_lines (mrp_State *L) {
  if (mrp_isnoneornil(L, 1)) {  /* no arguments? */
    mrp_pushstring(L, IO_INPUT);
    mrp_rawget(L, mrp_upvalueindex(1));  /* will iterate over default input */
    return f_lines(L);
  }
  else {
    const char *filename = mr_L_checkstring(L, 1);
    FILE **pf = newfile(L);
    *pf = fopen(filename, "r");
    mr_L_argcheck(L, *pf, 1,  strerror(errno));
    aux_lines(L, mrp_gettop(L), 1);
    return 1;
  }
}


/*
** {======================================================
** READ
** =======================================================
*/


static int read_number (mrp_State *L, FILE *f) {
  mrp_Number d;
  if (fscanf(f, MRP_NUMBER_SCAN, &d) == 1) {
    mrp_pushnumber(L, d);
    return 1;
  }
  else return 0;  /* read fails */
}


static int test_eof (mrp_State *L, FILE *f) {
  int c = getc(f);
  ungetc(c, f);
  mrp_pushlstring(L, NULL, 0);
  return (c != EOF);
}


static int read_line (mrp_State *L, FILE *f) {
  mr_L_Buffer b;
  mr_L_buffinit(L, &b);
  for (;;) {
    size_t l;
    char *p = mr_L_prepbuffer(&b);
    if (fgets(p, MRP_L_BUFFERSIZE, f) == NULL) {  /* eof? */
      mr_L_pushresult(&b);  /* close buffer */
      return (mrp_strlen(L, -1) > 0);  /* check whether read something */
    }
    l = STRLEN(p);
    if (p[l-1] != '\n')
      mr_L_addsize(&b, l);
    else {
      mr_L_addsize(&b, l - 1);  /* do not include `eol' */
      mr_L_pushresult(&b);  /* close buffer */
      return 1;  /* read at least an `eol' */
    }
  }
}


static int read_chars (mrp_State *L, FILE *f, size_t n) {
  size_t rlen;  /* how much to read */
  size_t nr;  /* number of chars actually read */
  mr_L_Buffer b;
  mr_L_buffinit(L, &b);
  rlen = MRP_L_BUFFERSIZE;  /* try to read that much each time */
  do {
    char *p = mr_L_prepbuffer(&b);
    if (rlen > n) rlen = n;  /* cannot read more than asked */
    nr = fread(p, sizeof(char), rlen, f);
    mr_L_addsize(&b, nr);
    n -= nr;  /* still have to read `n' chars */
  } while (n > 0 && nr == rlen);  /* until end of count or eof */
  mr_L_pushresult(&b);  /* close buffer */
  return (n == 0 || mrp_strlen(L, -1) > 0);
}


static int g_read (mrp_State *L, FILE *f, int first) {
  int nargs = mrp_gettop(L) - 1;
  int success;
  int n;
  if (nargs == 0) {  /* no arguments? */
    success = read_line(L, f);
    n = first+1;  /* to return 1 result */
  }
  else {  /* ensure stack space for all results and for auxlib's buffer */
    mr_L_checkstack(L, nargs+MRP_MINSTACK, "too many arguments");
    success = 1;
    for (n = first; nargs-- && success; n++) {
      if (mrp_type(L, n) == MRP_TNUMBER) {
        size_t l = (size_t)mrp_tonumber(L, n);
        success = (l == 0) ? test_eof(L, f) : read_chars(L, f, l);
      }
      else {
        const char *p = mrp_tostring(L, n);
        mr_L_argcheck(L, p && p[0] == '*', n, "invalid option");
        switch (p[1]) {
          case 'n':  /* number */
            success = read_number(L, f);
            break;
          case 'l':  /* line */
            success = read_line(L, f);
            break;
          case 'a':  /* file */
            read_chars(L, f, ~((size_t)0));  /* read MAX_SIZE_T chars */
            success = 1; /* always success */
            break;
          case 'w':  /* word */
            return mr_L_error(L, "obsolete option `*w' to `read'");
          default:
            return mr_L_argerror(L, n, "invalid format");
        }
      }
    }
  }
  if (!success) {
    mrp_pop(L, 1);  /* remove last result */
    mrp_pushnil(L);  /* push nil instead */
  }
  return n - first;
}


static int io_read (mrp_State *L) {
  return g_read(L, getiofile(L, IO_INPUT), 1);
}


static int f_read (mrp_State *L) {
  return g_read(L, tofile(L, 1), 2);
}


static int io_readline (mrp_State *L) {
  FILE *f = *(FILE **)mrp_touserdata(L, mrp_upvalueindex(2));
  if (f == NULL)  /* file is already closed? */
    mr_L_error(L, "file is already closed");
  if (read_line(L, f)) return 1;
  else {  /* EOF */
    if (mrp_toboolean(L, mrp_upvalueindex(3))) {  /* generator created file? */
      mrp_settop(L, 0);
      mrp_pushvalue(L, mrp_upvalueindex(2));
      aux_close(L);  /* close it */
    }
    return 0;
  }
}

/* }====================================================== */


static int g_write (mrp_State *L, FILE *f, int arg) {
  int nargs = mrp_gettop(L) - 1;
  int status = 1;
  for (; nargs--; arg++) {
    if (mrp_type(L, arg) == MRP_TNUMBER) {
      /* optimization: could be done exactly as for strings */
      status = status &&
          fprintf(f, MRP_NUMBER_FMT, mrp_tonumber(L, arg)) > 0;
    }
    else {
      size_t l;
      const char *s = mr_L_checklstring(L, arg, &l);
      status = status && (fwrite(s, sizeof(char), l, f) == l);
    }
  }
  return pushresult(L, status, NULL);
}


static int io_write (mrp_State *L) {
  return g_write(L, getiofile(L, IO_OUTPUT), 1);
}


static int f_write (mrp_State *L) {
  return g_write(L, tofile(L, 1), 2);
}


static int f_seek (mrp_State *L) {
   /*
  static const int mode[] = {SEEK_SET, SEEK_CUR, SEEK_END};
  static const char *const modenames[] = {"set", "cur", "end", NULL};
  */ //ouli brew
  const int mode[] = {SEEK_SET, SEEK_CUR, SEEK_END};
  const char *const modenames[] = {"set", "cur", "end", NULL};
  FILE *f = tofile(L, 1);
  int op = mr_L_findstring(mr_L_optstring(L, 2, "cur"), modenames);
  long offset = mr_L_optlong(L, 3, 0);
  mr_L_argcheck(L, op != -1, 2, "invalid mode");
  op = fseek(f, offset, mode[op]);
  if (op)
    return pushresult(L, 0, NULL);  /* error */
  else {
    mrp_pushnumber(L, ftell(f));
    return 1;
  }
}


static int io_flush (mrp_State *L) {
  return pushresult(L, fflush(getiofile(L, IO_OUTPUT)) == 0, NULL);
}


static int f_flush (mrp_State *L) {
  return pushresult(L, fflush(tofile(L, 1)) == 0, NULL);
}


static const mr_L_reg iolib[] = {
  {"input", io_input},
  {"output", io_output},
  {"lines", io_lines},
  {"close", io_close},
  {"flush", io_flush},
  {"open", io_open},
  {"popen", io_popen},
  {"read", io_read},
  {"tmpfile", io_tmpfile},
  {"type", io_type},
  {"write", io_write},
  {NULL, NULL}
};


static const mr_L_reg flib[] = {
  {"flush", f_flush},
  {"read", f_read},
  {"lines", f_lines},
  {"seek", f_seek},
  {"write", f_write},
  {"close", io_close},
  {"__gc", io_gc},
  {"__str", io_tostring},
  {NULL, NULL}
};


static void createmeta (mrp_State *L) {
  mr_L_newmetatable(L, FILEHANDLE);  /* create new metatable for file handles */
  /* file methods */
  mrp_pushliteral(L, "__index");
  mrp_pushvalue(L, -2);  /* push metatable */
  mrp_rawset(L, -3);  /* metatable.__index = metatable */
  mr_L_openlib(L, NULL, flib, 0);
}

/* }====================================================== */


/*
** {======================================================
** Other O.S. Operations
** =======================================================
*/

static int io_execute (mrp_State *L) {
  mrp_pushnumber(L, system(mr_L_checkstring(L, 1)));
  return 1;
}


static int io_remove (mrp_State *L) {
  const char *filename = mr_L_checkstring(L, 1);
  return pushresult(L, remove(filename) == 0, filename);
}


static int io_rename (mrp_State *L) {
  const char *fromname = mr_L_checkstring(L, 1);
  const char *toname = mr_L_checkstring(L, 2);
  return pushresult(L, rename(fromname, toname) == 0, fromname);
}


static int io_tmpname (mrp_State *L) {
#if !USE_TMPNAME
  mr_L_error(L, "`tmpname' not supported");
  return 0;
#else
  char buff[L_tmpnam];
  if (tmpnam(buff) != buff)
    return mr_L_error(L, "unable to generate a unique filename in `tmpname'");
  mrp_pushstring(L, buff);
  return 1;
#endif
}


static int io_getenv (mrp_State *L) {
  mrp_pushstring(L, getenv(mr_L_checkstring(L, 1)));  /* if NULL push nil */
  return 1;
}


static int io_clock (mrp_State *L) {
  mrp_pushnumber(L, ((mrp_Number)clock())/(mrp_Number)CLOCKS_PER_SEC);
  return 1;
}


/*
** {======================================================
** Time/Date operations
** { year=%Y, month=%m, day=%d, hour=%H, min=%M, sec=%S,
**   wday=%w+1, yday=%j, isdst=? }
** =======================================================
*/

static void setfield (mrp_State *L, const char *key, int value) {
  mrp_pushstring(L, key);
  mrp_pushnumber(L, value);
  mrp_rawset(L, -3);
}

static void setboolfield (mrp_State *L, const char *key, int value) {
  mrp_pushstring(L, key);
  mrp_pushboolean(L, value);
  mrp_rawset(L, -3);
}

static int getboolfield (mrp_State *L, const char *key) {
  int res;
  mrp_pushstring(L, key);
  mrp_gettable(L, -2);
  res = mrp_toboolean(L, -1);
  mrp_pop(L, 1);
  return res;
}


static int getfield (mrp_State *L, const char *key, int d) {
  int res;
  mrp_pushstring(L, key);
  mrp_gettable(L, -2);
  if (mrp_isnumber(L, -1))
    res = (int)(mrp_tonumber(L, -1));
  else {
    if (d == -2)
      return mr_L_error(L, "field `%s' missing in date table", key);
    res = d;
  }
  mrp_pop(L, 1);
  return res;
}


static int io_date (mrp_State *L) {
  const char *s = mr_L_optstring(L, 1, "%c");
  time_t t = (time_t)(mr_L_optnumber(L, 2, -1));
  struct tm *stm;
  if (t == (time_t)(-1))  /* no time given? */
    t = time(NULL);  /* use current time */
  if (*s == '!') {  /* UTC? */
    stm = gmtime(&t);
    s++;  /* skip `!' */
  }
  else
    stm = localtime(&t);
  if (stm == NULL)  /* invalid date? */
    mrp_pushnil(L);
  else if (STRCMP(s, "*t") == 0) {
    mrp_newtable(L);
    setfield(L, "sec", stm->tm_sec);
    setfield(L, "min", stm->tm_min);
    setfield(L, "hour", stm->tm_hour);
    setfield(L, "day", stm->tm_mday);
    setfield(L, "month", stm->tm_mon+1);
    setfield(L, "year", stm->tm_year+1900);
    setfield(L, "wday", stm->tm_wday+1);
    setfield(L, "yday", stm->tm_yday+1);
    setboolfield(L, "isdst", stm->tm_isdst);
  }
  else {
    char b[256];
    if (strftime(b, sizeof(b), s, stm))
      mrp_pushstring(L, b);
    else
      return mr_L_error(L, "`date' format too long");
  }
  return 1;
}


static int io_time (mrp_State *L) {
  if (mrp_isnoneornil(L, 1))  /* called without args? */
    mrp_pushnumber(L, time(NULL));  /* return current time */
  else {
    time_t t;
    struct tm ts;
    mr_L_checktype(L, 1, MRP_TTABLE);
    mrp_settop(L, 1);  /* make sure table is at the top */
    ts.tm_sec = getfield(L, "sec", 0);
    ts.tm_min = getfield(L, "min", 0);
    ts.tm_hour = getfield(L, "hour", 12);
    ts.tm_mday = getfield(L, "day", -2);
    ts.tm_mon = getfield(L, "month", -2) - 1;
    ts.tm_year = getfield(L, "year", -2) - 1900;
    ts.tm_isdst = getboolfield(L, "isdst");
    t = mktime(&ts);
    if (t == (time_t)(-1))
      mrp_pushnil(L);
    else
      mrp_pushnumber(L, t);
  }
  return 1;
}


static int io_difftime (mrp_State *L) {
/*
  mrp_pushnumber(L, difftime((time_t)(mr_L_checknumber(L, 1)),
                             (time_t)(mr_L_optnumber(L, 2, 0))));
*/
  return 1;
}

/* }====================================================== */


static int io_setloc (mrp_State *L) {
   /*
  static const int cat[] = {LC_ALL, LC_COLLATE, LC_CTYPE, LC_MONETARY,
                      LC_NUMERIC, LC_TIME};
  static const char *const catnames[] = {"all", "collate", "ctype", "monetary",
     "numeric", "time", NULL};
   */ //ouli brew
  const int cat[] = {LC_ALL, LC_COLLATE, LC_CTYPE, LC_MONETARY,
                      LC_NUMERIC, LC_TIME};
  const char *const catnames[] = {"all", "collate", "ctype", "monetary",
     "numeric", "time", NULL};
  const char *l = mrp_tostring(L, 1);
  int op = mr_L_findstring(mr_L_optstring(L, 2, "all"), catnames);
  mr_L_argcheck(L, l || mrp_isnoneornil(L, 1), 1, "string expected");
  mr_L_argcheck(L, op != -1, 2, "invalid option");
  mrp_pushstring(L, setlocale(cat[op], l));
  return 1;
}


static int io_exit (mrp_State *L) {
  exit(mr_L_optint(L, 1, EXIT_SUCCESS));
  return 0;  /* to avoid warnings */
}

static const mr_L_reg syslib[] = {
  {"clock",     io_clock},
  {"date",      io_date},
  {"difftime",  io_difftime},
  {"execute",   io_execute},
  {"exit",      io_exit},
  {"getenv",    io_getenv},
  {"remove",    io_remove},
  {"rename",    io_rename},
  {"setlocale", io_setloc},
  {"time",      io_time},
  {"tmpname",   io_tmpname},
  {NULL, NULL}
};

/* }====================================================== */



MRPLIB_API int mrp_open_file (mrp_State *L) {
  mr_L_openlib(L, MRP_SYSLIBNAME, syslib, 0);
  createmeta(L);
  mrp_pushvalue(L, -1);
  mr_L_openlib(L, MRP_FILELIBNAME, iolib, 1);
  /* put predefined file handles into `io' table */
  registerfile(L, stdin, "stdin", IO_INPUT);
  registerfile(L, stdout, "stdout", IO_OUTPUT);
  registerfile(L, stderr, "stderr", NULL);
  return 1;
}

