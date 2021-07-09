
#ifndef mr_h
#define mr_h

#include "mrporting.h"
#include "other.h"
#include "printf.h"
#include "string.h"
#include "type.h"

#define MR_START_FILE "start.mr"
#define MR_ERROR_WAP "https://github.com/zengming00/vmrp"

#define COMPATIBILITY01

#define MR_MAX_FILENAME_SIZE 128
#define MR_MAX_FILE_SIZE 1024000
#define MRP_L_BUFFERSIZE 256

/*
#define STRTOL(n,e,b)		STRTOD(e,b)
#define STRCSPN(a,b)		    (unsigned int)(STRSTR(a,b) - a)
#define STRNCAT(a,b,c)		    STRLCAT(a,b,c+STRLEN(a))
#define STRCOLL		    STRCMP
#define STRPBRK(a,b)		   ((STRCHRSEND(a,b) == a+STRLEN(a))? NULL:STRCHRSEND(a,b))
*/

#define SETJMP setjmp
#define LONGJMP longjmp

int mr_isxdigit(int ch);
int mr_isalpha(int ch);
int mr_isspace(int ch);
int mr_toupper(int ch);
int mr_tolower(int ch);
int mr_isalnum(int ch);
int mr_isupper(int ch);
int mr_ispunct(int ch);
int mr_iscntrl(int ch);
int mr_isdigit(int ch);
int mr_islower(int ch);

#ifdef MR_BIG_ENDIAN
#define ntohl(i) (((uint32)i >> 24) | (((uint32)i & 0xff0000) >> 8) | (((uint32)i & 0xff00) << 8) | ((uint32)i << 24))
#define htonl(i) (i)
#define ntohs(i) ((((uint16)i) >> 8) | ((uint16)i << 8))
#else
#define ntohl(i) (i)
#define htonl(i) (((uint32)i >> 24) | (((uint32)i & 0xff0000) >> 8) | (((uint32)i & 0xff00) << 8) | ((uint32)i << 24))
#define ntohs(i) (i)
#endif

#define mr_htonl(i) (((uint32)i >> 24) | (((uint32)i & 0xff0000) >> 8) | (((uint32)i & 0xff00) << 8) | ((uint32)i << 24))

//////////////////////////////////////////////
enum {
    MR_STATE_IDLE,
    MR_STATE_RUN,
    MR_STATE_PAUSE,
    MR_STATE_RESTART,
    MR_STATE_STOP,
    MR_STATE_ERROR
};

extern int32 mr_state;
//////////////////////////////////////////////

#define MRDBGPRINTF mr_printf
// #define LUADBGPRINTF mr_printf
#define LUADBGPRINTF(...)

#define STRCSPN strcspn2
#define STRNCAT strncat2
#define STRPBRK strpbrk2

#define STRCOLL strcmp2
#define MEMCPY(dest, src, size) memcpy2((dest), (src), (size))
#define MEMMOVE(dest, src, size) memmove2((dest), (src), (size))
#define MEMSET(dest, ch, size) memset2((dest), (ch), (size))
#define MEMCMP(a, b, size) memcmp2((a), (b), (size))
#define MEMCHR(s, c, size) memchr2((s), (c), (size))
#define MEMSTR(h, n, hl) memstr2((h), (n), (hl))
#define MEMRCHR(s, c, sl) memrchr2((s), (c), (sl))
#define MEMCHREND(s, c, sl) memchrend2((s), (c), (sl))
#define MEMRCHRBEGIN(s, c, sl) memrchrbegin2((s), (c), (sl))
#define STRCPY(dest, src) strcpy2((dest), (src))
#define STRNCPY(dest, src, count) strncpy2((dest), (char *)(src), (count))
#define STRNCMP(a, b, count) strncmp2((a), (b), (count))
#define STRICMP(a, b) stricmp2((a), (b))
#define STRNICMP(a, b, count) strnicmp2((a), (b), (count))
#define STRCAT(dest, src) strcat2((dest), (src))
#define STRCMP(s1, s2) strcmp2((s1), (s2))
#define STRLEN(s1) strlen2((char *)(s1))
#define STRNLEN(s1, n) ((strlen2((char *)(s1)) > n) ? n : strlen2((char *)(s1)))
#define STRCHR(s1, ch) strchr2((s1), (ch))
#define STRCHREND(s1, ch) strchrend2((s1), (ch))
#define STRCHRSEND(s, cs) strchrsend2((s), (cs))
#define STRRCHR(s1, ch) strrchr2((s1), (ch))
#define STRSTR(h, n) strstr2((h), (n))
#define STRISTR(h, n) stristr2((h), (n))
#define STRBEGINS(p, s) strbegins2((p), (s))
#define STRENDS(p, s) strends2((p), (s))
#define STRLOWER(s) strlower2((s))
#define STRUPPER(s) strupper2((s))
#define SNPRINTF snprintf
#define SPRINTF sprintf_
#define STRTOUL(s1, s2, n) strtoul2((s1), (s2), (n))
#define STRTOD(s, ps) strtod((s), (ps))
#define STRLCPY(d, s, n) strlcpy((d), (s), (n))
#define STRLCAT(d, s, n) strlcat((d), (s), (n))
#define WSTRCPY(d, s) wstrcpy((d), (s))
#define WSTRCAT(d, s) wstrcat((d), (s))
#define WSTRCMP(s1, s2) wstrcmp((s1), (s2))
#define WSTRNCMP(s1, s2, n) wstrncmp((s1), (s2), (n))
#define WSTRICMP(s1, s2) wstricmp((s1), (s2))
#define WSTRNICMP(s1, s2, n) wstrnicmp((s1), (s2), (n))
#define WSTRLEN(s1) wstrlen((s1))
#define WSTRCHR(s1, ch) wstrchr((s1), (ch))
#define WSTRRCHR(s1, ch) wstrrchr((s1), (ch))
#define WSPRINTF wsprintf
#define VSNPRINTF(b, l, f, r) vsnprintf((b), (l), (f), (r))
#define STRTOWSTR(src, dest, size) strtowstr((src), (dest), (size))
#define WSTRTOSTR(src, dest, size) wstrtostr((src), (dest), (size))
#define WSTRTOFLOAT(src) wstrtofloat((src))
#define FLOATTOWSTR(v, d, dl) floattowstr((v), (d), (dl))
#define UTF8TOWSTR(in, len, dest, s) utf8towstr((in), (len), (dest), (s))
#define WSTRTOUTF8(in, len, dest, s) wstrtoutf8((in), (len), (dest), (s))
#define WSTRLOWER(dest) wstrlower((dest))
#define WSTRUPPER(dest) wstrupper((dest))
#define WSTRLCPY(d, s, n) wstrlcpy((d), (s), (n))
#define WSTRLCAT(d, s, n) wstrlcat((d), (s), (n))
#define GETCHTYPE(ch) chartype((ch))
#define ATOI(psz) atoi((psz))
#define WSTRCOMPRESS(ps, ns, pd, nd) wstrcompress((ps), (ns), (pd), (nd))
#define STREXPAND(ps, ns, pd, nd) strexpand((ps), (ns), (pd), (nd))

#define STRTOL strtol2

//#ifdef MR_V2000
//#define MR_VERSION	2009     //升级版本前进行版本备份
//#else
//#define MR_VERSION	 1966     //升级版本前进行版本备份
//#endif

#define MR_COPYRIGHT "Copyright (C) "
#define MR_AUTHORS " "

/* option for multiple returns in `mrp_pcall' and `mrp_call' */
#define MRP_MULTRET (-1)

/*
** pseudo-indices
*/
#define MRP_REGISTRYINDEX (-10000)
#define MRP_GLOBALSINDEX (-10001)
#define mrp_upvalueindex(i) (MRP_GLOBALSINDEX - (i))

/* error codes for `mrp_load' and `mrp_pcall' */
#define MRP_ERRRUN 1
#define MRP_ERRFILE 2
#define MRP_ERRSYNTAX 3
#define MRP_ERRMEM 4
#define MRP_ERRERR 5

typedef struct mrp_State mrp_State;

typedef int (*mrp_CFunction)(mrp_State *L);

/*
** functions that read/write blocks when loading/dumping Lua chunks
*/
typedef const char *(*mrp_Chunkreader)(mrp_State *L, void *ud, size_t *sz);

typedef int (*mrp_Chunkwriter)(mrp_State *L, const void *p,
                               size_t sz, void *ud);

/*
** basic types
*/
#define MRP_TNONE (-1)

#define MRP_TNIL 0
#define MRP_TBOOLEAN 1
#define MRP_TLIGHTUSERDATA 2
#define MRP_TNUMBER 3
#define MRP_TSTRING 4
#define MRP_TTABLE 5
#define MRP_TFUNCTION 6
#define MRP_TUSERDATA 7
#define MRP_TTHREAD 8

/* minimum Lua stack available to a C function */
#define MRP_MINSTACK 20

/*
** generic extra include file
*/

#ifndef MR_V2000
#include "../src/h/mr_user_number.h"
#endif

/* type of numbers in Lua */
#ifndef MRP_NUMBER
typedef double mrp_Number;
#else
typedef MRP_NUMBER mrp_Number;
#endif

/* mark for all API functions */
#ifndef MRP_API
#define MRP_API extern
#endif

/*
** state manipulation
*/
MRP_API mrp_State *mrp_open(void);
MRP_API void mrp_close(mrp_State *L);
MRP_API mrp_State *mrp_newthread(mrp_State *L);

MRP_API mrp_CFunction mrp_atpanic(mrp_State *L, mrp_CFunction panicf);

/*
** basic stack manipulation
*/
MRP_API int mrp_gettop(mrp_State *L);
MRP_API void mrp_settop(mrp_State *L, int idx);
MRP_API void mrp_pushvalue(mrp_State *L, int idx);
MRP_API void mrp_remove(mrp_State *L, int idx);
MRP_API void mrp_insert(mrp_State *L, int idx);
MRP_API void mrp_replace(mrp_State *L, int idx);
MRP_API int mrp_checkstack(mrp_State *L, int sz);

MRP_API void mrp_xmove(mrp_State *from, mrp_State *to, int n);

/*
** access functions (stack -> C)
*/

MRP_API int mrp_isnumber(mrp_State *L, int idx);
MRP_API int mrp_isstring(mrp_State *L, int idx);
MRP_API int mrp_iscfunction(mrp_State *L, int idx);
MRP_API int mrp_isuserdata(mrp_State *L, int idx);
MRP_API int mrp_type(mrp_State *L, int idx);
MRP_API const char *mrp_typename(mrp_State *L, int tp);
MRP_API const char *mrp_shorttypename(mrp_State *L, int tp);

MRP_API int mrp_equal(mrp_State *L, int idx1, int idx2);
MRP_API int mrp_rawequal(mrp_State *L, int idx1, int idx2);
MRP_API int mrp_lessthan(mrp_State *L, int idx1, int idx2);

MRP_API mrp_Number mrp_tonumber(mrp_State *L, int idx);
MRP_API int mrp_toboolean(mrp_State *L, int idx);
MRP_API const char *mrp_tostring(mrp_State *L, int idx);
MRP_API size_t mrp_strlen(mrp_State *L, int idx);
MRP_API const char *mrp_tostring_t(mrp_State *L, int idx);
MRP_API size_t mrp_strlen_t(mrp_State *L, int idx);
MRP_API mrp_CFunction mrp_tocfunction(mrp_State *L, int idx);
MRP_API void *mrp_touserdata(mrp_State *L, int idx);
MRP_API mrp_State *mrp_tothread(mrp_State *L, int idx);
MRP_API const void *mrp_topointer(mrp_State *L, int idx);

/*
** push functions (C -> stack)
*/
MRP_API void mrp_pushnil(mrp_State *L);
MRP_API void mrp_pushnumber(mrp_State *L, mrp_Number n);
MRP_API void mrp_pushlstring(mrp_State *L, const char *s, size_t l);
MRP_API void mrp_pushstring(mrp_State *L, const char *s);
MRP_API const char *mrp_pushvfstring(mrp_State *L, const char *fmt,
                                     va_list argp);
MRP_API const char *mrp_pushfstring(mrp_State *L, const char *fmt, ...);
MRP_API void mrp_pushcclosure(mrp_State *L, mrp_CFunction fn, int n);
MRP_API void mrp_pushboolean(mrp_State *L, int b);
MRP_API void mrp_pushlightuserdata(mrp_State *L, void *p);

/*
** get functions (Lua -> stack)
*/
MRP_API void mrp_gettable(mrp_State *L, int idx);
MRP_API void mrp_rawget(mrp_State *L, int idx);
MRP_API void mrp_rawgeti(mrp_State *L, int idx, int n);
MRP_API void mrp_newtable(mrp_State *L);
MRP_API void *mrp_newuserdata(mrp_State *L, size_t sz);
MRP_API int mrp_getmetatable(mrp_State *L, int objindex);
MRP_API void mrp_getfenv(mrp_State *L, int idx);

/*
** set functions (stack -> Lua)
*/
MRP_API void mrp_settable(mrp_State *L, int idx);
MRP_API void mrp_rawset(mrp_State *L, int idx);
MRP_API void mrp_rawseti(mrp_State *L, int idx, int n);
MRP_API int mrp_setmetatable(mrp_State *L, int objindex);
MRP_API int mrp_setfenv(mrp_State *L, int idx);

/*
** `load' and `call' functions (load and run Lua code)
*/
MRP_API void mrp_call(mrp_State *L, int nargs, int nresults);
MRP_API int mrp_pcall(mrp_State *L, int nargs, int nresults, int errfunc);
MRP_API int mrp_cpcall(mrp_State *L, mrp_CFunction func, void *ud);
MRP_API int mrp_load(mrp_State *L, mrp_Chunkreader reader, void *dt,
                     const char *chunkname);

MRP_API int mrp_dump(mrp_State *L, mrp_Chunkwriter writer, void *data);

/*
** coroutine functions
*/
MRP_API int mrp_yield(mrp_State *L, int nresults);
MRP_API int mrp_resume(mrp_State *L, int narg);

/*
** garbage-collection functions
*/
MRP_API int mrp_getgcthreshold(mrp_State *L);
MRP_API int mrp_getgccount(mrp_State *L);
MRP_API void mrp_setgcthreshold(mrp_State *L, int newthreshold);

/*
** miscellaneous functions
*/

MRP_API uint32 mrp_version(void);

MRP_API int mrp_error(mrp_State *L);

MRP_API int mrp_next(mrp_State *L, int idx);

MRP_API void mrp_concat(mrp_State *L, int n);

/* 
** ===============================================================
** some useful macros
** ===============================================================
*/

#define mrp_boxpointer(L, u) \
    (*(void **)(mrp_newuserdata(L, sizeof(void *))) = (u))

#define mrp_unboxpointer(L, i) (*(void **)(mrp_touserdata(L, i)))

#define mrp_pop(L, n) mrp_settop(L, -(n)-1)

#define mrp_register(L, n, f) \
    (mrp_pushstring(L, n),    \
     mrp_pushcfunction(L, f), \
     mrp_settable(L, MRP_GLOBALSINDEX))

#define mrp_pushcfunction(L, f) mrp_pushcclosure(L, f, 0)

#define mrp_isfunction(L, n) (mrp_type(L, n) == MRP_TFUNCTION)
#define mrp_istable(L, n) (mrp_type(L, n) == MRP_TTABLE)
#define mrp_islightuserdata(L, n) (mrp_type(L, n) == MRP_TLIGHTUSERDATA)
#define mrp_isnil(L, n) (mrp_type(L, n) == MRP_TNIL)
#define mrp_isboolean(L, n) (mrp_type(L, n) == MRP_TBOOLEAN)
#define mrp_isnone(L, n) (mrp_type(L, n) == MRP_TNONE)
#define mrp_isnoneornil(L, n) (mrp_type(L, n) <= 0)

#define mrp_pushliteral(L, s) \
    mrp_pushlstring(L, "" s, (sizeof(s) / sizeof(char)) - 1)

/*
** compatibility macros and functions
*/

MRP_API int mrp_pushupvalues(mrp_State *L);

#define mrp_getregistry(L) mrp_pushvalue(L, MRP_REGISTRYINDEX)
#define mrp_setglobal(L, s) \
    (mrp_pushstring(L, s), mrp_insert(L, -2), mrp_settable(L, MRP_GLOBALSINDEX))

#define mrp_getglobal(L, s) \
    (mrp_pushstring(L, s), mrp_gettable(L, MRP_GLOBALSINDEX))

/* compatibility with ref system */

/* pre-defined references */
#define MRP_NOREF (-2)
#define MRP_REFNIL (-1)

#define mrp_ref(L, lock) ((lock) ? mr_L_ref(L, MRP_REGISTRYINDEX) : (mrp_pushstring(L, "unlocked references are obsolete"), mrp_error(L), 0))

#define mrp_unref(L, ref) mr_L_unref(L, MRP_REGISTRYINDEX, (ref))

#define mrp_getref(L, ref) mrp_rawgeti(L, MRP_REGISTRYINDEX, ref)

#ifndef api_check
#define api_check(L, o) /*{ assert(o); }*/
#endif
#define api_incr_top(L)                    \
    {                                      \
        api_check(L, L->top < L->ci->top); \
        L->top++;                          \
    }

/*
** {======================================================================
** useful definitions for Lua kernel and libraries
** =======================================================================
*/

/* formats for Lua numbers */
#ifndef MRP_NUMBER_SCAN
#define MRP_NUMBER_SCAN "%lf"
#endif

#ifndef MRP_NUMBER_FMT
#define MRP_NUMBER_FMT "%.14g"
#endif

/* }====================================================================== */

/*
** {======================================================================
** Debug API
** =======================================================================
*/

/*
** Event codes
*/
#define MRP_HOOKCALL 0
#define MRP_HOOKRET 1
#define MRP_HOOKLINE 2
#define MRP_HOOKCOUNT 3
#define MRP_HOOKTAILRET 4

/*
** Event masks
*/
#define MRP_MASKCALL (1 << MRP_HOOKCALL)
#define MRP_MASKRET (1 << MRP_HOOKRET)
#define MRP_MASKLINE (1 << MRP_HOOKLINE)
#define MRP_MASKCOUNT (1 << MRP_HOOKCOUNT)

typedef struct mrp_Debug mrp_Debug; /* activation record */

typedef void (*mrp_Hook)(mrp_State *L, mrp_Debug *ar);

MRP_API int mrp_getstack(mrp_State *L, int level, mrp_Debug *ar);
MRP_API int mrp_getinfo(mrp_State *L, const char *what, mrp_Debug *ar);
MRP_API const char *mrp_getlocal(mrp_State *L, const mrp_Debug *ar, int n);
MRP_API const char *mrp_setlocal(mrp_State *L, const mrp_Debug *ar, int n);
MRP_API const char *mrp_getupvalue(mrp_State *L, int funcindex, int n);
MRP_API const char *mrp_setupvalue(mrp_State *L, int funcindex, int n);

MRP_API int mrp_sethook(mrp_State *L, mrp_Hook func, int mask, int count);
MRP_API mrp_Hook mrp_gethook(mrp_State *L);
MRP_API int mrp_gethookmask(mrp_State *L);
MRP_API int mrp_gethookcount(mrp_State *L);

#define MRP_IDSIZE 60

struct mrp_Debug {
    int event;
    const char *name;           /* (n) */
    const char *namewhat;       /* (n) `global', `local', `field', `method' */
    const char *what;           /* (S) `Lua', `C', `main', `tail' */
    const char *source;         /* (S) */
    int currentline;            /* (l) */
    int nups;                   /* (u) number of upvalues */
    int linedefined;            /* (S) */
    char short_src[MRP_IDSIZE]; /* (S) */
    /* private part */
    int i_ci; /* active function */
};

/* }====================================================================== */

#endif
