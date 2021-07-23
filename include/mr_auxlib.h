
#ifndef mr_auxlib_h
#define mr_auxlib_h



#include "mr.h"


#ifndef MRPLIB_API
#define MRPLIB_API	MRP_API
#endif



typedef struct mr_L_reg {
  const char *name;
  mrp_CFunction func;
} mr_L_reg;


MRPLIB_API void mr_L_openlib (mrp_State *L, const char *libname,
                               const mr_L_reg *l, int nup);
MRPLIB_API int mr_L_getmetafield (mrp_State *L, int obj, const char *e);
MRPLIB_API int mr_L_callmeta (mrp_State *L, int obj, const char *e);
MRPLIB_API int mr_L_typerror (mrp_State *L, int narg, const char *tname);
MRPLIB_API int mr_L_argerror (mrp_State *L, int numarg, const char *extramsg);
MRPLIB_API const char *mr_L_checklstring (mrp_State *L, int numArg, size_t *l);
MRPLIB_API const char *mr_L_optlstring (mrp_State *L, int numArg,
                                           const char *def, size_t *l);
MRPLIB_API mrp_Number mr_L_checknumber (mrp_State *L, int numArg);
MRPLIB_API mrp_Number mr_L_optnumber (mrp_State *L, int nArg, mrp_Number def);

MRPLIB_API void mr_L_checkstack (mrp_State *L, int sz, const char *msg);
MRPLIB_API void mr_L_checktype (mrp_State *L, int narg, int t);
MRPLIB_API void mr_L_checkany (mrp_State *L, int narg);

MRPLIB_API int   mr_L_newmetatable (mrp_State *L, const char *tname);
MRPLIB_API void  mr_L_getmetatable (mrp_State *L, const char *tname);
MRPLIB_API void *mr_L_checkudata (mrp_State *L, int ud, const char *tname);

MRPLIB_API void mr_L_where (mrp_State *L, int lvl);
MRPLIB_API int mr_L_error (mrp_State *L, const char *fmt, ...);

MRPLIB_API int mr_L_findstring (const char *st, const char *const lst[]);

MRPLIB_API int mr_L_ref (mrp_State *L, int t);
MRPLIB_API void mr_L_unref (mrp_State *L, int t, int ref);

MRPLIB_API int mr_L_getn (mrp_State *L, int t);
MRPLIB_API void mr_L_setn (mrp_State *L, int t, int n);

MRPLIB_API int mr_L_loadfile (mrp_State *L, const char *filename);
MRPLIB_API int mr_L_loadbuffer (mrp_State *L, const char *buff, size_t sz,
                                const char *name);



/*
** ===============================================================
** some useful macros
** ===============================================================
*/

#define mr_L_argcheck(L, cond,numarg,extramsg) if (!(cond)) \
                                               mr_L_argerror(L, numarg,extramsg)
#define mr_L_checkstring(L,n)	(mr_L_checklstring(L, (n), NULL))
#define mr_L_optstring(L,n,d)	(mr_L_optlstring(L, (n), (d), NULL))
#define mr_L_checkint(L,n)	((int)mr_L_checknumber(L, n))
#define mr_L_checklong(L,n)	((long)mr_L_checknumber(L, n))
#define mr_L_optint(L,n,d)	((int)mr_L_optnumber(L, n,(mrp_Number)(d)))
#define mr_L_optlong(L,n,d)	((long)mr_L_optnumber(L, n,(mrp_Number)(d)))


/*
** {======================================================
** Generic Buffer manipulation
** =======================================================
*/


#ifndef MRP_L_BUFFERSIZE
#define MRP_L_BUFFERSIZE	  BUFSIZ
#endif


typedef struct mr_L_Buffer {
  char *p;			/* current position in buffer */
  int lvl;  /* number of strings in the stack (level) */
  mrp_State *L;
  char buffer[MRP_L_BUFFERSIZE];
} mr_L_Buffer;

#define mr_L_putchar(B,c) \
  ((void)((B)->p < ((B)->buffer+MRP_L_BUFFERSIZE) || mr_L_prepbuffer(B)), \
   (*(B)->p++ = (char)(c)))

#define mr_L_addsize(B,n)	((B)->p += (n))

MRPLIB_API void mr_L_buffinit (mrp_State *L, mr_L_Buffer *B);
MRPLIB_API char *mr_L_prepbuffer (mr_L_Buffer *B);
MRPLIB_API void mr_L_addlstring (mr_L_Buffer *B, const char *s, size_t l);
MRPLIB_API void mr_L_addstring (mr_L_Buffer *B, const char *s);
MRPLIB_API void mr_L_addvalue (mr_L_Buffer *B);
MRPLIB_API void mr_L_pushresult (mr_L_Buffer *B);


/* }====================================================== */



/*
** Compatibility macros and functions
*/

MRPLIB_API int   mrp_dofile (mrp_State *L, const char *filename);
MRPLIB_API int   mrp_dostring (mrp_State *L, const char *str);
MRPLIB_API int   mrp_dobuffer (mrp_State *L, const char *buff, size_t sz,
                               const char *n);


#define mr_L_check_lstr 	mr_L_checklstring
#define mr_L_opt_lstr 	mr_L_optlstring 
#define mr_L_check_number 	mr_L_checknumber 
#define mr_L_opt_number	mr_L_optnumber
#define mr_L_arg_check	mr_L_argcheck
#define mr_L_check_string	mr_L_checkstring
#define mr_L_opt_string	mr_L_optstring
#define mr_L_check_int	mr_L_checkint
#define mr_L_check_long	mr_L_checklong
#define mr_L_opt_int	mr_L_optint
#define mr_L_opt_long	mr_L_optlong


#endif


