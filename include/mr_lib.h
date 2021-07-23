/*
** $Id: lualib.h,v 1.28 2003/03/18 12:24:26 roberto Exp $
** Lua standard libraries
** See Copyright Notice in lua.h
*/

#ifndef mr_lib_h
#define mr_lib_h

#include "mr.h"

#ifndef MRPLIB_API
#define MRPLIB_API MRP_API
#endif

#define MRP_COLIBNAME "_co"
MRPLIB_API int mrp_open_base(mrp_State *L);

#define MRP_TABLIBNAME "table"
MRPLIB_API int mrp_open_table(mrp_State *L);

#define MRP_FILELIBNAME "file"
#define MRP_SYSLIBNAME "sys"
#define MR_GUILIBNAME "gui"
MRPLIB_API int mrp_open_file(mrp_State *L);

#define MRP_STRLIBNAME "string"
MRPLIB_API int mrp_open_string(mrp_State *L);

#define MRP_MATHLIBNAME "_math"
MRPLIB_API int mrp_open_math(mrp_State *L);

#define MRP_DBLIBNAME "_debug"
MRPLIB_API int mrp_open_debug(mrp_State *L);

#define MRP_PHONELIBNAME "phone"
MRPLIB_API int mrp_open_phone(mrp_State *L);

MRPLIB_API int mrp_open_loadlib(mrp_State *L);

/* to help testing the libraries */
#ifndef mrp_assert
#define mrp_assert(c) /* empty */
#endif

/* compatibility code */
#define mrp_baselibopen mrp_open_base
#define mrp_tablibopen mrp_open_table
#define mrp_iolibopen mrp_open_file
#define mrp_strlibopen mrp_open_string
#define mrp_mathlibopen mrp_open_math
#define mrp_dblibopen mrp_open_debug

extern int mr_B_next(mrp_State *L);
extern int mr_B_unpack(mrp_State *L);
extern int mr_B_rawget(mrp_State *L);
extern int mr_B_rawset(mrp_State *L);
extern int mr_B_pairs(mrp_State *L);
extern int mr_B_ipairs(mrp_State *L);


#endif
