#ifndef MR_SOCKET_H
#define MR_SOCKET_H
/*=========================================================================*\
* LuaSocket toolkit
* Networking support for the Lua language
* Diego Nehab
* 9/11/1999
*
* RCS ID: $Id: luasocket.h,v 1.19 2005/01/02 22:44:00 diego Exp $
\*=========================================================================*/
#include "mr.h"

/*-------------------------------------------------------------------------*\
* Current luasocket version
\*-------------------------------------------------------------------------*/
#define MRP_SOCKET_VERSION    "MythroadSocket 1.0"
#define MRP_SOCKET_COPYRIGHT  "Copyright"
#define MRP_SOCKET_AUTHORS    " "

/*-------------------------------------------------------------------------*\
* This macro prefixes all exported API functions
\*-------------------------------------------------------------------------*/
#ifndef MRP_SOCKET_API
#define MRP_SOCKET_API extern
#endif

/*-------------------------------------------------------------------------*\
* Initializes the library.
\*-------------------------------------------------------------------------*/
   MRP_SOCKET_API int mropen_socket(mrp_State *L, const char *mode);


#endif /* MRP_SOCKET_H */
