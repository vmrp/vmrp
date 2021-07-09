
#include "mr.h"
#include "mr_auxlib.h"
#include "mr_lib.h"

#undef LOADLIB


#ifdef USE_DLOPEN
#define LOADLIB
/*
* This is an implementation of loadlib based on the dlfcn interface.
* The dlfcn interface is available in Linux, SunOS, Solaris, IRIX, FreeBSD,
* NetBSD, AIX 4.2, HPUX 11, and  probably most other Unix flavors, at least
* as an emulation layer on top of native functions.
*/


static int loadlib(mrp_State *L)
{
 const char *path=mr_L_checkstring(L,1);
 const char *init=mr_L_checkstring(L,2);
 void *lib=dlopen(path,RTLD_NOW);
 if (lib!=NULL)
 {
  mrp_CFunction f=(mrp_CFunction) dlsym(lib,init);
  if (f!=NULL)
  {
   mrp_pushlightuserdata(L,lib);
   mrp_pushcclosure(L,f,1);
   return 1;
  }
 }
 /* else return appropriate error messages */
 mrp_pushnil(L);
 mrp_pushstring(L,dlerror());
 mrp_pushstring(L,(lib!=NULL) ? "init" : "open");
 if (lib!=NULL) dlclose(lib);
 return 3;
}

#endif



/*
** In Windows, default is to use dll; otherwise, default is not to use dll
*/
#ifndef USE_DLL
#ifdef _WIN32
#define USE_DLL	1
#else
#define USE_DLL	0
#endif
#endif


#if USE_DLL
#define LOADLIB
/*
* This is an implementation of loadlib for Windows using native functions.
*/


static void pusherror(mrp_State *L)
{
 int error=GetLastError();
 char buffer[128];
 if (FormatMessage(FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM,
	0, error, 0, buffer, sizeof(buffer), 0))
  mrp_pushstring(L,buffer);
 else
  mrp_pushfstring(L,"system error %d\n",error);
}

static int loadlib(mrp_State *L)
{
 const char *path=mr_L_checkstring(L,1);
 const char *init=mr_L_checkstring(L,2);
 HINSTANCE lib=LoadLibrary(path);
 if (lib!=NULL)
 {
  mrp_CFunction f=(mrp_CFunction) GetProcAddress(lib,init);
  if (f!=NULL)
  {
   mrp_pushlightuserdata(L,lib);
   mrp_pushcclosure(L,f,1);
   return 1;
  }
 }
 mrp_pushnil(L);
 pusherror(L);
 mrp_pushstring(L,(lib!=NULL) ? "init" : "open");
 if (lib!=NULL) FreeLibrary(lib);
 return 3;
}

#endif



#ifndef LOADLIB
/* Fallback for other systems */

/*
** Those systems support dlopen, so they should have defined USE_DLOPEN.
** The default (no)implementation gives them a special error message.
*/
#ifdef linux
#define LOADLIB
#endif

#ifdef sun
#define LOADLIB
#endif

#ifdef sgi
#define LOADLIB
#endif

#ifdef BSD
#define LOADLIB
#endif

#ifdef _WIN32
#define LOADLIB
#endif

#ifdef LOADLIB
#undef LOADLIB
#define LOADLIB	"`loadlib' not installed (check your Lua configuration)"
#else
#define LOADLIB	"`loadlib' not supported"
#endif

static int loadlib(mrp_State *L)
{
 mrp_pushnil(L);
 mrp_pushliteral(L,LOADLIB);
 mrp_pushliteral(L,"absent");
 return 3;
}
#endif

MRPLIB_API int mrp_open_loadlib (mrp_State *L)
{
 mrp_register(L,"loadlib",loadlib);
 return 0;
}

/*
* Here are some links to available implementations of dlfcn and
* interfaces to other native dynamic loaders on top of which loadlib
* could be implemented. Please send contributions and corrections to us.
*
* AIX
* Starting with AIX 4.2, dlfcn is included in the base OS.
* There is also an emulation package available.
* http://www.faqs.org/faqs/aix-faq/part4/section-21.html
*
* HPUX 
* HPUX 11 has dlfcn. For HPUX 10 use shl_*.
* http://www.geda.seul.org/mailinglist/geda-dev37/msg00094.html
* http://www.stat.umn.edu/~luke/xls/projects/dlbasics/dlbasics.html
*
* Macintosh, Windows
* http://www.stat.umn.edu/~luke/xls/projects/dlbasics/dlbasics.html
*
* Mac OS X/Darwin
* http://www.opendarwin.org/projects/dlcompat/
*
* GLIB has wrapper code for BeOS, OS2, Unix and Windows
* http://cvs.gnome.org/lxr/source/glib/gmodule/
*
*/
