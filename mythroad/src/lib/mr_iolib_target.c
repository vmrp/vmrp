/*
** $Id: liolib.c,v 2.39a 2003/03/19 21:16:12 roberto Exp $
** Standard I/O (and system) library
** See Copyright Notice in lua.h
*/



//#define liolib_c

#include "../../tomr/tomr.h"
#include "../../include/mr_helper.h"
#include "../../include/mr_auxlib.h"
#include "../../include/mr_lib.h"
#include "../../include/mrporting.h"
#include "../../include/mythroad.h"

#include "../h/mr_gc.h"
#include "../h/mr_string.h"
#include "../h/mr_mem.h"


#define FILE int32


/*
** {======================================================
** FILE Operations
** =======================================================
*/

static mr_L_reg filelib[5];
static mr_L_reg flib[7];


#define FILEHANDLE		"file*"

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
      mrp_pushfstring(L, "file err: %s: %d", filename, mr_ferrno());
    else
      mrp_pushfstring(L, "file err:%d", mr_ferrno());
    mrp_pushnumber(L, mr_ferrno());
    return 3;
  }
}


static FILE *topfile (mrp_State *L, int findex) {
  FILE *f = (FILE *)mr_L_checkudata(L, findex, FILEHANDLE);
  if (f == NULL) mr_L_argerror(L, findex, "bad file");
  return f;
}


static int io_type (mrp_State *L) {
  FILE *f = (FILE *)mr_L_checkudata(L, 1, FILEHANDLE);
  if (f == NULL) mrp_pushnumber(L, MR_FILE_STATE_NIL);
  else if (*f == 0)
    mrp_pushnumber(L, MR_FILE_STATE_CLOSED);
  else
    mrp_pushnumber(L, MR_FILE_STATE_OPEN);
  return 1;
}


static FILE tofile (mrp_State *L, int findex) {
  FILE *f = topfile(L, findex);
  if (*f == 0)
    mr_L_error(L, "attempt to use a closed file");
  return *f;
}



/*
** When creating file handles, always creates a `closed' file handle
** before opening the actual file; so, if there is a memory error, the
** file is not left opened.
*/
static FILE *newfile (mrp_State *L) {
  FILE *pf = (FILE *)mrp_newuserdata(L, sizeof(FILE));
  *pf = 0;  /* file handle is currently `closed' */
  mr_L_getmetatable(L, FILEHANDLE);
  mrp_setmetatable(L, -2);
  return pf;
}



static int mr_aux_close (mrp_State *L) {
   FILE f = tofile(L, 1);
   int ok = (mr_close(f) == 0);
   if (ok)
     *(FILE *)mrp_touserdata(L, 1) = 0;  /* mark file as closed */
   return ok;
}


static int io_close (mrp_State *L) {
/*
  if (mrp_isnone(L, 1) && mrp_type(L, mrp_upvalueindex(1)) == MRP_TTABLE) {
    mrp_pushstring(L, IO_OUTPUT);
    mrp_rawget(L, mrp_upvalueindex(1));
  }
*/
  return pushresult(L, mr_aux_close(L), NULL);
}


static int io_gc (mrp_State *L) {
  FILE *f = topfile(L, 1);
  if (*f != 0)  /* ignore closed files */
    mr_aux_close(L);
  return 0;
}


static int io_tostring (mrp_State *L) {
  char buff[128];
  FILE *f = topfile(L, 1);
  if (*f == 0)
    STRCPY(buff, "closed");
  else
    SPRINTF(buff, "%p", mrp_touserdata(L, 1));
  mrp_pushfstring(L, "file (%s)", buff);
  return 1;
}


static int io_open (mrp_State *L) {
  const char *filename = mr_L_checkstring(L, 1);
  long mode = mr_L_optlong(L, 2, MR_FILE_RDONLY);
  FILE *pf = newfile(L);

  *pf = mr_open (filename, mode);
  return (*pf == 0) ? pushresult(L, 0, filename) : 1;
}


/*
static FILE getiofile (mrp_State *L, const char *name) {
  mrp_pushstring(L, name);
  mrp_rawget(L, mrp_upvalueindex(1));
  return tofile(L, -1);
}
*/


/*
** {======================================================
** READ
** =======================================================
*/

static int read_chars (mrp_State *L, FILE f, size_t n) {
  size_t rlen;  /* how much to read */
  size_t nr;  /* number of chars actually read */
  mr_L_Buffer b;
  mr_L_buffinit(L, &b);
  rlen = MRP_L_BUFFERSIZE;  /* try to read that much each time */
  do {
    char *p = mr_L_prepbuffer(&b);
    if (rlen > n) rlen = n;  /* cannot read more than asked */
    nr = mr_read( f, p, rlen);
    mr_L_addsize(&b, nr);
    n -= nr;  /* still have to read `n' chars */
  } while (n > 0 && nr == rlen);  /* until end of count or eof */
  mr_L_pushresult(&b);  /* close buffer */
  return (n == 0 || mrp_strlen(L, -1) > 0);
}



static int io_readAll (mrp_State *L) {
   char* filename = (char*)  mrp_tostring(L, 1);
   int32 ret,filelen,f,oldlen;
   uint8 * p;
   char* filebuf;

   ret = mr_info(filename);
   if((ret != MR_IS_FILE))
   {
     return 0;
   }

   filelen = mr_getLen(filename);
   if (filelen <= 0)
   {
     return 0;
   }

   f = mr_open(filename, MR_FILE_RDONLY );
   if (f == 0)
   {
     return 0;
   }
  

  p = (uint8 *)mr_M_malloc(L, sizestring(filelen));

   if(p==0)
   {
      mr_close(f);
      return 0;
   }
  
  MEMSET(p, 0, sizestring(filelen));
  mrp_lock(L);
  mr_C_checkGC(L);
  setsvalue2s(L->top, _mr_newlstr_without_malloc(L, p, filelen));
  api_incr_top(L);
  mrp_unlock(L);

  filebuf = (char*)((TString *)p + 1);
  oldlen = 0;
  while(oldlen < filelen){
     ret = mr_read(f, (char*)filebuf+oldlen, filelen-oldlen);
     if (ret <= 0)
     {
         //MR_FREE(filebuf, filelen);
         mr_close(f);
         //_mr_readFileShowInfo(filename, 3009);
         return 0;
     }
     oldlen = oldlen + ret;
  }


  
  mr_close(f);
  return 1;
}


static int g_read (mrp_State *L, FILE f, int first) {
  int nargs = mrp_gettop(L) - 1;
  int success;
  int n;

  mr_L_checkstack(L, nargs+MRP_MINSTACK, "too many arguments");

  success = 1;
  for (n = first; nargs-- && success; n++) {
     if (mrp_type(L, n) == MRP_TNUMBER) {
        size_t l = (size_t)mrp_tonumber(L, n);
        success = read_chars(L, f, l);
     }
  }
  if (!success) {
    mrp_pop(L, 1);  /* remove last result */
    mrp_pushnil(L);  /* push nil instead */
  }
  return n - first;
}

/*
static int io_read (mrp_State *L) {
  return g_read(L, getiofile(L, IO_INPUT), 1);
}
*/

static int f_read (mrp_State *L) {
  return g_read(L, tofile(L, 1), 2);
}

/* }====================================================== */


static int g_write (mrp_State *L, FILE f, int arg) {
  int nargs = mrp_gettop(L) - 1;
  int status = 1;
  for (; nargs--; arg++) {
   size_t l;
   const char *s = mr_L_checklstring(L, arg, &l);
   status = status && (mr_write (f, (void*)s, (uint32)l) == (int32)l);
  }
  return pushresult(L, status, NULL);
}

/*
static int io_write (mrp_State *L) {
  return g_write(L, getiofile(L, IO_OUTPUT), 1);
}
*/

static int f_write (mrp_State *L) {
  return g_write(L, tofile(L, 1), 2);
}

static int f_seek (mrp_State *L) {
   /*
  static const int mode[] = {SEEK_SET, SEEK_CUR, SEEK_END};
  static const char *const modenames[] = {"set", "cur", "end", NULL};
  */ //ouli brew
  FILE f = tofile(L, 1);
  int op = mr_L_optint(L, 2, 0);
  long offset = mr_L_optlong(L, 3, 0);
  //op = fseek(f, offset, mode[op]);
  op = mr_seek (f, offset, op);
  if (op != 0)
    return pushresult(L, 0, NULL);  /* error */
  else {
    mrp_pushnumber(L, offset);
    return 1;
  }
}

static void createfilemeta (mrp_State *L) {
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

static int io_remove (mrp_State *L) {
  const char *filename = mr_L_checkstring(L, 1);
  return pushresult(L, mr_remove(filename) == 0, filename);
}


static int io_rename (mrp_State *L) {
  const char *fromname = mr_L_checkstring(L, 1);
  const char *toname = mr_L_checkstring(L, 2);
  return pushresult(L, mr_rename(fromname, toname) == 0, fromname);
}

static int io_getuptime (mrp_State *L) {
  mrp_pushnumber(L, mr_getTime());
  return 1;
}

static int io_mkdir (mrp_State *L) {
  const char *filename = mr_L_checkstring(L, 1);
  return pushresult(L, mr_mkDir(filename) == 0, filename);
}

static int io_rmdir (mrp_State *L) {
  const char *filename = mr_L_checkstring(L, 1);
  return pushresult(L, mr_rmDir(filename) == 0, filename);
}

static int io_getfileinfo (mrp_State *L) {
  const char *filename = mr_L_checkstring(L, 1);
  mrp_pushnumber(L, mr_info(filename));
  return 1;
}

static int io_getfilelen (mrp_State *L) {
  const char *filename = mr_L_checkstring(L, 1);
  mrp_pushnumber(L, mr_getLen(filename));
  return 1;
}

static int io_findstart (mrp_State *L) {
  char buf[MR_MAX_FILENAME_SIZE];
  const char *filename = mr_L_checkstring(L, 1);
  MEMSET(buf, 0, sizeof(buf));
  mrp_pushnumber(L, mr_findStart(filename, buf, sizeof(buf)));
  mrp_pushstring(L, buf);
  return 2;
}

static int io_findnext (mrp_State *L) {
  char buf[MR_MAX_FILENAME_SIZE];
  int32 h = (int32)mr_L_optlong(L, 1, 0);
  int32 ret = mr_findGetNext(h, buf, sizeof(buf));
  if (ret == MR_SUCCESS)
    mrp_pushstring(L, buf);
  else
    mrp_pushnil(L);
  return 1;
}

static int io_findstop (mrp_State *L) {
  int32 h = (int32)mr_L_optlong(L, 1, 0);
  mrp_pushnumber(L, mr_findStop(h));
  return 1;
}

//ouli
//#define MR_AUTO_UNICODE

static int MenuCreate(mrp_State *L)
{
   const char* title = (const char*)mr_L_checkstring(L, 1);
   int16 num = (int16)mr_L_optlong(L, 2, 0);
   int tempret=0;

#ifdef MR_AUTO_UNICODE
   int TextSize;
   uint16 *tempBuf;
   tempBuf = c2u((const char*)title, NULL, &TextSize);
   if (!tempBuf)
   {
      mrp_pushfstring(L, "MenuCreate num=%d:c2u err!",num);
      mrp_error(L);
      return;
   }

   tempret = mr_menuCreate((const char*)tempBuf, num);
#else
   tempret = mr_menuCreate((const char*)title, num);
#endif

   if(tempret > 0)
   {
      mrp_pushnumber(L, tempret);
   }else
   {
      mrp_pushnil(L);
   }
#ifdef MR_AUTO_UNICODE
   MR_FREE((void *)tempBuf, TextSize);
#endif
   return 1;
}

static int MenuAddItem(mrp_State *L)
{
   int32 menu = (int32)mr_L_optlong(L, 1, 0);
   const char* text = (const char*)mr_L_checkstring(L, 2);
   int32 index = (int32)mr_L_optlong(L, 3, 0);
   int tempret=0;
   
#ifdef MR_AUTO_UNICODE
   int TextSize;
   uint16 *tempBuf;
   tempBuf = c2u((const char*)text, NULL, &TextSize); 
   if (!tempBuf)
   {
      mrp_pushfstring(L, "MenuAddItem index=%d:c2u err!",index);
      mrp_error(L);
      return;
   }

   tempret = mr_menuSetItem(menu, (const char*)tempBuf,  index);
#else
   tempret = mr_menuSetItem(menu, (const char*)text,  index);
#endif

   if(tempret == MR_SUCCESS)
   {
      mrp_pushnumber(L, tempret);
   }else
   {
      mrp_pushnil(L);
   }
#ifdef MR_AUTO_UNICODE
   MR_FREE((void *)tempBuf, TextSize);
#endif
   return 1;
}

static int MenuShow(mrp_State *L)
{
   int32 menu = (int32)mr_L_optlong(L, 1, 0);
   int tempret=0;
   tempret = mr_menuShow(menu);
   if(tempret == MR_SUCCESS)
   {
      mrp_pushnumber(L, tempret);
   }else
   {
      mrp_pushnil(L);
   }
   return 1;
}

static int MenuSetFocus(mrp_State *L)
{
#ifdef GUI_RECREATE_MOD
   int32 menu = (int32)mr_L_optlong(L, 1, 0);
   int32 index = (int32)mr_L_optlong(L, 2, 0);
   int tempret=0;
   tempret = mr_menuSetFocus(menu, index);
   if(tempret == MR_SUCCESS)
   {
      mrp_pushnumber(L, tempret);
   }else
   {
      mrp_pushnil(L);
   }
   return 1;
#else
   mrp_pushnil(L);
   return 1;
#endif
}

static int MenuRefresh(mrp_State *L)
{
#ifndef GUI_NONE_REFRESH
   int32 menu = (int32)mr_L_optlong(L, 1, 0);
   int32 tempret;
   tempret = mr_menuRefresh(menu);
   if(tempret == MR_SUCCESS)
   {
      mrp_pushnumber(L, tempret);
   }else
   {
      mrp_pushnil(L);
   }
   return 1;
#else
   mrp_pushnil(L);
   return 1;
#endif
}

static int MenuRelease(mrp_State *L)
{
   int32 menu = (int32)mr_L_optlong(L, 1, 0);
   int tempret=0;
   tempret = mr_menuRelease(menu);
   if(tempret == MR_SUCCESS)
   {
      mrp_pushnumber(L, tempret);
   }else
   {
      mrp_pushnil(L);
   }
   return 1;
}

static int DialogCreate(mrp_State *L)
{
   const char* title = (const char*)mr_L_checkstring(L, 1);
   const char* text = (const char*)mr_L_checkstring(L, 2);
   int32 type = mr_L_optlong(L, 3, 0);
   int tempret=0;

   tempret = mr_dialogCreate((const char*)title, text, type);

   if(tempret > 0)
   {
      mrp_pushnumber(L, tempret);
   }else
   {
      mrp_pushnil(L);
   }
   return 1;
}

static int DialogRelease(mrp_State *L)
{
   int32 dialog = (int32)mr_L_optlong(L, 1, 0);
   int tempret=0;
   tempret = mr_dialogRelease(dialog);
   if(tempret == MR_SUCCESS)
   {
      mrp_pushnumber(L, tempret);
   }else
   {
      mrp_pushnil(L);
   }
   return 1;
}

static int DialogRefresh(mrp_State *L)
{
#ifndef GUI_NONE_REFRESH
   int32 dialog = (int32)mr_L_optlong(L, 1, 0);
   const char* title = (const char*)mr_L_checkstring(L, 2);
   const char* text = (const char*)mr_L_checkstring(L, 3);
   int32 type = mr_L_optlong(L, 4, -1);
   int tempret=0;

   tempret = mr_dialogRefresh(dialog, (const char*)title, text, type);

   if(tempret > 0)
   {
      mrp_pushnumber(L, tempret);
   }else
   {
      mrp_pushnil(L);
   }
   return 1;
#else
   mrp_pushnil(L);
   return 1;
#endif
}


static int TextCreate(mrp_State *L)
{
   const char* title = (const char*)mr_L_checkstring(L, 1);
   const char* text = (const char*)mr_L_checkstring(L, 2);
   int32 type = mr_L_optlong(L, 3, 0);
   int tempret=0;

   tempret = mr_textCreate((const char*)title, text, type);

   if(tempret > 0)
   {
      mrp_pushnumber(L, tempret);
   }else
   {
      mrp_pushnil(L);
   }
   return 1;
}

static int TextRelease(mrp_State *L)
{
   int32 dialog = (int32)mr_L_optlong(L, 1, 0);
   int tempret=0;
   tempret = mr_textRelease(dialog);
   if(tempret == MR_SUCCESS)
   {
      mrp_pushnumber(L, tempret);
   }else
   {
      mrp_pushnil(L);
   }
   return 1;
}

static int TextRefresh(mrp_State *L)
{
#ifndef GUI_NONE_REFRESH
   int32 dialog = (int32)mr_L_optlong(L, 1, 0);
   const char* title = (const char*)mr_L_checkstring(L, 2);
   const char* text = (const char*)mr_L_checkstring(L, 3);
   int tempret=0;

   tempret = mr_textRefresh(dialog, (const char*)title, text);

   if(tempret > 0)
   {
      mrp_pushnumber(L, tempret);
   }else
   {
      mrp_pushnil(L);
   }
   return 1;
#else
   mrp_pushnil(L);
   return 1;
#endif
}

static int EditCreate(mrp_State *L)
{
   const char* title = (const char*)mr_L_checkstring(L, 1);
   const char* text = (const char*)mr_L_checkstring(L, 2);
   int32 type = mr_L_optlong(L, 3, 0);
   int32 max_size = mr_L_optlong(L, 4, 68);
   int tempret=0;

   tempret = mr_editCreate((const char*)title, text, type, max_size);

   if(tempret > 0)
   {
      mrp_pushnumber(L, tempret);
   }else
   {
      mrp_pushnil(L);
   }
   return 1;
}

static int EditRelease(mrp_State *L)
{
   int32 dialog = (int32)mr_L_optlong(L, 1, 0);
   int tempret=0;
   tempret = mr_editRelease(dialog);
   if(tempret == MR_SUCCESS)
   {
      mrp_pushnumber(L, tempret);
   }else
   {
      mrp_pushnil(L);
   }
   return 1;
}

static int EditGetText(mrp_State *L)
{
   int32 dialog = (int32)mr_L_optlong(L, 1, 0);
   const char* tempret=NULL;
   tempret = mr_editGetText(dialog);
   if(tempret == NULL)
   {
      mrp_pushnil(L);
   }else
   {
      mrp_pushlstring(L, tempret, mr_wstrlen((char *)tempret)+2);
   }
   return 1;
}


static int WinCreate(mrp_State *L)
{
   //const char* title = (const char*)mr_L_checkstring(L, 1);
   //const char* text = (const char*)mr_L_checkstring(L, 2);
   //int32 type = mr_L_optlong(L, 3, 0);
   //int32 max_size = mr_L_optlong(L, 4, 68);
   int tempret=0;

   tempret = mr_winCreate();

   if(tempret > 0)
   {
      mrp_pushnumber(L, tempret);
   }else
   {
      mrp_pushnil(L);
   }
   return 1;
}

static int WinRelease(mrp_State *L)
{
   int32 dialog = (int32)mr_L_optlong(L, 1, 0);
   int tempret=0;
   tempret = mr_winRelease(dialog);
   if(tempret == MR_SUCCESS)
   {
      mrp_pushnumber(L, tempret);
   }else
   {
      mrp_pushnil(L);
   }
   return 1;
}

/* }====================================================== */

static  mr_L_reg syslib[22];
static  mr_L_reg guilib[20];


MRPLIB_API int mrp_open_file (mrp_State *L) {
   mr_L_openlib(L, MR_GUILIBNAME, guilib, 0);
   mr_L_openlib(L, MRP_SYSLIBNAME, syslib, 0);
   createfilemeta(L);
   mrp_pushvalue(L, -1);
   mr_L_openlib(L, MRP_FILELIBNAME, filelib, 1);
   LUADBGPRINTF("file lib");
  return 1;
}

void mr_iolib_target_init(void) {
    filelib[0].name = "close", filelib[0].func = io_close;
    filelib[1].name = "open", filelib[1].func = io_open;
    //{"read", io_read},
    filelib[2].name = "state", filelib[2].func = io_type;
    //{"write", io_write},
    filelib[3].name = "readAll", filelib[3].func = io_readAll;
    filelib[4].name = NULL, filelib[4].func = NULL;

    /////////////////////////////////////////////////////////////

    flib[0].name = "read", flib[0].func = f_read;
    flib[1].name = "seek", flib[1].func = f_seek;
    flib[2].name = "write", flib[2].func = f_write;
    flib[3].name = "close", flib[3].func = io_close;
    flib[4].name = "__gc", flib[4].func = io_gc;
    flib[5].name = "__str", flib[5].func = io_tostring;
    flib[6].name = NULL, flib[6].func = NULL;

    /////////////////////////////////////////////////////////////

    syslib[0].name = "getUptime", syslib[0].func = io_getuptime;
    syslib[1].name = "rm", syslib[1].func = io_remove;
    syslib[2].name = "mkDir", syslib[2].func = io_mkdir;
    syslib[3].name = "rmDir", syslib[3].func = io_rmdir;
    syslib[4].name = "getFileInfo", syslib[4].func = io_getfileinfo;
    syslib[5].name = "getFileLen", syslib[5].func = io_getfilelen;
    syslib[6].name = "findStart", syslib[6].func = io_findstart;
    syslib[7].name = "findNext", syslib[7].func = io_findnext;
    syslib[8].name = "findStop", syslib[8].func = io_findstop;
    syslib[9].name = "getInfo", syslib[9].func = _mr_GetSysInfo;
    syslib[10].name = "datetime", syslib[10].func = _mr_GetDatetime;
#ifdef COMPATIBILITY01
    syslib[11].name = "getuptime", syslib[11].func = io_getuptime;
    syslib[12].name = "remove", syslib[12].func = io_remove;
    syslib[13].name = "rename", syslib[13].func = io_rename;
    syslib[14].name = "mkdir", syslib[14].func = io_mkdir;
    syslib[15].name = "rmdir", syslib[15].func = io_rmdir;
    syslib[16].name = "getfileinfo", syslib[16].func = io_getfileinfo;
    syslib[17].name = "getfilelen", syslib[17].func = io_getfilelen;
    syslib[18].name = "findstart", syslib[18].func = io_findstart;
    syslib[19].name = "findnext", syslib[19].func = io_findnext;
    syslib[20].name = "findstop", syslib[20].func = io_findstop;
#endif
    syslib[21].name = NULL, syslib[21].func = NULL;

    /////////////////////////////////////////////////////////////

    guilib[0].name = "m_create", guilib[0].func = MenuCreate;
    guilib[1].name = "m_setItem", guilib[1].func = MenuAddItem;
    guilib[2].name = "m_show", guilib[2].func = MenuShow;
    guilib[3].name = "m_release", guilib[3].func = MenuRelease;
    guilib[4].name = "m_focus", guilib[4].func = MenuSetFocus;
    guilib[5].name = "d_create", guilib[5].func = DialogCreate;
    guilib[6].name = "d_release", guilib[6].func = DialogRelease;
    guilib[7].name = "t_create", guilib[7].func = TextCreate;
    guilib[8].name = "t_release", guilib[8].func = TextRelease;
#ifndef GUI_NONE_REFRESH
    guilib[9].name = "m_update", guilib[9].func = MenuRefresh;
    guilib[10].name = "d_update", guilib[10].func = DialogRefresh;
    guilib[11].name = "t_update", guilib[11].func = TextRefresh;
#endif
    guilib[12].name = "e_create", guilib[12].func = EditCreate;
    guilib[13].name = "e_release", guilib[13].func = EditRelease;
    guilib[14].name = "e_getText", guilib[14].func = EditGetText;
    guilib[15].name = "w_create", guilib[15].func = WinCreate;
    guilib[16].name = "w_release", guilib[16].func = WinRelease;
#ifdef COMPATIBILITY01
    guilib[17].name = "m_setitem", guilib[17].func = MenuAddItem;
    guilib[18].name = "e_gettext", guilib[18].func = EditGetText;
#endif
    guilib[19].name = NULL, guilib[19].func = NULL;
}
