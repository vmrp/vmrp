




#include "../../include/mem.h"
#include "../../include/mythroad.h"



/* This file uses only the official API of Lua.
** Any function declared here could be written as an application function.
*/

//#define lauxlib_c
#include "../../include/mr_auxlib.h"

/* number of prereserved references (for internal use) */
#define RESERVED_REFS	2

/* reserved references */
#define FREELIST_REF	1	/* free list of references */
#define ARRAYSIZE_REF	2	/* array sizes */


/* convert a stack index to positive */
#define abs_index(L, i)		((i) > 0 || (i) <= MRP_REGISTRYINDEX ? (i) : \
					mrp_gettop(L) + (i) + 1)


/*
** {======================================================
** Error-report functions
** =======================================================
*/


MRPLIB_API int mr_L_argerror (mrp_State *L, int narg, const char *extramsg) {
  mrp_Debug ar;
  mrp_getstack(L, 0, &ar);
  mrp_getinfo(L, "n", &ar);
  if (STRCMP(ar.namewhat, "method") == 0) {
    narg--;  /* do not count `self' */
    if (narg == 0)  /* error is in the self argument itself? */
      return mr_L_error(L, "calling `%s' on bad self (%s)", ar.name, extramsg);
  }
  if (ar.name == NULL)
    ar.name = "?";
  return mr_L_error(L, "bad argument #%d to `%s' (%s)",
                        narg, ar.name, extramsg);
}


MRPLIB_API int mr_L_typerror (mrp_State *L, int narg, const char *tname) {
  const char *msg = mrp_pushfstring(L, "%s expected, got %s",
                                    tname, mrp_typename(L, mrp_type(L,narg)));
  return mr_L_argerror(L, narg, msg);
}


static void tag_error (mrp_State *L, int narg, int tag) {
  mr_L_typerror(L, narg, mrp_typename(L, tag)); 
}


MRPLIB_API void mr_L_where (mrp_State *L, int level) {
  mrp_Debug ar;
  if (mrp_getstack(L, level, &ar)) {  /* check function at level */
    mrp_getinfo(L, "Snl", &ar);  /* get info about it */
    if (ar.currentline > 0) {  /* is there info? */
      mrp_pushfstring(L, "%s:%d: ", ar.short_src, ar.currentline);
      return;
    }
  }
  mrp_pushliteral(L, "");  /* else, no information available... */
}


MRPLIB_API int mr_L_error (mrp_State *L, const char *fmt, ...) {
  va_list argp;
  va_start(argp, fmt);
  mr_L_where(L, 1);
  mrp_pushvfstring(L, fmt, argp);
  va_end(argp);
  mrp_concat(L, 2);
  return mrp_error(L);
}

/* }====================================================== */


MRPLIB_API int mr_L_findstring (const char *name, const char *const list[]) {
  int i;
  for (i=0; list[i]; i++)
    if (STRCMP(list[i], name) == 0)
      return i;
  return -1;  /* name not found */
}


MRPLIB_API int mr_L_newmetatable (mrp_State *L, const char *tname) {
  mrp_pushstring(L, tname);
  mrp_rawget(L, MRP_REGISTRYINDEX);  /* get registry.name */
  if (!mrp_isnil(L, -1))  /* name already in use? */
    return 0;  /* leave previous value on top, but return 0 */
  mrp_pop(L, 1);
  mrp_newtable(L);  /* create metatable */
  mrp_pushstring(L, tname);
  mrp_pushvalue(L, -2);
  mrp_rawset(L, MRP_REGISTRYINDEX);  /* registry.name = metatable */
  mrp_pushvalue(L, -1);
  mrp_pushstring(L, tname);
  mrp_rawset(L, MRP_REGISTRYINDEX);  /* registry[metatable] = name */
  return 1;
}


MRPLIB_API void  mr_L_getmetatable (mrp_State *L, const char *tname) {
  mrp_pushstring(L, tname);
  mrp_rawget(L, MRP_REGISTRYINDEX);
}


MRPLIB_API void *mr_L_checkudata (mrp_State *L, int ud, const char *tname) {
  const char *tn;
  if (!mrp_getmetatable(L, ud)) return NULL;  /* no metatable? */
  mrp_rawget(L, MRP_REGISTRYINDEX);  /* get registry[metatable] */
  tn = mrp_tostring(L, -1);
  if (tn && (STRCMP(tn, tname) == 0)) {
    mrp_pop(L, 1);
    return mrp_touserdata(L, ud);
  }
  else {
    mrp_pop(L, 1);
    return NULL;
  }
}


MRPLIB_API void mr_L_checkstack (mrp_State *L, int space, const char *mes) {
  if (!mrp_checkstack(L, space))
    mr_L_error(L, "stack overflow (%s)", mes);
}


MRPLIB_API void mr_L_checktype (mrp_State *L, int narg, int t) {
  if (mrp_type(L, narg) != t)
    tag_error(L, narg, t);
}


MRPLIB_API void mr_L_checkany (mrp_State *L, int narg) {
  if (mrp_type(L, narg) == MRP_TNONE)
    mr_L_argerror(L, narg, "value expected");
}


MRPLIB_API const char *mr_L_checklstring (mrp_State *L, int narg, size_t *len) {
  const char *s = mrp_tostring_t(L, narg);
  if (!s) tag_error(L, narg, MRP_TSTRING);
  if (len) *len = mrp_strlen_t(L, narg);
  return s;
}


MRPLIB_API const char *mr_L_optlstring (mrp_State *L, int narg,
                                        const char *def, size_t *len) {
  if (mrp_isnoneornil(L, narg)) {
    if (len)
      *len = (def ? STRLEN(def) : 0);
    return def;
  }
  else return mr_L_checklstring(L, narg, len);
}


MRPLIB_API mrp_Number mr_L_checknumber (mrp_State *L, int narg) {
  mrp_Number d = mrp_tonumber(L, narg);
  if (d == 0 && !mrp_isnumber(L, narg))  /* avoid extra test when d is not 0 */
    tag_error(L, narg, MRP_TNUMBER);
  return d;
}


MRPLIB_API mrp_Number mr_L_optnumber (mrp_State *L, int narg, mrp_Number def) {
  if (mrp_isnoneornil(L, narg)) return def;
  else return mr_L_checknumber(L, narg);
}


MRPLIB_API int mr_L_getmetafield (mrp_State *L, int obj, const char *event) {
  if (!mrp_getmetatable(L, obj))  /* no metatable? */
    return 0;
  mrp_pushstring(L, event);
  mrp_rawget(L, -2);
  if (mrp_isnil(L, -1)) {
    mrp_pop(L, 2);  /* remove metatable and metafield */
    return 0;
  }
  else {
    mrp_remove(L, -2);  /* remove only metatable */
    return 1;
  }
}


MRPLIB_API int mr_L_callmeta (mrp_State *L, int obj, const char *event) {
  obj = abs_index(L, obj);
  if (!mr_L_getmetafield(L, obj, event))  /* no metafield? */
    return 0;
  mrp_pushvalue(L, obj);
  mrp_call(L, 1, 1);
  return 1;
}


MRPLIB_API void mr_L_openlib (mrp_State *L, const char *libname,
                              const mr_L_reg *l, int nup) {
  if (libname) {
    mrp_pushstring(L, libname);
    mrp_gettable(L, MRP_GLOBALSINDEX);  /* check whether lib already exists */
    if (mrp_isnil(L, -1)) {  /* no? */
      mrp_pop(L, 1);
      mrp_newtable(L);  /* create it */
      mrp_pushstring(L, libname);
      mrp_pushvalue(L, -2);
      mrp_settable(L, MRP_GLOBALSINDEX);  /* register it with given name */
    }
    mrp_insert(L, -(nup+1));  /* move library table to below upvalues */
  }
  for (; l->name; l++) {
    int i;
    mrp_pushstring(L, l->name);
    for (i=0; i<nup; i++)  /* copy upvalues to the top */
      mrp_pushvalue(L, -(nup+1));
    mrp_pushcclosure(L, l->func, nup);
    mrp_settable(L, -(nup+3));
  }
  mrp_pop(L, nup);  /* remove upvalues */
}



/*
** {======================================================
** getn-setn: size for arrays
** =======================================================
*/

static int checkint (mrp_State *L, int topop) {
  int n = (int)mrp_tonumber(L, -1);
  if (n == 0 && !mrp_isnumber(L, -1)) n = -1;
  mrp_pop(L, topop);
  return n;
}


static void getsizes (mrp_State *L) {
  mrp_rawgeti(L, MRP_REGISTRYINDEX, ARRAYSIZE_REF);
  if (mrp_isnil(L, -1)) {  /* no `size' table? */
    mrp_pop(L, 1);  /* remove nil */
    mrp_newtable(L);  /* create it */
    mrp_pushvalue(L, -1);  /* `size' will be its own metatable */
    mrp_setmetatable(L, -2);
    mrp_pushliteral(L, "__mode");
    mrp_pushliteral(L, "k");
    mrp_rawset(L, -3);  /* metatable(N).__mode = "k" */
    mrp_pushvalue(L, -1);
    mrp_rawseti(L, MRP_REGISTRYINDEX, ARRAYSIZE_REF);  /* store in register */
  }
}


void mr_L_setn (mrp_State *L, int t, int n) {
  t = abs_index(L, t);
  mrp_pushliteral(L, "n");
  mrp_rawget(L, t);
  if (checkint(L, 1) >= 0) {  /* is there a numeric field `n'? */
    mrp_pushliteral(L, "n");  /* use it */
    mrp_pushnumber(L, (mrp_Number)n);
    mrp_rawset(L, t);
  }
  else {  /* use `sizes' */
    getsizes(L);
    mrp_pushvalue(L, t);
    mrp_pushnumber(L, (mrp_Number)n);
    mrp_rawset(L, -3);  /* sizes[t] = n */
    mrp_pop(L, 1);  /* remove `sizes' */
  }
}


int mr_L_getn (mrp_State *L, int t) {
  int n;
  t = abs_index(L, t);
  mrp_pushliteral(L, "n");  /* try t.n */
  mrp_rawget(L, t);
  if ((n = checkint(L, 1)) >= 0) return n;
  getsizes(L);  /* else try sizes[t] */
  mrp_pushvalue(L, t);
  mrp_rawget(L, -2);
  if ((n = checkint(L, 2)) >= 0) return n;
  for (n = 1; ; n++) {  /* else must count elements */
    mrp_rawgeti(L, t, n);
    if (mrp_isnil(L, -1)) break;
    mrp_pop(L, 1);
  }
  mrp_pop(L, 1);
  return n - 1;
}

/* }====================================================== */



/*
** {======================================================
** Generic Buffer manipulation
** =======================================================
*/


#define bufflen(B)	((B)->p - (B)->buffer)
#define bufffree(B)	((size_t)(MRP_L_BUFFERSIZE - bufflen(B)))

#define LIMIT	(MRP_MINSTACK/2)


static int emptybuffer (mr_L_Buffer *B) {
  size_t l = bufflen(B);
  if (l == 0) return 0;  /* put nothing on stack */
  else {
    mrp_pushlstring(B->L, B->buffer, l);
    B->p = B->buffer;
    B->lvl++;
    return 1;
  }
}


static void adjuststack (mr_L_Buffer *B) {
  if (B->lvl > 1) {
    mrp_State *L = B->L;
    int toget = 1;  /* number of levels to concat */
    size_t toplen = mrp_strlen(L, -1);
    do {
      size_t l = mrp_strlen(L, -(toget+1));
      if (B->lvl - toget + 1 >= LIMIT || toplen > l) {
        toplen += l;
        toget++;
      }
      else break;
    } while (toget < B->lvl);
    mrp_concat(L, toget);
    B->lvl = B->lvl - toget + 1;
  }
}


MRPLIB_API char *mr_L_prepbuffer (mr_L_Buffer *B) {
  if (emptybuffer(B))
    adjuststack(B);
  return B->buffer;
}


MRPLIB_API void mr_L_addlstring (mr_L_Buffer *B, const char *s, size_t l) {
  while (l--)
    mr_L_putchar(B, *s++);
}


MRPLIB_API void mr_L_addstring (mr_L_Buffer *B, const char *s) {
  mr_L_addlstring(B, s, STRLEN(s));
}


MRPLIB_API void mr_L_pushresult (mr_L_Buffer *B) {
  emptybuffer(B);
  mrp_concat(B->L, B->lvl);
  B->lvl = 1;
}


MRPLIB_API void mr_L_addvalue (mr_L_Buffer *B) {
  mrp_State *L = B->L;
  size_t vl = mrp_strlen(L, -1);
  if (vl <= bufffree(B)) {  /* fit into buffer? */
    MEMCPY(B->p, mrp_tostring(L, -1), vl);  /* put it there *///ouli brew
    B->p += vl;
    mrp_pop(L, 1);  /* remove from stack */
  }
  else {
    if (emptybuffer(B))
      mrp_insert(L, -2);  /* put buffer before new value */
    B->lvl++;  /* add new value into B stack */
    adjuststack(B);
  }
}


MRPLIB_API void mr_L_buffinit (mrp_State *L, mr_L_Buffer *B) {
  B->L = L;
  B->p = B->buffer;
  B->lvl = 0;
}

/* }====================================================== */


MRPLIB_API int mr_L_ref (mrp_State *L, int t) {
  int ref;
  t = abs_index(L, t);
  if (mrp_isnil(L, -1)) {
    mrp_pop(L, 1);  /* remove from stack */
    return MRP_REFNIL;  /* `nil' has a unique fixed reference */
  }
  mrp_rawgeti(L, t, FREELIST_REF);  /* get first free element */
  ref = (int)mrp_tonumber(L, -1);  /* ref = t[FREELIST_REF] */
  mrp_pop(L, 1);  /* remove it from stack */
  if (ref != 0) {  /* any free element? */
    mrp_rawgeti(L, t, ref);  /* remove it from list */
    mrp_rawseti(L, t, FREELIST_REF);  /* (t[FREELIST_REF] = t[ref]) */
  }
  else {  /* no free elements */
    ref = mr_L_getn(L, t);
    if (ref < RESERVED_REFS)
      ref = RESERVED_REFS;  /* skip reserved references */
    ref++;  /* create new reference */
    mr_L_setn(L, t, ref);
  }
  mrp_rawseti(L, t, ref);
  return ref;
}


MRPLIB_API void mr_L_unref (mrp_State *L, int t, int ref) {
  if (ref >= 0) {
    t = abs_index(L, t);
    mrp_rawgeti(L, t, FREELIST_REF);
    mrp_rawseti(L, t, ref);  /* t[ref] = t[FREELIST_REF] */
    mrp_pushnumber(L, (mrp_Number)ref);
    mrp_rawseti(L, t, FREELIST_REF);  /* t[FREELIST_REF] = ref */
  }
}



/*
** {======================================================
** Load functions
** =======================================================
*/





typedef struct LoadS {
  const char *s;
  size_t size;
} LoadS;


static const char *getS (mrp_State *L, void *ud, size_t *size) {
  LoadS *ls = (LoadS *)ud;
  (void)L;
  if (ls->size == 0) return NULL;
  *size = ls->size;
  ls->size = 0;
  return ls->s;
}

#if 0
static const char *getF (mrp_State *L, void *ud, size_t *size) {
#ifdef PC_MOD
   LoadF *lf = (LoadF *)ud;
   (void)L;
   if (feof(lf->f)) return NULL;
   *size = fread(lf->buff, 1, MRP_L_BUFFERSIZE, lf->f);
   return (*size > 0) ? lf->buff : NULL;
#endif

#ifdef TARGET_MOD
  LoadF *lf = (LoadF *)ud;
  (void)L;

///*               change for zip

  //ouli brew
//  if (feof(lf->f)) return NULL;
//  *size = fread(lf->buff, 1, MRP_L_BUFFERSIZE, lf->f);
  *size = mr_read ( lf->f,
                   (void*)(lf->buff),
                   MRP_L_BUFFERSIZE);
  //LUADBGPRINTF("ffs_read");
  //MmiTraceInt(*size);
  return (*size > 0) ? lf->buff : NULL;
//*/
#endif

#ifdef BREW_MOD

  LoadF *lf = (LoadF *)ud;
  (void)L;
  //ouli brew
//  if (feof(lf->f)) return NULL;
//  *size = fread(lf->buff, 1, MRP_L_BUFFERSIZE, lf->f);
  *size = IUNZIPASTREAM_Read(lf->pUnzip, lf->buff, MRP_L_BUFFERSIZE);
   return (*size > 0) ? lf->buff : NULL;
#endif

#if 0 //brew mod do not use zip
  LoadF *lf = (LoadF *)ud;
  (void)L;
  //ouli brew
//  if (feof(lf->f)) return NULL;
//  *size = fread(lf->buff, 1, MRP_L_BUFFERSIZE, lf->f);
  *size = IFILE_Read(lf->f, lf->buff, MRP_L_BUFFERSIZE);
  return (*size > 0) ? lf->buff : NULL;
#endif
}
#endif

static int errfile (mrp_State *L, int fnameindex) {
  const char *filename = mrp_tostring(L, fnameindex) + 1;
//ouli important
  mrp_pushfstring(L, "cannot read %s", filename);
  mrp_remove(L, fnameindex);
  return MRP_ERRFILE;
}



MRPLIB_API int mr_L_loadfile (mrp_State *L, const char *filename) {
#ifdef PC_MOD
   LoadF lf;
   int status, readstatus;
   int c;
   int fnameindex = mrp_gettop(L) + 1;  /* index of filename on the stack */
   if (filename == NULL) {
     mrp_pushliteral(L, "=stdin");
     lf.f = stdin;
   }
   else {
     mrp_pushfstring(L, "@%s", filename);
     lf.f = fopen(filename, "r");
   }
   if (lf.f == NULL) return errfile(L, fnameindex);  /* unable to open file */
   c = ungetc(getc(lf.f), lf.f);
   if (!(mr_isspace(c) || mr_isprint(c)) && lf.f != stdin) {  /* binary file? */
     fclose(lf.f);
     lf.f = fopen(filename, "rb");  /* reopen in binary mode */
     if (lf.f == NULL) return errfile(L, fnameindex); /* unable to reopen file */
   }
   status = mrp_load(L, getF, &lf, mrp_tostring(L, -1));
   readstatus = ferror(lf.f);
   if (lf.f != stdin) fclose(lf.f);  /* close file (even in case of errors) */
   if (readstatus) {
     mrp_settop(L, fnameindex);  /* ignore results from `mrp_load' */
     return errfile(L, fnameindex);
   }
   mrp_remove(L, fnameindex);
   return status;
#endif  //#ifdef PC_MOD


#ifdef TARGET_MOD
   //LoadF lf;
   int status, readstatus;
//  int c;
   int fnameindex = mrp_gettop(L) + 1;  /* index of filename on the stack */
   void* buff;
   int filelen;
   
   LUADBGPRINTF("mr_L_loadfile sart");

   // Open the file for writing using the generated file name
   mrp_pushfstring(L, "@%s", filename);
   
//  change for zip
   buff = _mr_readFile((const char *)filename, &filelen, 0);

   if (!buff)
      {
      mrp_settop(L, fnameindex);  /* ignore results from `mrp_load' */
      
      LUADBGPRINTF("_mr_readFile Failed");
      return errfile(L, fnameindex);
      }

   {
      LoadS ls;
      ls.s = buff;
      ls.size = filelen;
      status = mrp_load(L, getS, &ls, mrp_tostring(L, -1));
   }
   MR_FREE(buff, filelen);
   LUADBGPRINTF("after free");
   readstatus = 0;

/*               change for zip
   lf.f = ffs_open(filebuf, FFS_O_RDONLY );
   //lf.f = fopen(filename, "r");
   if (lf.f < EFFS_OK)
   {
      LUADBGPRINTF("ffs_open failed!********");
      return errfile(L, fnameindex);  
   }
   LUADBGPRINTF("ffs_open ok");
   	
  status = mrp_load(L, getF, &lf, mrp_tostring(L, -1));

   LUADBGPRINTF("After mrp_load");

  readstatus = 0;
   ffs_close(lf.f);
*/

//ouli brew
  if (readstatus) {
    mrp_settop(L, fnameindex);  /* ignore results from `mrp_load' */

    LUADBGPRINTF("mr_L_loadfile error");
    return errfile(L, fnameindex);
  }
  LUADBGPRINTF("before rm");
  mrp_remove(L, fnameindex);
  LUADBGPRINTF("after rm");

  LUADBGPRINTF("mr_L_loadfile end");
  return status;
#endif  //#ifdef TARGET_MOD else

#ifdef BREW_MOD
   LoadF lf;
  int status, readstatus;
  int fnameindex = mrp_gettop(L) + 1;  /* index of filename on the stack */

   LegendGameApp *pLegendGame = (LegendGameApp *)GETAPPINSTANCE();

   LUADBGPRINTF("mr_L_loadfile sart");

   // Open the file for writing using the generated file name
   mrp_pushfstring(L, "@%s", filename);

#if 0
   lf.f = IFILEMGR_OpenFile( pLegendGame->pFileMgr, filename, _OFM_READ );
   if (lf.f == NULL)
   {
      LUADBGPRINTF("IFILEMGR_OpenFile failed!********");
   	//IFILEMGR_Release( pFileMgr );
      return errfile(L, fnameindex);  /* unable to open file */
   }
   LUADBGPRINTF("IFILEMGR_OpenFile ok");
#endif
//   LoadF lf;
   lf.f = GetFileStream(filename);
   if (lf.f == NULL)
   {
      LUADBGPRINTF("IFILEMGR_OpenFile failed!********");
   	//IFILEMGR_Release( pFileMgr );
      return errfile(L, fnameindex);  /* unable to open file */
   }

   IUNZIPASTREAM_SetStream ( pLegendGame->pUnzip, 
       (IAStream *)lf.f );
   lf.pUnzip = pLegendGame->pUnzip;
  status = mrp_load(L, getF, &lf, mrp_tostring(L, -1));

   LUADBGPRINTF("After mrp_load");

  readstatus = 0;
   IFILE_Release(lf.f);//ouli brew
   
  if (readstatus) {
    mrp_settop(L, fnameindex);  /* ignore results from `mrp_load' */

    LUADBGPRINTF("mr_L_loadfile error");
    return errfile(L, fnameindex);
  }
  mrp_remove(L, fnameindex);

  LUADBGPRINTF("mr_L_loadfile end");
  return status;

#endif //BREW_MOD


#if 0 //brew mod do not use zip
   LoadF lf;
  int status, readstatus;
//  int c;
  int fnameindex = mrp_gettop(L) + 1;  /* index of filename on the stack */
//ouli brew
  //IFileMgr* pFileMgr = NULL;

   LegendGameApp *pLegendGame = (LegendGameApp *)GETAPPINSTANCE();

   LUADBGPRINTF("mr_L_loadfile sart");

   // Open the file for writing using the generated file name
   mrp_pushfstring(L, "@%s", filename);

/*
   if ( ISHELL_CreateInstance(pLegendGame->a.m_pIShell, AEECLSID_FILEMGR, (void**)(&pFileMgr)) != SUCCESS )
   {
      mrp_pushfstring(L, "cannot create FILEMGR");
      mrp_remove(L, fnameindex);
      return MRP_ERRFILE;
   }

*/
   

   lf.f = IFILEMGR_OpenFile( pLegendGame->pFileMgr, filename, _OFM_READ );
   //lf.f = fopen(filename, "r");
   if (lf.f == NULL)
   {
      LUADBGPRINTF("IFILEMGR_OpenFile failed!********");
   	//IFILEMGR_Release( pFileMgr );
      return errfile(L, fnameindex);  /* unable to open file */
   }
   LUADBGPRINTF("IFILEMGR_OpenFile ok");
   	
   //IFILEMGR_Release( pFileMgr );

  //if (lf.f == NULL) return errfile(L, fnameindex);  /* unable to open file */

//ouli brew
//  c = ungetc(getc(lf.f), lf.f);
//  if (!(mr_isspace(c) || mr_isprint(c)) ) {  /* binary file? */
//    fclose(lf.f);
//    lf.f = fopen(filename, "rb");  /* reopen in binary mode */
//    if (lf.f == NULL) return errfile(L, fnameindex); /* unable to reopen file */
//  }
  status = mrp_load(L, getF, &lf, mrp_tostring(L, -1));

   LUADBGPRINTF("After mrp_load");

  //readstatus = ferror(lf.f);
  readstatus = 0;
  //fclose(lf.f);  /* close file (even in case of errors) */
   IFILE_Release(lf.f);//ouli brew
//ouli brew
  if (readstatus) {
    mrp_settop(L, fnameindex);  /* ignore results from `mrp_load' */

    LUADBGPRINTF("mr_L_loadfile error");
    return errfile(L, fnameindex);
  }
  mrp_remove(L, fnameindex);

  LUADBGPRINTF("mr_L_loadfile end");
  return status;

#endif  //brew mod do not use zip
  

}


MRPLIB_API int mr_L_loadbuffer (mrp_State *L, const char *buff, size_t size,
                                const char *name) {
  LoadS ls;
  ls.s = buff;
  ls.size = size;
  return mrp_load(L, getS, &ls, name);
}

/* }====================================================== */


/*
** {======================================================
** compatibility code
** =======================================================
*/

#if 0
static void callalert (mrp_State *L, int status) {
  if (status != 0) {
    mrp_getglobal(L, "_ALERT");
    if (mrp_isfunction(L, -1)) {
      mrp_insert(L, -2);
      mrp_call(L, 1, 0);
    }
    else {  /* no _ALERT function; print it on stderr */
      //fprintf(stderr, "%s\n", mrp_tostring(L, -2));  //ouli
      MRDBGPRINTF( mrp_tostring(L, -2));  
      mrp_pop(L, 2);  /* remove error message and _ALERT */
    }
  }
}
#endif


static int mr_aux_do (mrp_State *L, int status) {
  LUADBGPRINTF("mr_aux_do start");
#if 0
  if (status == 0) {  /* parse OK? */
    status = mrp_pcall(L, 0, MRP_MULTRET, 0);  /* call main */
  }
  callalert(L, status);
#else
   if (status == 0) {  /* parse OK? */
      _mr_pcall(0,MRP_MULTRET);
   }
#endif
  LUADBGPRINTF("mr_aux_do end");
  return status;
}


MRPLIB_API int mrp_dofile (mrp_State *L, const char *filename) {
  return mr_aux_do(L, mr_L_loadfile(L, filename));
}


MRPLIB_API int mrp_dobuffer (mrp_State *L, const char *buff, size_t size,
                          const char *name) {
  return mr_aux_do(L, mr_L_loadbuffer(L, buff, size, name));
}


MRPLIB_API int mrp_dostring (mrp_State *L, const char *str) {
  return mrp_dobuffer(L, str, STRLEN(str), str);
}

/* }====================================================== */
