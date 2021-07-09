

//#define ldblib_c

#include "mr.h"

#include "mr_auxlib.h"
#include "mr_lib.h"

#include "mythroad.h"

extern mr_bitmapSt  mr_bitmap[BITMAPMAX+1];
extern mr_tileSt    mr_tile[TILEMAX];
extern int16*       mr_map[TILEMAX];
extern mr_soundSt  mr_sound[SOUNDMAX];



static void settabss (mrp_State *L, const char *i, const char *v) {
  mrp_pushstring(L, i);
  mrp_pushstring(L, v);
  mrp_rawset(L, -3);
}


static void settabsi (mrp_State *L, const char *i, int v) {
  mrp_pushstring(L, i);
  mrp_pushnumber(L, (mrp_Number)v);
  mrp_rawset(L, -3);
}


static int getinfo (mrp_State *L) {
  mrp_Debug ar;
  const char *options = mr_L_optstring(L, 2, "flnSu");
  if (mrp_isnumber(L, 1)) {
    if (!mrp_getstack(L, (int)(mrp_tonumber(L, 1)), &ar)) {
      mrp_pushnil(L);  /* level out of range */
      return 1;
    }
  }
  else if (mrp_isfunction(L, 1)) {
    mrp_pushfstring(L, ">%s", options);
    options = mrp_tostring(L, -1);
    mrp_pushvalue(L, 1);
  }
  else
    return mr_L_argerror(L, 1, "function or level expected");
  if (!mrp_getinfo(L, options, &ar))
    return mr_L_argerror(L, 2, "invalid option");
  mrp_newtable(L);
  for (; *options; options++) {
    switch (*options) {
      case 'S':
        settabss(L, "source", ar.source);
        settabss(L, "short_src", ar.short_src);
        settabsi(L, "linedefined", ar.linedefined);
        settabss(L, "what", ar.what);
        break;
      case 'l':
        settabsi(L, "currentline", ar.currentline);
        break;
      case 'u':
        settabsi(L, "nups", ar.nups);
        break;
      case 'n':
        settabss(L, "name", ar.name);
        settabss(L, "namewhat", ar.namewhat);
        break;
      case 'f':
        mrp_pushliteral(L, "func");
        mrp_pushvalue(L, -3);
        mrp_rawset(L, -3);
        break;
    }
  }
  return 1;  /* return table */
}
    

static int getlocal (mrp_State *L) {
  mrp_Debug ar;
  const char *name;
  if (!mrp_getstack(L, mr_L_checkint(L, 1), &ar))  /* level out of range? */
    return mr_L_argerror(L, 1, "level out of range");
  name = mrp_getlocal(L, &ar, mr_L_checkint(L, 2));
  if (name) {
    mrp_pushstring(L, name);
    mrp_pushvalue(L, -2);
    return 2;
  }
  else {
    mrp_pushnil(L);
    return 1;
  }
}


static int setlocal (mrp_State *L) {
  mrp_Debug ar;
  if (!mrp_getstack(L, mr_L_checkint(L, 1), &ar))  /* level out of range? */
    return mr_L_argerror(L, 1, "level out of range");
  mr_L_checkany(L, 3);
  mrp_pushstring(L, mrp_setlocal(L, &ar, mr_L_checkint(L, 2)));
  return 1;
}


static int mr_auxupvalue (mrp_State *L, int get) {
  const char *name;
  int n = mr_L_checkint(L, 2);
  mr_L_checktype(L, 1, MRP_TFUNCTION);
  if (mrp_iscfunction(L, 1)) return 0;  /* cannot touch C upvalues from vm */
  name = get ? mrp_getupvalue(L, 1, n) : mrp_setupvalue(L, 1, n);
  if (name == NULL) return 0;
  mrp_pushstring(L, name);
  mrp_insert(L, -(get+1));
  return get + 1;
}


static int getupvalue (mrp_State *L) {
  return mr_auxupvalue(L, 1);
}


static int setupvalue (mrp_State *L) {
  mr_L_checkany(L, 3);
  return mr_auxupvalue(L, 0);
}



static const char KEY_HOOK = 'h';


  static const char *const hooknames[] =
    {"call", "return", "line", "count", "tail return"};

static void hookf (mrp_State *L, mrp_Debug *ar) {
   /*
  static const char *const hooknames[] =
    {"call", "return", "line", "count", "tail return"};
    */ //ouli brew
  mrp_pushlightuserdata(L, (void *)&KEY_HOOK);
  mrp_rawget(L, MRP_REGISTRYINDEX);
  if (mrp_isfunction(L, -1)) {
    mrp_pushstring(L, hooknames[(int)ar->event]);
    if (ar->currentline >= 0)
      mrp_pushnumber(L, (mrp_Number)ar->currentline);
    else mrp_pushnil(L);
    mrp_assert(mrp_getinfo(L, "lS", ar));
    mrp_call(L, 2, 0);
  }
  else
    mrp_pop(L, 1);  /* pop result from gettable */
}


static int makemask (const char *smask, int count) {
  int mask = 0;
  if (STRCHR(smask, 'c')) mask |= MRP_MASKCALL;
  if (STRCHR(smask, 'r')) mask |= MRP_MASKRET;
  if (STRCHR(smask, 'l')) mask |= MRP_MASKLINE;
  if (count > 0) mask |= MRP_MASKCOUNT;
  return mask;
}


static char *unmakemask (int mask, char *smask) {
  int i = 0;
  if (mask & MRP_MASKCALL) smask[i++] = 'c';
  if (mask & MRP_MASKRET) smask[i++] = 'r';
  if (mask & MRP_MASKLINE) smask[i++] = 'l';
  smask[i] = '\0';
  return smask;
}


static int sethook (mrp_State *L) {
  if (mrp_isnoneornil(L, 1)) {
    mrp_settop(L, 1);
    mrp_sethook(L, NULL, 0, 0);  /* turn off hooks */
  }
  else {
    const char *smask = mr_L_checkstring(L, 2);
    int count = mr_L_optint(L, 3, 0);
    mr_L_checktype(L, 1, MRP_TFUNCTION);
    mrp_sethook(L, hookf, makemask(smask, count), count);
  }
  mrp_pushlightuserdata(L, (void *)&KEY_HOOK);
  mrp_pushvalue(L, 1);
  mrp_rawset(L, MRP_REGISTRYINDEX);  /* set new hook */
  return 0;
}


static int gethook (mrp_State *L) {
  char buff[5];
  int mask = mrp_gethookmask(L);
  mrp_Hook hook = mrp_gethook(L);
  if (hook != NULL && hook != hookf)  /* external hook? */
    mrp_pushliteral(L, "external hook");
  else {
    mrp_pushlightuserdata(L, (void *)&KEY_HOOK);
    mrp_rawget(L, MRP_REGISTRYINDEX);   /* get hook */
  }
  mrp_pushstring(L, unmakemask(mask, buff));
  mrp_pushnumber(L, (mrp_Number)mrp_gethookcount(L));
  return 3;
}


static int debug (mrp_State *L) {
//ouli brew
/*
  for (;;) {
    char buffer[250];
    //fputs("mrp_debug> ", stderr);
    DBGPRINTF("mrp_debug> ");
    if (fgets(buffer, sizeof(buffer), stdin) == 0 ||
        STRCMP(buffer, "cont\n") == 0)
      return 0;
    mrp_dostring(L, buffer);
    mrp_settop(L, 0);  /* remove eventual returns */  /*
  }
*/
//ouli brew
   return 0;
}


#define LEVELS1	12	/* size of the first part of the stack */
#define LEVELS2	10	/* size of the second part of the stack */

static int errorfb (mrp_State *L) {
  int level = 1;  /* skip level 0 (it's this function) */
  int firstpart = 1;  /* still before eventual `...' */
  mrp_Debug ar;
  if (mrp_gettop(L) == 0)
    mrp_pushliteral(L, "");
  else if (!mrp_isstring(L, 1)) return 1;  /* no string message */
  else mrp_pushliteral(L, "\n");
    mrp_pushliteral(L, "stack information:");
  while (mrp_getstack(L, level++, &ar)) {
    if (level > LEVELS1 && firstpart) {
      /* no more than `LEVELS2' more levels? */
      if (!mrp_getstack(L, level+LEVELS2, &ar))
        level--;  /* keep going */
      else {
        mrp_pushliteral(L, "\r\n   ...");  /* too many levels */
        while (mrp_getstack(L, level+LEVELS2, &ar))  /* find last levels */
          level++;
      }
      firstpart = 0;
      continue;
    }
    mrp_pushliteral(L, "\r\n   ");
    mrp_getinfo(L, "Snl", &ar);
    mrp_pushfstring(L, "File '%s'  ,  ", ar.short_src);
    if (ar.currentline > 0)
      mrp_pushfstring(L, "Line %d  ,  ", ar.currentline);
    switch (*ar.namewhat) {
      case 'g':  /* global */ 
      case 'l':  /* local */
      case 'f':  /* field */
      case 'm':  /* method */
        mrp_pushfstring(L, " in `%s'", ar.name);
        break;
      default: {
        if (*ar.what == 'm')  /* main? */
          mrp_pushfstring(L, " in 'root'");
        else if (*ar.what == 'C' || *ar.what == 'i')
          mrp_pushliteral(L, " ?");  /* C function or tail call */
        else
          mrp_pushfstring(L, " in '%s' , %d",
                             ar.short_src, ar.linedefined);
      }
    }
    mrp_concat(L, mrp_gettop(L));
  }
  mrp_concat(L, mrp_gettop(L));
  return 1;
}


static int bitmapinfo (mrp_State *L) {
   int i,total = 0;
   mrp_pushliteral(L, "Bitmaps:\r\n");

   for(i=0;i<BITMAPMAX;i++)
   {
      if(mr_bitmap[i].p)
      {
         mrp_pushfstring(L, "  bitmap[%d]: %d bytes\r\n", i, mr_bitmap[i].buflen);
         total = total + mr_bitmap[i].buflen;
      }
   }

   if(mr_bitmap[BITMAPMAX].type == MR_SCREEN_SECOND_BUF) {
   //if(1) {
      mrp_pushfstring(L, "Screen Buf in secend buffer:%d bytes\r\n", mr_bitmap[BITMAPMAX].buflen);
   }else{
      mrp_pushfstring(L, "  Screen Buf: %d bytes\r\n", mr_bitmap[BITMAPMAX].buflen);
      total = total + mr_bitmap[BITMAPMAX].buflen;
   }
   mrp_pushfstring(L, "  Bitmaps Total: %d bytes\r\n", total);
   
   mrp_concat(L, mrp_gettop(L));
   return 1;
}

static int mapinfo (mrp_State *L) {
   int i,total = 0;
   mrp_pushliteral(L, "Maps:\r\n");
   for(i=0;i<TILEMAX;i++)
   {
      if(mr_map[i])
      {
         mrp_pushfstring(L, "  map[%d]: %d bytes\r\n", i, mr_tile[i].w*mr_tile[i].h*2);
         total = total + mr_tile[i].w*mr_tile[i].h*2;
      }
   }
   mrp_pushfstring(L, "  Maps Total: %d bytes\r\n", total);
   
   mrp_concat(L, mrp_gettop(L));
   return 1;
}

static int soundinfo (mrp_State *L) {
   int i,total = 0;
   mrp_pushliteral(L, "Sounds:\r\n");
   for(i=0;i<SOUNDMAX;i++)
   {
      if(mr_sound[i].p)
      {
         mrp_pushfstring(L, "  sound[%d]: %d bytes\r\n", i, mr_sound[i].buflen);
         total = total + mr_sound[i].buflen;
      }
   }
   
   mrp_pushfstring(L, "  Sounds Total: %d bytes\r\n", total);
   
   mrp_concat(L, mrp_gettop(L));
   return 1;
}



static const mr_L_reg dblib[] = {
//  {"getlocal", getlocal},
//  {"getinfo", getinfo},
//  {"gethook", gethook},
//  {"getupvalue", getupvalue},
//  {"sethook", sethook},
//  {"setlocal", setlocal},
//  {"setupvalue", setupvalue},
//  {"debug", debug},
   {"bitmapinfo", bitmapinfo},
   {"mapinfo", mapinfo},
   {"soundinfo", soundinfo},
   {"traceback", errorfb},
   {NULL, NULL}
};


MRPLIB_API int mrp_open_debug (mrp_State *L) {
  mr_L_openlib(L, MRP_DBLIBNAME, dblib, 0);
  //mrp_pushliteral(L, "_TRACEBACK");
  //mrp_pushcfunction(L, errorfb);
  //mrp_settable(L, MRP_GLOBALSINDEX);
  return 1;
}

