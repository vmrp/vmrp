/*
** $Id: lobject.c,v 1.97 2003/04/03 13:35:34 roberto Exp $
** Some generic functions over Lua objects
** See Copyright Notice in lua.h
*/

//#define lobject_c


#include "./h/mr_do.h"
#include "./h/mr_mem.h"
#include "./h/mr_object.h"
#include "./h/mr_state.h"
#include "./h/mr_string.h"
#include "./h/mr_vm.h"




/* function to convert a string to a mrp_Number */
#ifndef mrp_str2number
#define mrp_str2number(s,p)     strtod((s), (p))
#endif


const TObject mr_O_nilobject = {MRP_TNIL, {NULL}};


/*
** converts an integer to a "floating point byte", represented as
** (mmmmmxxx), where the real value is (xxx) * 2^(mmmmm)
*/
int mr_O_int2fb (unsigned int x) {
  int m = 0;  /* mantissa */
  while (x >= (1<<3)) {
    x = (x+1) >> 1;
    m++;
  }
  return (m << 3) | cast(int, x);
}

  static const lu_byte log_8[255] = {
    0,
    1,1,
    2,2,2,2,
    3,3,3,3,3,3,3,3,
    4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,
    5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
    6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
    6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7
  };


int mr_O_log2 (unsigned int x) {
   /*
  static const lu_byte log_8[255] = {
    0,
    1,1,
    2,2,2,2,
    3,3,3,3,3,3,3,3,
    4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,
    5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
    6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
    6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7
  }; */ //ouli brew
  if (x >= 0x00010000) {
    if (x >= 0x01000000) return log_8[((x>>24) & 0xff) - 1]+24;
    else return log_8[((x>>16) & 0xff) - 1]+16;
  }
  else {
    if (x >= 0x00000100) return log_8[((x>>8) & 0xff) - 1]+8;
    else if (x) return log_8[(x & 0xff) - 1];
    return -1;  /* special `log' for 0 */
  }
}


int mr_O_rawequalObj (const TObject *t1, const TObject *t2) {
  if (ttype(t1) != ttype(t2)) return 0;
  else switch (ttype(t1)) {
    case MRP_TNIL:
      return 1;
    case MRP_TNUMBER:
      return nvalue(t1) == nvalue(t2);
    case MRP_TBOOLEAN:
      return bvalue(t1) == bvalue(t2);  /* boolean true must be 1 !! */
    case MRP_TLIGHTUSERDATA:
      return pvalue(t1) == pvalue(t2);
    default:
      mrp_assert(iscollectable(t1));
      return gcvalue(t1) == gcvalue(t2);
  }
}


int mr_O_str2d (const char *s, mrp_Number *result) {
  char *endptr;
  mrp_Number res = mrp_str2number(s, &endptr);
  if (endptr == s) return 0;  /* no conversion */
  while (mr_isspace((unsigned char)(*endptr))) endptr++;
  if (*endptr != '\0') return 0;  /* invalid trailing characters? */
  *result = res;
  return 1;
}



static void pushstr (mrp_State *L, const char *str) {
  setsvalue2s(L->top, mr_S_new(L, str));
  incr_top(L);
}


/* this function handles only `%d', `%c', %f, and `%s' formats */
const char *mr_O_pushvfstring (mrp_State *L, const char *fmt, va_list argp) {
  int n = 1;
  pushstr(L, "");
  for (;;) {
    const char *e = STRCHR(fmt, '%');
    if (e == NULL) break;
    setsvalue2s(L->top, mr_S_newlstr(L, fmt, e-fmt));
    incr_top(L);
    switch (*(e+1)) {
      case 's':
#ifndef MR_TI254_MOD
        pushstr(L, va_arg(argp, char *));
#else
#if 1
      pushstr(L, va_arg(argp, char *));
#else
        pushstr(L,(__va_argref(char*) 						    
	 ? ((argp += sizeof(char**)),(**(char***)(argp-(sizeof(char**)))))    
         : ((sizeof(char*) == sizeof(double)                                  
             ? ((argp += 8), (*(char **)(argp - 8)))                          
             : ((argp += 4), (*(char **)(argp - 4)))))));
#endif
#endif
        break;
      case 'c': {
        char buff[2];
#ifndef MR_TI254_MOD
        buff[0] = cast(char, va_arg(argp, int));
#else
#if 1
         buff[0] = cast(char, va_arg(argp, int));
#else
    buff[0] = cast(char, (__va_argref(int)                       
? ((argp += sizeof(int*)),(**(int**)(argp-(sizeof(int*)))))    
     : ((sizeof(int) == sizeof(double)                                  
         ? ((argp += 8), (*(int*)(argp - 8)))                          
         : ((argp += 4), (*(int*)(argp - 4)))))));
#endif
#endif
        buff[1] = '\0';
        pushstr(L, buff);
        break;
      }
      case 'd':
#ifndef MR_TI254_MOD
        setnvalue(L->top, cast(mrp_Number, va_arg(argp, int)));
#else
#if 1
        setnvalue(L->top, cast(mrp_Number, va_arg(argp, int)));
#else
    setnvalue(L->top, cast(mrp_Number, (__va_argref(int)                       
? ((argp += sizeof(int*)),(**(int**)(argp-(sizeof(int*)))))    
     : ((sizeof(int) == sizeof(double)                                  
         ? ((argp += 8), (*(int*)(argp - 8)))                          
         : ((argp += 4), (*(int*)(argp - 4))))))));
#endif
#endif
        incr_top(L);
        break;
      case 'f':
#ifndef MR_TI254_MOD
        setnvalue(L->top, cast(mrp_Number, va_arg(argp, l_uacNumber)));
#else
#if 1
        setnvalue(L->top, cast(mrp_Number, va_arg(argp, l_uacNumber)));
#else
    setnvalue(L->top, cast(mrp_Number,  (__va_argref(l_uacNumber)                       
? ((argp += sizeof(l_uacNumber*)),(**(l_uacNumber**)(argp-(sizeof(l_uacNumber*)))))    
     : ((sizeof(l_uacNumber) == sizeof(double)                                  
         ? ((argp += 8), (*(l_uacNumber*)(argp - 8)))                          
         : ((argp += 4), (*(l_uacNumber*)(argp - 4))))))));
#endif
#endif
        incr_top(L);
        break;
      case '%':
        pushstr(L, "%");
        break;
      default: mrp_assert(0);
    }
    n += 2;
    fmt = e+2;
  }
  pushstr(L, fmt);
  mr_V_concat(L, n+1, L->top - L->base - 1);
  L->top -= n;
  return svalue(L->top - 1);
}


const char *mr_O_pushfstring (mrp_State *L, const char *fmt, ...) {
  const char *msg;
  va_list argp;
  va_start(argp, fmt);
  msg = mr_O_pushvfstring(L, fmt, argp);
  va_end(argp);
  return msg;
}


void mr_O_chunkid (char *out, const char *source, int bufflen) {
  if (*source == '=') {
    STRNCPY(out, source+1, bufflen);  /* remove first char */
    out[bufflen-1] = '\0';  /* ensures null termination */
  }
  else {  /* out = "source", or "...source" */
    if (*source == '@') {
      int l;
      source++;  /* skip the `@' */
      bufflen -= sizeof(" `...' ");
      l = STRLEN(source);
      STRCPY(out, "");
      if (l>bufflen) {
        source += (l-bufflen);  /* get last part of file name */
        STRCAT(out, "...");
      }
      STRCAT(out, source);
    }
    else {  /* out = [string "string"] */
      int len = STRCSPN(source, "\n");  /* stop at first newline */
      bufflen -= sizeof(" [string \"...\"] ");
      if (len > bufflen) len = bufflen;
      STRCPY(out, "[string \"");
      if (source[len] != '\0') {  /* must truncate? */
        STRNCAT(out, source, len);
        STRCAT(out, "...");
      }
      else
        STRCAT(out, source);
      STRCAT(out, "\"]");
    }
  }
}
