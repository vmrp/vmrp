/*
** $Id: lstrlib.c,v 1.98 2003/04/03 13:35:34 roberto Exp $
** Standard library for string operations and pattern-matching
** See Copyright Notice in lua.h
*/


#include "../../include/mem.h"
#include "../../include/mr_auxlib.h"
#include "../../include/mr_lib.h"
#include "../../include/mythroad.h"

#include "../h/mr_string.h"
#include "../h/mr_gc.h"
#include "../h/mr_mem.h"


/* macro to `unsign' a character */
#ifndef uchar
#define uchar(c)        ((unsigned char)(c))
#endif


typedef long sint32;	/* a signed version for size_t */

int mr_isdigit(int ch) {
    return (ch >= '0') && (ch <= '9');
}

int mr_isxdigit(int ch) {
    return ((ch >= '0') && (ch <= '9')) || ((ch >= 'a') && (ch <= 'f')) || ((ch >= 'A') && (ch <= 'F'));
}

int mr_isalpha(int ch) {
    return ((ch >= 'a') && (ch <= 'z')) || ((ch >= 'A') && (ch <= 'Z'));
}

int mr_islower(int ch) {
    return (ch >= 'a') && (ch <= 'z');
}

int mr_isspace(int ch) {
    return (ch == ' ') || (ch == '\t') || (ch == '\r') || (ch == '\n') || (ch == '\f') || (ch == '\v');
}

int mr_toupper(int ch) {
    if ((unsigned int)(ch - 'a') < 26u)
        ch += 'A' - 'a';
    return ch;
}

int mr_tolower(int ch) {
    if ((unsigned int)(ch - 'A') < 26u)
        ch += 'a' - 'A';
    return ch;
}

int mr_iscntrl(int ch) {
    return (unsigned int)ch < 32u || ch == 127;
}

int mr_isalnum(int ch) {
    return (unsigned int)((ch | 0x20) - 'a') < 26u || (unsigned int)(ch - '0') < 10u;
}

int mr_isupper(int ch) {
    return (unsigned int)(ch - 'A') < 26u;
}

int mr_isprint(int ch) {
    return (unsigned int)(ch - ' ') < 127u - ' ';
}

int mr_ispunct(int ch) {
    return mr_isprint(ch) && !mr_isalnum(ch) && !mr_isspace(ch);
}

//////////-------------------------------------------------


/*
** Library for packing/unpacking structures.
**
** Valid formats:
** x - pading
** b/B - signed/unsigned byte
** h/H - signed/unsigned short
** l/L - signed/unsigned long
** i/In - signed/unsigned integer with size `n' (default is size of int)
** cn - sequence of `n' chars (from/to a string); when packing, n==0 means
        the whole string; when unpacking, n==0 means use the previous
        read number as the string length
** s - zero-terminated string
** f - float
** d - doulbe
*/



/* dummy structure to get alignment requirements */
struct cD {
  char c;
  int d;
};


static int getmaxalign (void) {
  int ma = sizeof(int);
  int e = sizeof(struct cD) - sizeof(int);
  if (ma < e) ma = e;
  return ma;
}


static int getendianess (const char **s, int *native_out) {
  int endian;  /* 0 = little; 1 = big */
  int native = 1;
  if (*(char *)&native == 1)
    native = 0;
  if (**s == '>') {
    endian = 1;
    (*s)++;
  }
  else if (**s == '<') {
    endian = 0;
    (*s)++;
  }
  else
    endian = native;
  *native_out = native;
  return endian;
}

static int getnum (const char **fmt, int df) {
  if (!mr_isdigit(**fmt))
    return df;  /* no number */
  else {
    int a = 0;
    do {
      a = a*10 + *((*fmt)++) - '0';
    } while (mr_isdigit(**fmt));
    return a;
  }
}

static int optsize (char opt, const char **fmt) {
  switch (opt) {
    case 'B': case 'b': return 1;
    case 'H': case 'h': return 2;
    case 'i': case 'I': return 4;
    case 'x': return 1;
    case 'l': case 'L': {
      int tmp = getnum(fmt, sizeof(int));
      tmp = (tmp > sizeof(int))? sizeof(int):tmp;
      return tmp;
    }
    case 'c': return getnum(fmt, 1);
    case 's': case 'p': return 0;
    default: return 1;  /* invalid code */
  }
}

static int getalign (const char **fmt) {
  if (**fmt != '@') return 1;  /* no alignment */
  else {
    (*fmt)++;
    return getnum(fmt, getmaxalign());
  }
}

static int gettoalign (mrp_State *L, int align, int opt, int size) {
  int toalign = (opt == 'c' || opt == 's' || opt == 'p') ? 1 : size;
  if (toalign > align) toalign = align;
  if (toalign == 0 || (toalign & (toalign - 1)) != 0)
    mr_L_error(L, "alignment must be 2^n");
  return toalign;
}

static void putinteger (mrp_State *L, mr_L_Buffer *b, int arg, int endian,
                        int size) {
  unsigned char buff[sizeof(long)];
  mrp_Number n = mr_L_checknumber(L, arg);
  unsigned long value;
  unsigned char *s;
  int inc, i;
  if (n < 0) {
    value = (unsigned long)(-n);
    value = (~value) + 1;  /* 2's complement */
  }
  else
    value = (unsigned long)n;
  if (endian == 0) {
    inc = 1;
    s = buff;
  }
  else {
    inc = -1;
    s = buff+(size-1);
  }
  for (i=0; i<size; i++) {
    *s = (unsigned char)(value & 0xff);
    s += inc;
    value >>= 8;
  }
  mr_L_addlstring(b, (char *)buff, size);
}

#if 0
static void invertbytes (char *b, int size) {
  int i = 0;
  while (i < --size) {
    char temp = b[i];
    b[i++] = b[size];
    b[size] = temp;
  }
}
#endif


static void invalidformat (mrp_State *L, char c) {
  const char *msg = mrp_pushfstring(L, "invalid format '%c'", c);
  mr_L_argerror(L, 1, msg);
}


static int b_size (mrp_State *L) {
  int native;
  const char *fmt = mr_L_checkstring(L, 1);
  int align;
  int totalsize = 0;
  getendianess(&fmt, &native);
  align = getalign(&fmt);
  while (*fmt) {
    int opt = *fmt++;
    int size = optsize(opt, &fmt);
    int toalign = gettoalign(L, align, opt, size);
    if (size == 0)
      mr_L_error(L, "meet size 0, check 'c' , 's' or 'p'");
    totalsize += toalign - 1;
    totalsize -= totalsize&(toalign-1);
    totalsize += size;
  }
  mrp_pushnumber(L, totalsize);
  return 1;
}


static int b_pack (mrp_State *L) {
  mr_L_Buffer b;
  int native;
  const char *fmt = mr_L_checkstring(L, 1);
  int endian = getendianess(&fmt, &native);
  int align = getalign(&fmt);
  int arg = 2;
  int totalsize = 0;
  mrp_pushnil(L);  /* mark to separate arguments from string buffer */
  mr_L_buffinit(L, &b);
  for (; *fmt; arg++) {
    int opt = *fmt++;
    int size = optsize(opt, &fmt);
    int toalign = gettoalign(L, align, opt, size);
    while ((totalsize&(toalign-1)) != 0) {
       mr_L_putchar(&b, '\0');
       totalsize++;
    }
    switch (opt) {
      case ' ': break;  /* ignore white spaces */
      case 'b': case 'B': case 'h': case 'H':
      case 'l': case 'L': case 'i': case 'I': {  /* integer types */
        putinteger(L, &b, arg, endian, size);
        break;
      }
      case 'x': {
        arg--;  /* undo increment */
        mr_L_putchar(&b, '\0');
        break;
      }
      case 'c': case 's': case 'p':{
        size_t l;
        const char *s = mr_L_checklstring(L, arg, &l);
        if (size == 0) size = l;
#if 0
         mr_L_argcheck(L, l >= (size_t)size, arg, "string too short");
         mr_L_addlstring(&b, s, size);
#else
         if(l < (size_t)size){
            char * temp_buf = MR_MALLOC(size);
            if (temp_buf){
               MEMSET(temp_buf, 0, size);
               MEMCPY(temp_buf, s, l);
               mr_L_addlstring(&b, temp_buf, size);
               MR_FREE(temp_buf, size);
            }else{
               mr_L_addlstring(&b, s, size);
            }
         }else{
            mr_L_addlstring(&b, s, size);
         }
#endif
        if (opt == 's') {
          mr_L_putchar(&b, '\0');  /* add zero at the end */
          size++;
        }
        break;
      }
      default: invalidformat(L, opt);
    }
    totalsize += size;
  }
  mr_L_pushresult(&b);
  return 1;
}


static void getinteger (mrp_State *L, const char *buff, int endian,
                        int withsign, int size) {
  unsigned long l = 0;
  int i, inc;
  if (endian == 1)
    inc = 1;
  else {
    inc = -1;
    buff += size-1;
  }
  for (i=0; i<size; i++) {
    l = (l<<8) + (unsigned char)(*buff);
    buff += inc;
  }
  if (withsign) {  /* signed format? */
    unsigned long mask = ~(0UL) << (size*8 - 1);
    if (l & mask) {  /* negative value? */
      l = (l^~(mask<<1)) + 1;
      mrp_pushnumber(L, -(mrp_Number)l);
      return;
    }
  }
  mrp_pushnumber(L, l);
}

static int b_unpack (mrp_State *L) {
  int native;
  const char *fmt = mr_L_checkstring(L, 1);
  size_t ld;
  const char *data = mr_L_checklstring(L, 2, &ld);
  int pos = mr_L_optint(L, 3, 1) - 1;
  int endian = getendianess(&fmt, &native);
  int align = getalign(&fmt);
  mrp_settop(L, 2);
  while (*fmt) {
    int opt = *fmt++;
    int size = optsize(opt, &fmt);
    int toalign = gettoalign(L, align, opt, size);
    pos += toalign - 1;
    pos -= pos&(toalign-1);
    mr_L_argcheck(L, pos+size <= (int)ld, 2, "unpack:input too short");
    switch (opt) {
      case ' ': break;  /* ignore white spaces */
      case 'b': case 'B': case 'h': case 'H':
      case 'l': case 'L': case 'i':  case 'I': {  /* integer types */
        int withsign = mr_islower(opt);
        getinteger(L, data+pos, endian, withsign, size);
        break;
      }
      case 'x': {
        break;
      }
      case 'c': {
        mrp_pushlstring(L, data+pos, size);
        break;
      }
      case 'p':{
         if (!mrp_isnumber(L, -1))
           mr_L_error(L, "previous size for `p' missing");
         size = mrp_tonumber(L, -1);
         //mrp_pop(L, 1);
         mr_L_argcheck(L, pos+size <= (int)ld, 2, "unpack:input too short");
         mrp_pushlstring(L, data+pos, size);
         break;
      }
      case 's': {
        const char *e = (const char *)MEMCHR(data+pos, '\0', ld - pos);
        if (e == NULL)
          mr_L_error(L, "unfinished string in input");
        size = (e - (data+pos)) + 1;
        mrp_pushlstring(L, data+pos, size - 1);
        break;
      }
      default: invalidformat(L, opt);
    }
    pos += size;
  }
  mrp_pushnumber(L, pos + 1);
  return mrp_gettop(L) - 2;
}

/////--------------------------------------------




static int str_len (mrp_State *L) {
  size_t l;
  mr_L_checklstring(L, 1, &l);
  mrp_pushnumber(L, (mrp_Number)l);
  return 1;
}

static int str_clen (mrp_State *L) {
  int32 l;
  int32 clen;
  char * p = (char*)mr_L_checklstring(L, 1, (size_t*)&l);
  clen = STRLEN(p);
  l = (l > clen)? clen:l;
  mrp_pushnumber(L, (mrp_Number)l);
  return 1;
}

static int str_wlen (mrp_State *L) {
  int32 l;
  int32 clen;
  char * p = (char*)mr_L_checklstring(L, 1, (size_t*)&l);
  clen = mr_wstrlen(p);
  l = (l > clen)? clen:l;
  mrp_pushnumber(L, (mrp_Number)l);
  return 1;
}

static int str_cstr (mrp_State *L) {
   int32 l;
   int32 clen;
   char * p = (char*)mr_L_checklstring(L, 1, (size_t*)&l);
   clen = STRLEN(p);
   l = (l > clen)? clen:l;
   mrp_pushlstring(L, p, l);
   return 1;
}

static int str_wstr (mrp_State *L) {
   int32 l;
   int32 clen;
   char * p = (char*)mr_L_checklstring(L, 1, (size_t*)&l);
   clen = mr_wstrlen(p);
   l = (l > clen)? clen:l;
   mrp_pushlstring(L, p, l);
   return 1;
}


static sint32 posrelat (sint32 pos, size_t len) {
  /* relative string position: negative means back from end */
  return (pos>=0) ? pos : (sint32)len+pos+1;
}


static int str_sub (mrp_State *L) {
  size_t l;
  const char *s = mr_L_checklstring(L, 1, (size_t*)&l);
  sint32 start = posrelat(mr_L_checklong(L, 2), l);
  sint32 end = posrelat(mr_L_optlong(L, 3, -1), l);
  if (start < 1) start = 1;
  if (end > (sint32)l) end = (sint32)l;
  if (start <= end)
    mrp_pushlstring(L, s+start-1, end-start+1);
  else mrp_pushliteral(L, "");
  return 1;
}


static int str_lower (mrp_State *L) {
  size_t l;
  size_t i;
  mr_L_Buffer b;
  const char *s = mr_L_checklstring(L, 1, (size_t*)&l);
  mr_L_buffinit(L, &b);
  for (i=0; i<l; i++)
    mr_L_putchar(&b, mr_tolower(uchar(s[i])));
  mr_L_pushresult(&b);
  return 1;
}


static int str_upper (mrp_State *L) {
  size_t l;
  size_t i;
  mr_L_Buffer b;
  const char *s = mr_L_checklstring(L, 1, &l);
  mr_L_buffinit(L, &b);
  for (i=0; i<l; i++)
    mr_L_putchar(&b, mr_toupper(uchar(s[i])));
  mr_L_pushresult(&b);
  return 1;
}

static int str_rep (mrp_State *L) {
  size_t l;
  mr_L_Buffer b;
  const char *s = mr_L_checklstring(L, 1, &l);
  int n = mr_L_checkint(L, 2);
  mr_L_buffinit(L, &b);
  while (n-- > 0)
    mr_L_addlstring(&b, s, l);
  mr_L_pushresult(&b);
  return 1;
}


static int str_byte (mrp_State *L) {
  size_t l;
  const char *s = mr_L_checklstring(L, 1, &l);
  sint32 pos = posrelat(mr_L_optlong(L, 2, 1), l);
  if (pos <= 0 || (size_t)(pos) > l)  /* index out of range? */
    return 0;  /* no answer */
  mrp_pushnumber(L, uchar(s[pos-1]));
  return 1;
}


static int str_char (mrp_State *L) {
  int n = mrp_gettop(L);  /* number of arguments */
  int i;
  mr_L_Buffer b;
  mr_L_buffinit(L, &b);
  for (i=1; i<=n; i++) {
    int c = mr_L_checkint(L, i);
    mr_L_argcheck(L, uchar(c) == c, i, "invalid value");
    mr_L_putchar(&b, uchar(c));
  }
  mr_L_pushresult(&b);
  return 1;
}


static int writer (mrp_State *L, const void* b, size_t size, void* B) {
  (void)L;
  mr_L_addlstring((mr_L_Buffer*) B, (const char *)b, size);
  return 1;
}


static int str_dump (mrp_State *L) {
  mr_L_Buffer b;
  mr_L_checktype(L, 1, MRP_TFUNCTION);
  mr_L_buffinit(L,&b);
  if (!mrp_dump(L, writer, &b))
    mr_L_error(L, "unable to dump given function");
  mr_L_pushresult(&b);
  return 1;
}



/*
** {======================================================
** PATTERN MATCHING
** =======================================================
*/

#ifndef MAX_CAPTURES
#define MAX_CAPTURES 32  /* arbitrary limit */
#endif


#define CAP_UNFINISHED	(-1)
#define CAP_POSITION	(-2)

typedef struct MatchState {
  const char *src_init;  /* init of source string */
  const char *src_end;  /* end (`\0') of source string */
  mrp_State *L;
  int level;  /* total number of captures (finished or unfinished) */
  struct {
    const char *init;
    sint32 len;
  } capture[MAX_CAPTURES];
} MatchState;


#define ESC		'%'
#define SPECIALS	"^$*+?.([%-"


static int check_capture (MatchState *ms, int l) {
  l -= '1';
  if (l < 0 || l >= ms->level || ms->capture[l].len == CAP_UNFINISHED)
    return mr_L_error(ms->L, "invalid capture index");
  return l;
}


static int capture_to_close (MatchState *ms) {
  int level = ms->level;
  for (level--; level>=0; level--)
    if (ms->capture[level].len == CAP_UNFINISHED) return level;
  return mr_L_error(ms->L, "invalid pattern capture");
}


static const char *mr_I_classend (MatchState *ms, const char *p) {
  switch (*p++) {
    case ESC: {
      if (*p == '\0')
        mr_L_error(ms->L, "malformed pattern (ends with `%')");
      return p+1;
    }
    case '[': {
      if (*p == '^') p++;
      do {  /* look for a `]' */
        if (*p == '\0')
          mr_L_error(ms->L, "malformed pattern (missing `]')");
        if (*(p++) == ESC && *p != '\0')
          p++;  /* skip escapes (e.g. `%]') */
      } while (*p != ']');
      return p+1;
    }
    default: {
      return p;
    }
  }
}


static int match_class (int c, int cl) {
  int res;
  switch (mr_tolower(cl)) {
    case 'a' : res = mr_isalpha(c); break;
    case 'c' : res = mr_iscntrl(c); break;
    case 'd' : res = mr_isdigit(c); break;
    case 'l' : res = mr_islower(c); break;
    case 'p' : res = mr_ispunct(c); break;
    case 's' : res = mr_isspace(c); break;
    case 'u' : res = mr_isupper(c); break;
    case 'w' : res = mr_isalnum(c); break;
    case 'x' : res = mr_isxdigit(c); break;
    case 'z' : res = (c == 0); break;
    default: return (cl == c);
  }
  return (mr_islower(cl) ? res : !res);
}


static int matchbracketclass (int c, const char *p, const char *ec) {
  int sig = 1;
  if (*(p+1) == '^') {
    sig = 0;
    p++;  /* skip the `^' */
  }
  while (++p < ec) {
    if (*p == ESC) {
      p++;
      if (match_class(c, *p))
        return sig;
    }
    else if ((*(p+1) == '-') && (p+2 < ec)) {
      p+=2;
      if (uchar(*(p-2)) <= c && c <= uchar(*p))
        return sig;
    }
    else if (uchar(*p) == c) return sig;
  }
  return !sig;
}


static int mr_I_singlematch (int c, const char *p, const char *ep) {
  switch (*p) {
    case '.': return 1;  /* matches any char */
    case ESC: return match_class(c, *(p+1));
    case '[': return matchbracketclass(c, p, ep-1);
    default:  return (uchar(*p) == c);
  }
}


static const char *match (MatchState *ms, const char *s, const char *p);


static const char *matchbalance (MatchState *ms, const char *s,
                                   const char *p) {
  if (*p == 0 || *(p+1) == 0)
    mr_L_error(ms->L, "unbalanced pattern");
  if (*s != *p) return NULL;
  else {
    int b = *p;
    int e = *(p+1);
    int cont = 1;
    while (++s < ms->src_end) {
      if (*s == e) {
        if (--cont == 0) return s+1;
      }
      else if (*s == b) cont++;
    }
  }
  return NULL;  /* string ends out of balance */
}


static const char *max_expand (MatchState *ms, const char *s,
                                 const char *p, const char *ep) {
  sint32 i = 0;  /* counts maximum expand for item */
  while ((s+i)<ms->src_end && mr_I_singlematch(uchar(*(s+i)), p, ep))
    i++;
  /* keeps trying to match with the maximum repetitions */
  while (i>=0) {
    const char *res = match(ms, (s+i), ep+1);
    if (res) return res;
    i--;  /* else didn't match; reduce 1 repetition to try again */
  }
  return NULL;
}


static const char *min_expand (MatchState *ms, const char *s,
                                 const char *p, const char *ep) {
  for (;;) {
    const char *res = match(ms, s, ep+1);
    if (res != NULL)
      return res;
    else if (s<ms->src_end && mr_I_singlematch(uchar(*s), p, ep))
      s++;  /* try with one more repetition */
    else return NULL;
  }
}


static const char *start_capture (MatchState *ms, const char *s,
                                    const char *p, int what) {
  const char *res;
  int level = ms->level;
  if (level >= MAX_CAPTURES) mr_L_error(ms->L, "too many captures");
  ms->capture[level].init = s;
  ms->capture[level].len = what;
  ms->level = level+1;
  if ((res=match(ms, s, p)) == NULL)  /* match failed? */
    ms->level--;  /* undo capture */
  return res;
}


static const char *end_capture (MatchState *ms, const char *s,
                                  const char *p) {
  int l = capture_to_close(ms);
  const char *res;
  ms->capture[l].len = s - ms->capture[l].init;  /* close capture */
  if ((res = match(ms, s, p)) == NULL)  /* match failed? */
    ms->capture[l].len = CAP_UNFINISHED;  /* undo capture */
  return res;
}


static const char *match_capture (MatchState *ms, const char *s, int l) {
  size_t len;
  l = check_capture(ms, l);
  len = ms->capture[l].len;
  if ((size_t)(ms->src_end-s) >= len &&
      MEMCMP(ms->capture[l].init, s, len) == 0)
    return s+len;
  else return NULL;
}


static const char *match (MatchState *ms, const char *s, const char *p) {
  init: /* using goto's to optimize tail recursion */
  switch (*p) {
    case '(': {  /* start capture */
      if (*(p+1) == ')')  /* position capture? */
        return start_capture(ms, s, p+2, CAP_POSITION);
      else
        return start_capture(ms, s, p+1, CAP_UNFINISHED);
    }
    case ')': {  /* end capture */
      return end_capture(ms, s, p+1);
    }
    case ESC: {
      switch (*(p+1)) {
        case 'b': {  /* balanced string? */
          s = matchbalance(ms, s, p+2);
          if (s == NULL) return NULL;
          p+=4; goto init;  /* else return match(ms, s, p+4); */
        }
        case 'f': {  /* frontier? */
          const char *ep; char previous;
          p += 2;
          if (*p != '[')
            mr_L_error(ms->L, "missing `[' after `%%f' in pattern");
          ep = mr_I_classend(ms, p);  /* points to what is next */
          previous = (s == ms->src_init) ? '\0' : *(s-1);
          if (matchbracketclass(uchar(previous), p, ep-1) ||
             !matchbracketclass(uchar(*s), p, ep-1)) return NULL;
          p=ep; goto init;  /* else return match(ms, s, ep); */
        }
        default: {
          if (mr_isdigit(uchar(*(p+1)))) {  /* capture results (%0-%9)? */
            s = match_capture(ms, s, *(p+1));
            if (s == NULL) return NULL;
            p+=2; goto init;  /* else return match(ms, s, p+2) */
          }
          goto dflt;  /* case default */
        }
      }
    }
    case '\0': {  /* end of pattern */
      return s;  /* match succeeded */
    }
    case '$': {
      if (*(p+1) == '\0')  /* is the `$' the last char in pattern? */
        return (s == ms->src_end) ? s : NULL;  /* check end of string */
      else goto dflt;
    }
    default: dflt: {  /* it is a pattern item */
      const char *ep = mr_I_classend(ms, p);  /* points to what is next */
      int m = s<ms->src_end && mr_I_singlematch(uchar(*s), p, ep);
      switch (*ep) {
        case '?': {  /* optional */
          const char *res;
          if (m && ((res=match(ms, s+1, ep+1)) != NULL))
            return res;
          p=ep+1; goto init;  /* else return match(ms, s, ep+1); */
        }
        case '*': {  /* 0 or more repetitions */
          return max_expand(ms, s, p, ep);
        }
        case '+': {  /* 1 or more repetitions */
          return (m ? max_expand(ms, s+1, p, ep) : NULL);
        }
        case '-': {  /* 0 or more repetitions (minimum) */
          return min_expand(ms, s, p, ep);
        }
        default: {
          if (!m) return NULL;
          s++; p=ep; goto init;  /* else return match(ms, s+1, ep); */
        }
      }
    }
  }
}



const char *_mr_memfind (const char *s1, size_t l1,
                             const  char *s2, size_t l2) {
  if (l2 == 0) return s1;  /* empty strings are everywhere */
  else if (l2 > l1) return NULL;  /* avoids a negative `l1' */
  else {
    const char *init;  /* to search for a `*s2' inside `s1' */
    l2--;  /* 1st char will be checked by `memchr' */
    l1 = l1-l2;  /* `s2' cannot be found after that */
    while (l1 > 0 && (init = (const char *)MEMCHR(s1, *s2, l1)) != NULL) {
      init++;   /* 1st char is already checked */
      if (MEMCMP(init, s2+1, l2) == 0)
        return init-1;
      else {  /* correct `l1' and `s1' to try again */
        l1 -= init-s1;
        s1 = init;
      }
    }
    return NULL;  /* not found */
  }
}


static void push_onecapture (MatchState *ms, int i) {
  int l = ms->capture[i].len;
  if (l == CAP_UNFINISHED) mr_L_error(ms->L, "unfinished capture");
  if (l == CAP_POSITION)
    mrp_pushnumber(ms->L, (mrp_Number)(ms->capture[i].init - ms->src_init + 1));
  else
    mrp_pushlstring(ms->L, ms->capture[i].init, l);
}


static int push_captures (MatchState *ms, const char *s, const char *e) {
  int i;
  mr_L_checkstack(ms->L, ms->level, "too many captures");
  if (ms->level == 0 && s) {  /* no explicit captures? */
    mrp_pushlstring(ms->L, s, e-s);  /* return whole match */
    return 1;
  }
  else {  /* return all captures */
    for (i=0; i<ms->level; i++)
      push_onecapture(ms, i);
    return ms->level;  /* number of strings pushed */
  }
}


static int str_find (mrp_State *L) {
  size_t l1, l2;
  const char *s = mr_L_checklstring(L, 1, &l1);
  const char *p = mr_L_checklstring(L, 2, &l2);
  sint32 init = posrelat(mr_L_optlong(L, 3, 1), l1) - 1;
  if (init < 0) init = 0;
  else if ((size_t)(init) > l1) init = (sint32)l1;
  if ((!mrp_toboolean(L, 4)) ||  /* explicit request? */
      STRPBRK(p, SPECIALS) == NULL) {  /* or no special characters? */
    /* do a plain search */
    const char *s2 = _mr_memfind(s+init, l1-init, p, l2);
    if (s2) {
      mrp_pushnumber(L, (mrp_Number)(s2-s+1));
      mrp_pushnumber(L, (mrp_Number)(s2-s+l2));
      return 2;
    }
  }
  else {
    MatchState ms;
    int anchor = (*p == '^') ? (p++, 1) : 0;
    const char *s1=s+init;
    ms.L = L;
    ms.src_init = s;
    ms.src_end = s+l1;
    do {
      const char *res;
      ms.level = 0;
      if ((res=match(&ms, s1, p)) != NULL) {
        mrp_pushnumber(L, (mrp_Number)(s1-s+1));  /* start */
        mrp_pushnumber(L, (mrp_Number)(res-s));   /* end */
        return push_captures(&ms, NULL, 0) + 2;
      }
    } while (s1++<ms.src_end && !anchor);
  }
  mrp_pushnil(L);  /* not found */
  return 1;
}


static int gfind_mr_aux (mrp_State *L) {
  MatchState ms;
  const char *s = mrp_tostring(L, mrp_upvalueindex(1));
  size_t ls = mrp_strlen(L, mrp_upvalueindex(1));
  const char *p = mrp_tostring(L, mrp_upvalueindex(2));
  const char *src;
  ms.L = L;
  ms.src_init = s;
  ms.src_end = s+ls;
  for (src = s + (size_t)mrp_tonumber(L, mrp_upvalueindex(3));
       src <= ms.src_end;
       src++) {
    const char *e;
    ms.level = 0;
    if ((e = match(&ms, src, p)) != NULL) {
      int newstart = e-s;
      if (e == src) newstart++;  /* empty match? go at least one position */
      mrp_pushnumber(L, (mrp_Number)newstart);
      mrp_replace(L, mrp_upvalueindex(3));
      return push_captures(&ms, src, e);
    }
  }
  return 0;  /* not found */
}


static int gfind (mrp_State *L) {
  mr_L_checkstring(L, 1);
  mr_L_checkstring(L, 2);
  mrp_settop(L, 2);
  mrp_pushnumber(L, 0);
  mrp_pushcclosure(L, gfind_mr_aux, 3);
  return 1;
}


static void add_s (MatchState *ms, mr_L_Buffer *b,
                   const char *s, const char *e) {
  mrp_State *L = ms->L;
  if (mrp_isstring(L, 3)) {
    const char *news = mrp_tostring(L, 3);
    size_t l = mrp_strlen(L, 3);
    size_t i;
    for (i=0; i<l; i++) {
      if (news[i] != ESC)
        mr_L_putchar(b, news[i]);
      else {
        i++;  /* skip ESC */
        if (!mr_isdigit(uchar(news[i])))
          mr_L_putchar(b, news[i]);
        else {
          int level = check_capture(ms, news[i]);
          push_onecapture(ms, level);
          mr_L_addvalue(b);  /* add capture to accumulated result */
        }
      }
    }
  }
  else {  /* is a function */
    int n;
    mrp_pushvalue(L, 3);
    n = push_captures(ms, s, e);
    mrp_call(L, n, 1);
    if (mrp_isstring(L, -1))
      mr_L_addvalue(b);  /* add return to accumulated result */
    else
      mrp_pop(L, 1);  /* function result is not a string: pop it */
  }
}


static int str_gsub (mrp_State *L) {
  size_t srcl;
  const char *src = mr_L_checklstring(L, 1, &srcl);
  const char *p = mr_L_checkstring(L, 2);
  int max_s = mr_L_optint(L, 4, srcl+1);
  int anchor = (*p == '^') ? (p++, 1) : 0;
  int n = 0;
  MatchState ms;
  mr_L_Buffer b;
  mr_L_argcheck(L,
    mrp_gettop(L) >= 3 && (mrp_isstring(L, 3) || mrp_isfunction(L, 3)),
    3, "string or function expected");
  mr_L_buffinit(L, &b);
  ms.L = L;
  ms.src_init = src;
  ms.src_end = src+srcl;
  while (n < max_s) {
    const char *e;
    ms.level = 0;
    e = match(&ms, src, p);
    if (e) {
      n++;
      add_s(&ms, &b, src, e);
    }
    if (e && e>src) /* non empty match? */
      src = e;  /* skip it */
    else if (src < ms.src_end)
      mr_L_putchar(&b, *src++);
    else break;
    if (anchor) break;
  }
  mr_L_addlstring(&b, src, ms.src_end-src);
  mr_L_pushresult(&b);
  mrp_pushnumber(L, (mrp_Number)n);  /* number of substitutions */
  return 2;
}


static int str_subV (mrp_State *L) {
  int32 l;
  char * p = (char*)mr_L_checklstring(L, 1, (size_t*)&l);
  mrp_pushnumber(L, (mrp_Number)p);
  mrp_pushnumber(L, (mrp_Number)l);
  return 2;
}


/* }====================================================== */


/* maximum size of each formatted item (> len(format('%99.99f', -1e308))) */
#define MAX_ITEM	512
/* maximum size of each format specification (such as '%-099.99d') */
#define MAX_FORMAT	20


static void mr_I_addquoted (mrp_State *L, mr_L_Buffer *b, int arg) {
  size_t l;
  const char *s = mr_L_checklstring(L, arg, &l);
  mr_L_putchar(b, '"');
  while (l--) {
    switch (*s) {
      case '"': case '\\': case '\n': {
        mr_L_putchar(b, '\\');
        mr_L_putchar(b, *s);
        break;
      }
      case '\0': {
        mr_L_addlstring(b, "\\000", 4);
        break;
      }
      default: {
        mr_L_putchar(b, *s);
        break;
      }
    }
    s++;
  }
  mr_L_putchar(b, '"');
}


static const char *scanformat (mrp_State *L, const char *strfrmt,
                                 char *form, int *hasprecision) {
  const char *p = strfrmt;
  while (STRCHR("-+ #0", *p)) p++;  /* skip flags */
  if (mr_isdigit(uchar(*p))) p++;  /* skip width */
  if (mr_isdigit(uchar(*p))) p++;  /* (2 digits at most) */
  if (*p == '.') {
    p++;
    *hasprecision = 1;
    if (mr_isdigit(uchar(*p))) p++;  /* skip precision */
    if (mr_isdigit(uchar(*p))) p++;  /* (2 digits at most) */
  }
  if (mr_isdigit(uchar(*p)))
    mr_L_error(L, "invalid format (width or precision too long)");
  if (p-strfrmt+2 > MAX_FORMAT)  /* +2 to include `%' and the specifier */
    mr_L_error(L, "invalid format (too long)");
  form[0] = '%';
  STRNCPY(form+1, strfrmt, p-strfrmt+1);
  form[p-strfrmt+2] = 0;
  return p;
}


static int str_format (mrp_State *L) {
  int arg = 1;
  size_t sfl;
  const char *strfrmt = mr_L_checklstring(L, arg, &sfl);
  const char *strfrmt_end = strfrmt+sfl;
  mr_L_Buffer b;
  mr_L_buffinit(L, &b);
  while (strfrmt < strfrmt_end) {
    if (*strfrmt != '%')
      mr_L_putchar(&b, *strfrmt++);
    else if (*++strfrmt == '%')
      mr_L_putchar(&b, *strfrmt++);  /* %% */
    else { /* format item */
      char form[MAX_FORMAT];  /* to store the format (`%...') */
      char buff[MAX_ITEM];  /* to store the formatted item */
      int hasprecision = 0;
/*
      if (mr_isdigit(uchar(*strfrmt)) && *(strfrmt+1) == '$')
        return mr_L_error(L, "obsolete option (d$) to `format'");
*/
      arg++;
      strfrmt = scanformat(L, strfrmt, form, &hasprecision);
      switch (*strfrmt++) {
        case 'c':  case 'd':  case 'i': {
          SPRINTF(buff, form, mr_L_checkint(L, arg));//ouli brew
          break;
        }
        case 'o':  case 'u':  case 'x':  case 'X': {
          SPRINTF(buff, form, (unsigned int)(mr_L_checknumber(L, arg)));//ouli brew
          break;
        }
        case 'q': {
          mr_I_addquoted(L, &b, arg);
          continue;  /* skip the `addsize' at the end */
        }
        case 's': {
          size_t l;
          const char *s = mr_L_checklstring(L, arg, &l);
          if (!hasprecision && l >= 100) {
            /* no precision and string is too long to be formatted;
               keep original string */
            mrp_pushvalue(L, arg);
            mr_L_addvalue(&b);
            continue;  /* skip the `addsize' at the end */
          }
          else {
            SPRINTF(buff, form, s);//ouli brew
            break;
          }
        }
        default: {  /* also treat cases `pnLlh' */
          return mr_L_error(L, "invalid option to `format'");
        }
      }
      mr_L_addlstring(&b, buff, STRLEN(buff));
    }
  }
  mr_L_pushresult(&b);
  return 1;
}

int32 _mr_u2c(char * input, int32 inlen, char* output, int32 outlen){
   int32 pos=0;
   int32 upos=0;
   MEMSET(output, 0, outlen);
   while((upos<(inlen-1))&&((*(input+upos)+*(input+upos+1))!=0)&&(pos<outlen)){
      if(*(input+upos) == 0){
         output[pos] = *(input+upos+1);
         pos = pos + 1;
         upos = upos + 2;
      }else{
         break;
      }
   }
   return pos;
}

static int str_u2c (mrp_State *L) {
   size_t l;
   uint8 * p = (uint8 *)mr_L_checklstring(L, 1, &l);
   char* ascii = MR_MALLOC(l/2);
   if (l < 2){
      mrp_pushstring(L, "");
      return 1;
   }
   ascii = MR_MALLOC((l/2) + 1);
   if (!ascii){
      mrp_pushstring(L, "");
      return 1;
   }
   _mr_u2c((char*)p, l, ascii, (l/2) + 1);
#if 0
   int32 pos=0;
   int32 upos=0;
   MEMSET(ascii, 0, (l/2) + 1);
   while((upos<(l-1))&&((*(p+upos)+*(p+upos+1))!=0)){
      if(*(p+upos) == 0){
         ascii[pos] = *(p+upos+1);
         pos = pos + 1;
         upos = upos + 2;
      }else{
         break;
      }
   }
#endif
   mrp_pushstring(L, ascii);
   MR_FREE(ascii, (l/2) + 1);
   return 1;
}

static int str_update (mrp_State *L) {
   size_t l;
   uint8 * p = (uint8 *)mr_L_checklstring(L, 1, &l);
   size_t l_update;
   uint8 * p_update = (uint8 *)mr_L_checklstring(L, 2, &l_update);
   int32 offset = (int32)mr_L_optnumber(L, 3, 1);
   int32 start = (int32)mr_L_optnumber(L, 4, 1);
   int32 end = (int32)mr_L_optnumber(L, 5, l_update);
   offset = (offset<0)? (l+offset):(offset-1);
   
   start = (start<0)? (l_update+start):(start-1);
   end = (end<0)? (l_update+end):(end-1);
   p_update = p_update + start;
   l_update = end - start + 1;

   l_update = (l_update>(l-offset))? (l-offset):l_update;
   
   if(offset<0){
      mr_L_error(L, "update overflow");
      return 0;
   }
   MEMMOVE(p+offset, p_update, l_update);
   return 0;
}

static int str_pupdate (mrp_State *L) {
   uint8 * p = (uint8 *)mr_L_checknumber(L, 1);
   int32 l = (int32)mr_L_checknumber(L, 2);
   uint8 * p_update = (uint8 *)mr_L_checknumber(L, 3);
   int32 l_update = (int32)mr_L_checknumber(L, 4);
   int32 offset = (int32)mr_L_optnumber(L, 5, 1);
   int32 start = (int32)mr_L_optnumber(L, 6, 1);
   int32 end = (int32)mr_L_optnumber(L, 7, l_update);
   offset = (offset<0)? (l+offset):(offset-1);
   
   start = (start<0)? (l_update+start):(start-1);
   end = (end<0)? (l_update+end):(end-1);
   p_update = p_update + start;
   l_update = end - start + 1;
   
   l_update = (l_update>(l-offset))? (l-offset):l_update;
   if(offset<0){
      mr_L_error(L, "update overflow");
      return 0;
   }
   MEMMOVE(p+offset, p_update, l_update);
   return 0;
}



#ifndef api_check
#define api_check(L, o)		/*{ assert(o); }*/
#endif



TString *_mr_newlstr_without_malloc (mrp_State *L, uint8 *str, size_t l) {
  TString *ts = (TString *)str;
  stringtable *tb;
  lu_hash h = 0;
  ts->tsv.len = l;
  ts->tsv.hash = h;
  ts->tsv.marked = 0;
  ts->tsv.tt = MRP_TSTRING;
  ts->tsv.reserved = 0;
  tb = &G(L)->strt;
  h = lmod(h, tb->size);
  ts->tsv.next = tb->hash[h];  /* chain new entry */
  tb->hash[h] = valtogco(ts);
  tb->nuse++;
  if (tb->nuse > cast(ls_nstr, tb->size) && tb->size <= MAX_INT/2)
    mr_S_resize(L, tb->size*2);  /* too crowded */
  return ts;
}


static int str_new (mrp_State *L) {
   uint32 l = mr_L_checknumber(L, 1);
   uint8 * p = (uint8 *)mr_M_malloc(L, sizestring(l));
   
   if(p){
      MEMSET(p, 0, sizestring(l));
      mrp_lock(L);
      mr_C_checkGC(L);
      setsvalue2s(L->top, _mr_newlstr_without_malloc(L, p, l));
      api_incr_top(L);
      mrp_unlock(L);
      return 1;
   }else{
      return 0;
   }
}

static int str_set (mrp_State *L) {
   size_t l;
   uint8 * p = (uint8 *)mr_L_checklstring(L, 1, &l);
   int32 offset = (int32)mr_L_checknumber(L, 2);
   uint8 value = (uint8)mr_L_checknumber(L, 3);
   offset = (offset<0)? (l+offset):(offset-1);
   
   if((offset>=l)||(offset<0)){
      mr_L_error(L, "set overflow");
      return 0;
   }
   *(p+offset)=value;
   return 0;
}


static mr_L_reg strlib[29];

void mr_strlib_init(void){
 strlib[0].name = "len"; strlib[0].func =  str_len;
 strlib[1].name = "clen"; strlib[1].func =  str_clen;
 strlib[2].name = "wlen"; strlib[2].func =  str_wlen;
 strlib[3].name = "cstr"; strlib[3].func =  str_cstr;
 strlib[4].name = "wstr"; strlib[4].func =  str_wstr;
 strlib[5].name = "sub"; strlib[5].func =  str_sub;
 strlib[6].name = "lower"; strlib[6].func =  str_lower;
 strlib[7].name = "upper"; strlib[7].func =  str_upper;
 strlib[8].name = "char"; strlib[8].func =  str_char;
 strlib[9].name = "rep"; strlib[9].func =  str_rep;
 strlib[10].name = "byte"; strlib[10].func =  str_byte;
 strlib[11].name = "format"; strlib[11].func =  str_format;
 strlib[12].name = "dump"; strlib[12].func =  str_dump;
 strlib[13].name = "find"; strlib[13].func =  str_find;
 strlib[14].name = "findEx"; strlib[14].func =  gfind;
 strlib[15].name = "subEx"; strlib[15].func =  str_gsub;
 strlib[16].name = "subV"; strlib[16].func =  str_subV;
 strlib[17].name = "c2u"; strlib[17].func =  mr_Gb2312toUnicode;
 strlib[18].name = "u2c"; strlib[18].func =  str_u2c;
 strlib[19].name = "pack"; strlib[19].func =  b_pack;
 strlib[20].name = "unpack"; strlib[20].func =  b_unpack;
 strlib[21].name = "packLen"; strlib[21].func =  b_size;
 strlib[22].name = "update"; strlib[22].func =  str_update;
 strlib[23].name = "pupdate"; strlib[23].func =  str_pupdate;
 strlib[24].name = "new"; strlib[24].func =  str_new;
 strlib[25].name = "set"; strlib[25].func =  str_set;
#ifdef COMPATIBILITY01
 strlib[26].name = "findex"; strlib[26].func =  gfind;
 strlib[27].name = "subex"; strlib[27].func =  str_gsub;
#endif
 strlib[28].name = NULL; strlib[28].func =  NULL;
}

/*
** Open string library
*/
MRPLIB_API int mrp_open_string (mrp_State *L) {
  mr_L_openlib(L, MRP_STRLIBNAME, strlib, 0);
  LUADBGPRINTF("string lib");
  return 1;
}




