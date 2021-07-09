/*
** $Id: llex.c,v 1.119 2003/03/24 12:39:34 roberto Exp $
** Lexical Analyzer
** See Copyright Notice in lua.h
*/



//#define llex_c

#include "mr.h"

#include "mr_do.h"
#include "mr_lex.h"
#include "mr_object.h"
#include "mr_parser.h"
#include "mr_state.h"
#include "mr_string.h"
#include "mr_zio.h"



#define next(LS) (LS->current = zgetc(LS->z))



/* ORDER RESERVED */
static const char *const token2string [] = {
    "&&", "break", "do", "else", "elif",
    "end", "false", "for", "def", "if",
    "in", "local", "nil", "!", "||", "repeat",
    "return", "then", "true", "until", "while", "*name",
    "..", "...", "==", ">=", "<=", "!=",
    "*number", "*string", "<eof>"
};

// /* ORDER RESERVED */
// static const char *const token2string [] = {
//     "and", "break", "do", "else", "elseif",
//     "end", "false", "for", "function", "if",
//     "in", "local", "nil", "not", "or", "repeat",
//     "return", "then", "true", "until", "while", "*name",
//     "..", "...", "==", ">=", "<=", "~=",
//     "*number", "*string", "<eof>"
// };



void mr_X_init (mrp_State *L) {
  int i;
  LUADBGPRINTF("mr_X_init sart");
  for (i=0; i<NUM_RESERVED; i++) {
    TString *ts = mr_S_new(L, token2string[i]);
    mr_S_fix(ts);  /* reserved words are never collected */
    mrp_assert(STRLEN(token2string[i])+1 <= TOKEN_LEN);
    ts->tsv.reserved = cast(lu_byte, i+1);  /* reserved word */
  }
  LUADBGPRINTF("mr_X_init end");
}


#define MAXSRC          80


void mr_X_checklimit (LexState *ls, int val, int limit, const char *msg) {
  if (val > limit) {
    msg = mr_O_pushfstring(ls->L, "too many %s (limit=%d)", msg, limit);
    mr_X_syntaxerror(ls, msg);
  }
}


void mr_X_errorline (LexState *ls, const char *s, const char *token, int line) {
  mrp_State *L = ls->L;
  char buff[MAXSRC];
  mr_O_chunkid(buff, getstr(ls->source), MAXSRC);
  mr_O_pushfstring(L, "%s:%d: %s near `%s'", buff, line, s, token); 
  mr_D_throw(L, MRP_ERRSYNTAX);
}


static void mr_X_error (LexState *ls, const char *s, const char *token) {
  mr_X_errorline(ls, s, token, ls->linenumber);
}


void mr_X_syntaxerror (LexState *ls, const char *msg) {
  const char *lasttoken;
  switch (ls->t.token) {
    case TK_NAME:
      lasttoken = getstr(ls->t.seminfo.ts);
      break;
    case TK_STRING:
    case TK_NUMBER:
      lasttoken = mr_Z_buffer(ls->buff);
      break;
    default:
      lasttoken = mr_X_token2str(ls, ls->t.token);
      break;
  }
  mr_X_error(ls, msg, lasttoken);
}


const char *mr_X_token2str (LexState *ls, int token) {
  if (token < FIRST_RESERVED) {
    mrp_assert(token == (unsigned char)token);
    return mr_O_pushfstring(ls->L, "%c", token);
  }
  else
    return token2string[token-FIRST_RESERVED];
}


static void mr_X_lexerror (LexState *ls, const char *s, int token) {
  if (token == TK_EOS)
    mr_X_error(ls, s, mr_X_token2str(ls, token));
  else
    mr_X_error(ls, s, mr_Z_buffer(ls->buff));
}


static void inclinenumber (LexState *LS) {
  next(LS);  /* skip `\n' */
  ++LS->linenumber;
  mr_X_checklimit(LS, LS->linenumber, MAX_INT, "lines in a chunk");
}


void mr_X_setinput (mrp_State *L, LexState *LS, ZIO *z, TString *source) {
  LS->L = L;
  LS->lookahead.token = TK_EOS;  /* no look-ahead token */
  LS->z = z;
  LS->fs = NULL;
  LS->linenumber = 1;
  LS->lastline = 1;
  LS->source = source;
  next(LS);  /* read first char */
  if (LS->current == '#') {
    do {  /* skip first line */
      next(LS);
    } while (LS->current != '\n' && LS->current != EOZ);
  }
}



/*
** =======================================================
** LEXICAL ANALYZER
** =======================================================
*/


/* use buffer to store names, literal strings and numbers */

/* extra space to allocate when growing buffer */
#define EXTRABUFF	32

/* maximum number of chars that can be read without checking buffer size */
#define MAXNOCHECK	5

//ouli important
#define checkbuffer(LS, len)	\
    if (((len)+MAXNOCHECK)*sizeof(char) > mr_Z_sizebuffer((LS)->buff)) \
      mr_Z_openspace((LS)->L, (LS)->buff, (len)+EXTRABUFF)
/*
#define checkbuffer(LS, len)	\
    if (((len)+MAXNOCHECK)*sizeof(char) > mr_Z_sizebuffer((LS)->buff)) \
      mr_Z_openspace((LS)->L, (LS)->buff, (len)+EXTRABUFF)
*/

#define save(LS, c, l) \
	(mr_Z_buffer((LS)->buff)[l++] = cast(char, c))
#define save_and_next(LS, l)  (save(LS, LS->current, l), next(LS))


static size_t readname (LexState *LS) {
  size_t l = 0;
  checkbuffer(LS, l);
  do {
    checkbuffer(LS, l);
    save_and_next(LS, l);
  } while (mr_isalnum(LS->current) || LS->current == '_');
  save(LS, '\0', l);
  return l-1;
}


//Hex Patch
static int mr_O_hexstr2d (const char *s, mrp_Number *result) {
  char *endptr;
  mrp_Number res = strtoul(s, &endptr, 0);
  if (endptr == s) return 0;  /* no conversion */
  while (mr_isspace((unsigned char)(*endptr))) endptr++;
  if (*endptr != '\0') return 0;  /* invalid trailing characters? */
  *result = res;
  return 1;
}
//Hex Patch


/* MRP_NUMBER */
static void read_numeral (LexState *LS, int comma, SemInfo *seminfo) {
  size_t l = 0;
  checkbuffer(LS, l);
  if (comma) save(LS, '.', l);
  //Hex Patch
  if (LS->current == '0') {  /* check for hex prefix */
    save_and_next(LS, l);
    if (LS->current == 'x' || LS->current == 'X') {
      save_and_next(LS, l);
      while (mr_isxdigit(LS->current)) {
        checkbuffer(LS, l);
        save_and_next(LS, l);
      }
      save(LS, '\0', l);
      if (!mr_O_hexstr2d(mr_Z_buffer(LS->buff), &seminfo->r))
        mr_X_lexerror(LS, "malformed hex number", TK_NUMBER);
      return;
    }
  }
  //Hex Patch
  while (mr_isdigit(LS->current)) {
    checkbuffer(LS, l);
    save_and_next(LS, l);
  }
  if (LS->current == '.') {
    save_and_next(LS, l);
    if (LS->current == '.') {
      save_and_next(LS, l);
      save(LS, '\0', l);
      mr_X_lexerror(LS,
                 "ambiguous syntax (decimal point x string concatenation)",
                 TK_NUMBER);
    }
  }
  while (mr_isdigit(LS->current)) {
    checkbuffer(LS, l);
    save_and_next(LS, l);
  }
  if (LS->current == 'e' || LS->current == 'E') {
    save_and_next(LS, l);  /* read `E' */
    if (LS->current == '+' || LS->current == '-')
      save_and_next(LS, l);  /* optional exponent sign */
    while (mr_isdigit(LS->current)) {
      checkbuffer(LS, l);
      save_and_next(LS, l);
    }
  }
  save(LS, '\0', l);
  if (!mr_O_str2d(mr_Z_buffer(LS->buff), &seminfo->r))
    mr_X_lexerror(LS, "malformed number", TK_NUMBER);
}


static void read_long_comment_string(LexState *LS) {
   int cont = 0;
   size_t l = 0;
   checkbuffer(LS, l);
   save(LS, '/', l);  /* save first `[' */
   save_and_next(LS, l);  /* pass the second `[' */
   if (LS->current == '\n')  /* string starts with a newline? */
     inclinenumber(LS);  /* skip it */
   for (;;) {
     checkbuffer(LS, l);
     switch (LS->current) {
       case EOZ:
         save(LS, '\0', l);
         mr_X_lexerror(LS, "long comment unfinished", TK_EOS);
         break;  /* to avoid warnings */
       case '/':
         save_and_next(LS, l);
         if (LS->current == '*') {
           cont++;
           save_and_next(LS, l);
         }
         continue;
#if 0
       case ']':
         save_and_next(LS, l);
         if (LS->current == ']') {
           if (cont == 0) goto endloop;
           cont--;
           save_and_next(LS, l);
         }
         continue;
#endif
       case '*':
         save_and_next(LS, l);
         if (LS->current == '/') {
           if (cont == 0) goto endloop;
           cont--;
           save_and_next(LS, l);
         }
         continue;
       case '\n':
         save(LS, '\n', l);
         inclinenumber(LS);
         l = 0;  /* reset buffer to avoid wasting space */
         continue;
       default:
         save_and_next(LS, l);
     }
   } endloop:
   save_and_next(LS, l);  /* skip the second `]' */
   save(LS, '\0', l);
}


static void read_long_string (LexState *LS, SemInfo *seminfo) {
  int cont = 0;
  size_t l = 0;
  checkbuffer(LS, l);
  save(LS, '[', l);  /* save first `[' */
  save_and_next(LS, l);  /* pass the second `[' */
  if (LS->current == '\n')  /* string starts with a newline? */
    inclinenumber(LS);  /* skip it */
  for (;;) {
    checkbuffer(LS, l);
    switch (LS->current) {
      case EOZ:
        save(LS, '\0', l);
        mr_X_lexerror(LS, "long string unfinished", TK_EOS);
        break;  /* to avoid warnings */
      case '[':
        save_and_next(LS, l);
        if (LS->current == '[') {
          cont++;
          save_and_next(LS, l);
        }
        continue;
      case ']':
        save_and_next(LS, l);
        if (LS->current == ']') {
          if (cont == 0) goto endloop;
          cont--;
          save_and_next(LS, l);
        }
        continue;
      case '\n':
        save(LS, '\n', l);
        inclinenumber(LS);
        if (!seminfo) l = 0;  /* reset buffer to avoid wasting space */
        continue;
      default:
        save_and_next(LS, l);
    }
  } endloop:
  save_and_next(LS, l);  /* skip the second `]' */
  save(LS, '\0', l);
  if (seminfo)
    seminfo->ts = mr_S_newlstr(LS->L, mr_Z_buffer(LS->buff) + 2, l - 5);
}

#if 1
static int hexval(char c)
{
  if ((c >= '0') && (c <= '9')) return c - '0';
  if ((c >= 'a') && (c <= 'f')) return 10 + c - 'a';
  if ((c >= 'A') && (c <= 'F')) return 10 + c - 'A';
  return 0;
}
#endif


static void read_long_string_for_py_mode (LexState *LS, int del, SemInfo *seminfo) {
  int cont = 0;
  size_t l = 2;
  checkbuffer(LS, l);
  save_and_next(LS, l);  /* pass the second `[' */
  if (LS->current == '\n')  /* string starts with a newline? */
    inclinenumber(LS);  /* skip it */
  for (;;) {
    checkbuffer(LS, l);
    switch (LS->current) {
      case EOZ:
        save(LS, '\0', l);
        mr_X_lexerror(LS, "long string unfinished", TK_EOS);
        break;  /* to avoid warnings */
      case '\n':
        save(LS, '\n', l);
        inclinenumber(LS);
        continue;
      default:
         if (LS->current == del){
           save_and_next(LS, l);
           if (LS->current == del) {
              save_and_next(LS, l);
              if (LS->current == del) {
                 goto endloop;
            }
           }
         }else
            save_and_next(LS, l);
    }
  } endloop:
  save_and_next(LS, l);  /* skip the second `]' */
  save(LS, '\0', l);
  if (seminfo)
    seminfo->ts = mr_S_newlstr(LS->L, mr_Z_buffer(LS->buff) + 3, l - 7);
}



static void read_string (LexState *LS, int del, SemInfo *seminfo) {
  size_t l = 0;
  checkbuffer(LS, l);
  save_and_next(LS, l);
#if 1        //ouli for '''
   if(LS->current == del){
      save_and_next(LS, l);
      if(LS->current == del){
         read_long_string_for_py_mode(LS, del, seminfo);
         return;
      }else{
         save(LS, '\0', l);
         seminfo->ts = mr_S_newlstr(LS->L, mr_Z_buffer(LS->buff) + 1, l - 3);
         return;
      }
   }
#endif
  while (LS->current != del) {
    checkbuffer(LS, l);
    switch (LS->current) {
      case EOZ:
        save(LS, '\0', l);
        mr_X_lexerror(LS, "unfinished string", TK_EOS);
        break;  /* to avoid warnings */
      case '\n':
        save(LS, '\0', l);
        mr_X_lexerror(LS, "unfinished string", TK_STRING);
        break;  /* to avoid warnings */
      case '\\':
        next(LS);  /* do not save the `\' */
        switch (LS->current) {
          case 'a': save(LS, '\a', l); next(LS); break;
          case 'b': save(LS, '\b', l); next(LS); break;
          case 'f': save(LS, '\f', l); next(LS); break;
          case 'n': save(LS, '\n', l); next(LS); break;
          case 'r': save(LS, '\r', l); next(LS); break;
          case 't': save(LS, '\t', l); next(LS); break;
          case 'v': save(LS, '\v', l); next(LS); break;
          case '\n': save(LS, '\n', l); inclinenumber(LS); break;
#if 1
          case 'x': case 'X': {
            int c = 0;
            next(LS);
            if (!mr_isxdigit(LS->current)) {
              save(LS, '\0', l);
              mr_X_lexerror(LS, "hex expect for '\\x'", TK_STRING);
            }
            c = hexval(LS->current);
            next(LS);
            if (mr_isxdigit(LS->current)) {
              c = 16*c + hexval(LS->current);
              next(LS);
            }
            save(LS, c, l);
            break;
          }
#endif
          case EOZ: break;  /* will raise an error next loop */
          default: {
            if (!mr_isdigit(LS->current))
              save_and_next(LS, l);  /* handles \\, \", \', and \? */
            else {  /* \xxx */
              int c = 0;
              int i = 0;
              do {
                c = 10*c + (LS->current-'0');
                next(LS);
              } while (++i<3 && mr_isdigit(LS->current));
              // if (c > UCHAR_MAX) {
              if (c > 0xFF) {
                save(LS, '\0', l);
                mr_X_lexerror(LS, "escape sequence too large", TK_STRING);
              }
              save(LS, c, l);
            }
          }
        }
        break;
      default:
        save_and_next(LS, l);
    }/* default '\\' case - check for decimal digits, etc. */
  }/* switch on character after '\\' */
  save_and_next(LS, l);  /* skip delimiter */
  save(LS, '\0', l);
  seminfo->ts = mr_S_newlstr(LS->L, mr_Z_buffer(LS->buff) + 1, l - 3);
}


int mr_X_lex (LexState *LS, SemInfo *seminfo) {
  LUADBGPRINTF("mr_X_lex start");

  for (;;) {
    switch (LS->current) {

      case '\n': {
        inclinenumber(LS);
        continue;
      }
#if 0
      case '-': {
        next(LS);
        if (LS->current != '-') return '-';
        /* else is a comment */
        next(LS);
        if (LS->current == '[' && (next(LS), LS->current == '['))
          read_long_string(LS, NULL);  /* long comment */
        else  /* short comment */
          while (LS->current != '\n' && LS->current != EOZ)
            next(LS);
        continue;
      }
#endif
      case '/': {
        next(LS);
        if (LS->current == '*')
         {
          read_long_comment_string(LS);  /* long comment */
          continue;
         }
        if (LS->current != '/') return '/';
        while (LS->current != '\n' && LS->current != EOZ)
           next(LS);
        continue;
      }
      case '[': {
        next(LS);
        if (LS->current != '[') return '[';
        else {
          read_long_string(LS, seminfo);
          return TK_STRING;
        }
      }
      case '=': {
        next(LS);
        if (LS->current != '=') return '=';
        else { next(LS); return TK_EQ; }
      }
      case '<': {
        next(LS);
        if (LS->current != '=') return '<';
        else { next(LS); return TK_LE; }
      }
      case '&': {
        next(LS);
        if (LS->current != '&') return '&';
        else { next(LS); return TK_AND; }
      }
      case '|': {
        next(LS);
        if (LS->current != '|') return '|';
        else { next(LS); return TK_OR; }
      }
      case '>': {
        next(LS);
        if (LS->current != '=') return '>';
        else { next(LS); return TK_GE; }
      }
#if 0
      case '~': {
        next(LS);
        if (LS->current != '=') return '~';
        else { next(LS); return TK_NE; }
      }
#endif
      case '!': {
        next(LS);
        if (LS->current != '=') return TK_NOT;
        else { next(LS); return TK_NE; }
      }
      case '"':
      case '\'': {
        read_string(LS, LS->current, seminfo);
        return TK_STRING;
      }
      case '.': {
        next(LS);
        if (LS->current == '.') {
          next(LS);
          if (LS->current == '.') {
            next(LS);
            return TK_DOTS;   /* ... */
          }
          else return TK_CONCAT;   /* .. */
        }
        else if (!mr_isdigit(LS->current)) return '.';
        else {
          read_numeral(LS, 1, seminfo);
          return TK_NUMBER;
        }
      }
      case EOZ: {
        return TK_EOS;
      }
      default: {
        if (mr_isspace(LS->current)) {
          next(LS);
          continue;
        }
        else if (mr_isdigit(LS->current)) {
          read_numeral(LS, 0, seminfo);
          return TK_NUMBER;
        }
        else if (mr_isalpha(LS->current) || LS->current == '_') {
          /* identifier or reserved word */
          size_t l = readname(LS);
          TString *ts = mr_S_newlstr(LS->L, mr_Z_buffer(LS->buff), l);
          if (ts->tsv.reserved > 0)  /* reserved word? */
            return ts->tsv.reserved - 1 + FIRST_RESERVED;
          seminfo->ts = ts;
          return TK_NAME;
        }
        else {
          int c = LS->current;
          if (mr_iscntrl(c))
            mr_X_error(LS, "invalid control char",
                           mr_O_pushfstring(LS->L, "char(%d)", c));
          next(LS);
          return c;  /* single-char tokens (+ - / ...) */
        }
      }
    }
  }
}

#undef next
