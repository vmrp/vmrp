/*
** $Id: llex.h,v 1.47 2003/02/28 17:19:47 roberto Exp $
** Lexical Analyzer
** See Copyright Notice in lua.h
*/

#ifndef mr_lex_h
#define mr_lex_h

#include "mr_object.h"
#include "mr_zio.h"


#define FIRST_RESERVED	257

/* maximum length of a reserved word */
#define TOKEN_LEN	(sizeof("repeat")/sizeof(char))


/*
* WARNING: if you change the order of this enumeration,
* grep "ORDER RESERVED"
*/
enum RESERVED {
  /* terminal symbols denoted by reserved words */
  TK_AND = FIRST_RESERVED, TK_BREAK,
  TK_DO, TK_ELSE, TK_ELSEIF, TK_END, TK_FALSE, TK_FOR, TK_FUNCTION,
  TK_IF, TK_IN, TK_LOCAL, TK_NIL, TK_NOT, TK_OR, TK_REPEAT,
  TK_RETURN, TK_THEN, TK_TRUE, TK_UNTIL, TK_WHILE,
  /* other terminal symbols */
  TK_NAME, TK_CONCAT, TK_DOTS, TK_EQ, TK_GE, TK_LE, TK_NE, TK_NUMBER,
  TK_STRING, TK_EOS
};

/* number of reserved words */
#define NUM_RESERVED	(cast(int, TK_WHILE-FIRST_RESERVED+1))


typedef union {
  mrp_Number r;
  TString *ts;
} SemInfo;  /* semantics information */


typedef struct Token {
  int token;
  SemInfo seminfo;
} Token;


typedef struct LexState {
  int current;  /* current character (charint) */
  int linenumber;  /* input line counter */
  int lastline;  /* line of last token `consumed' */
  Token t;  /* current token */
  Token lookahead;  /* look ahead token */
  struct FuncState *fs;  /* `FuncState' is private to the parser */
  struct mrp_State *L;
  ZIO *z;  /* input stream */
  Mbuffer *buff;  /* buffer for tokens */
  TString *source;  /* current source name */
  int nestlevel;  /* level of nested non-terminals */
} LexState;


void mr_X_init (mrp_State *L);
void mr_X_setinput (mrp_State *L, LexState *LS, ZIO *z, TString *source);
int mr_X_lex (LexState *LS, SemInfo *seminfo);
void mr_X_checklimit (LexState *ls, int val, int limit, const char *msg);
void mr_X_syntaxerror (LexState *ls, const char *s);
void mr_X_errorline (LexState *ls, const char *s, const char *token, int line);
const char *mr_X_token2str (LexState *ls, int token);


#endif
