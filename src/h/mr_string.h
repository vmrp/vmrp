
#ifndef mr_string_h
#define mr_string_h


#include "mr_object.h"
#include "mr_state.h"



#define sizestring(l)	(cast(lu_mem, sizeof(union TString))+ \
                         (cast(lu_mem, l)+1)*sizeof(char))

#define sizeudata(l)	(cast(lu_mem, sizeof(union Udata))+(l))

#define mr_S_new(L, s)	(mr_S_newlstr(L, s, STRLEN(s)))
#define mr_S_newliteral(L, s)	(mr_S_newlstr(L, "" s, \
                                 (sizeof(s)/sizeof(char))-1))

#define mr_S_fix(s)	((s)->tsv.marked |= (1<<4))

void mr_S_resize (mrp_State *L, int newsize);
Udata *mr_S_newudata (mrp_State *L, size_t s);
void mr_S_freeall (mrp_State *L);
TString *mr_S_newlstr (mrp_State *L, const char *str, size_t l);

TString *_mr_newlstr_without_malloc (mrp_State *L, uint8 *str, size_t l);

#endif
