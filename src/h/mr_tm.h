
#ifndef mr_tm_h
#define mr_tm_h

#include "mr_object.h"

/*
* WARNING: if you change the order of this enumeration,
* grep "ORDER TM"
*/
typedef enum {
    TM_INDEX,
    TM_NEWINDEX,
    TM_GC,
    TM_MODE,
    TM_EQ, /* last tag method with `fast' access */
    TM_ADD,
    TM_SUB,
    TM_MUL,
    TM_DIV,
    TM_POW,
    TM_UNM,
    TM_LT,
    TM_LE,
    TM_CONCAT,
    TM_CALL,
    TM_N /* number of elements in the enum */
} TMS;

#define gfasttm(g, et, e) \
    (((et)->flags & (1u << (e))) ? NULL : mr_T_gettm(et, e, (g)->tmname[e]))

#define fasttm(l, et, e) gfasttm(G(l), et, e)

const TObject *mr_T_gettm(Table *events, TMS event, TString *ename);
const TObject *mr_T_gettmbyobj(mrp_State *L, const TObject *o, TMS event);
void mr_T_init(mrp_State *L);

extern const char *mr_T_typenames[];
extern const char *mr_T_short_typenames[];

#endif
