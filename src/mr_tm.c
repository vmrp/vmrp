

//#define ltm_c


#include "./h/mr_tm.h"
#include "./h/mr_object.h"
#include "./h/mr_state.h"
#include "./h/mr_string.h"
#include "./h/mr_table.h"

const char *mr_T_typenames[9];

const char *mr_T_short_typenames[9];

void mr_tm_init(void) {
    mr_T_typenames[0] = "nil";
    mr_T_typenames[1] = "boolean";
    mr_T_typenames[2] = "object";
    mr_T_typenames[3] = "number";
    mr_T_typenames[4] = "string";
    mr_T_typenames[5] = "table";
    mr_T_typenames[6] = "function";
    mr_T_typenames[7] = "object";
    mr_T_typenames[8] = "thread";

    mr_T_short_typenames[0] = "nil";
    mr_T_short_typenames[1] = "bool";
    mr_T_short_typenames[2] = "obj";
    mr_T_short_typenames[3] = "num";
    mr_T_short_typenames[4] = "str";
    mr_T_short_typenames[5] = "tab";
    mr_T_short_typenames[6] = "func";
    mr_T_short_typenames[7] = "obj";
    mr_T_short_typenames[8] = "co";
}

void mr_T_init(mrp_State *L) {
    char *mr_T_eventname[15];
    int i;
#if 0
  static const char *const mr_T_eventname[] = {  /* ORDER TM */ 
    "__index", "__newindex",
    "__gc", "__mode", "__eq",
    "__add", "__sub", "__mul", "__div",
    "__pow", "__unm", "__lt", "__le",
    "__concat", "__call"
  };
#endif  //ouli brew

    /* ORDER TM */
    mr_T_eventname[0] = "__index";
    mr_T_eventname[1] = "__newindex";
    mr_T_eventname[2] = "__gc";
    mr_T_eventname[3] = "__mode";
    mr_T_eventname[4] = "__eq";
    mr_T_eventname[5] = "__add";
    mr_T_eventname[6] = "__sub";
    mr_T_eventname[7] = "__mul";
    mr_T_eventname[8] = "__div";
    mr_T_eventname[9] = "__op";
    mr_T_eventname[10] = "__unm";
    mr_T_eventname[11] = "__lt";
    mr_T_eventname[12] = "__le";
    mr_T_eventname[13] = "__concat";
    mr_T_eventname[14] = "__call";
    for (i = 0; i < TM_N; i++) {
        G(L)->tmname[i] = mr_S_new(L, mr_T_eventname[i]);
        mr_S_fix(G(L)->tmname[i]); /* never collect these names */
    }
}

/*
** function to be used with macro "fasttm": optimized for absence of
** tag methods
*/
const TObject *mr_T_gettm(Table *events, TMS event, TString *ename) {
    const TObject *tm = mr_H_getstr(events, ename);
    mrp_assert(event <= TM_EQ);
    if (ttisnil(tm)) {                               /* no tag method? */
        events->flags |= cast(lu_byte, 1u << event); /* cache this fact */
        return NULL;
    } else
        return tm;
}

const TObject *mr_T_gettmbyobj(mrp_State *L, const TObject *o, TMS event) {
    TString *ename = G(L)->tmname[event];
    switch (ttype(o)) {
        case MRP_TTABLE:
            return mr_H_getstr(hvalue(o)->metatable, ename);
        case MRP_TUSERDATA:
            return mr_H_getstr(uvalue(o)->uv.metatable, ename);
        default:
            return &mr_O_nilobject;
    }
}
