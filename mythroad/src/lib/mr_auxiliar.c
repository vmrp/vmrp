


#include "../../include/mr_auxiliar.h"

/*=========================================================================*\
* Exported functions
\*=========================================================================*/
/*-------------------------------------------------------------------------*\
* Initializes the module
\*-------------------------------------------------------------------------*/
int mr_aux_open(mrp_State *L) {
    (void) L;
    return 0;
}

/*-------------------------------------------------------------------------*\
* Creates a new class with given methods
* Methods whose names start with __ are passed directly to the metatable.
\*-------------------------------------------------------------------------*/
void mr_aux_newclass(mrp_State *L, const char *classname, mr_L_reg *func) {
    mr_L_newmetatable(L, classname); /* mt */
    /* create __index table to place methods */
    mrp_pushstring(L, "__index");    /* mt,"__index" */
    mrp_newtable(L);                 /* mt,"__index",it */ 
    /* put class name into class metatable */
    mrp_pushstring(L, "class");      /* mt,"__index",it,"class" */
    mrp_pushstring(L, classname);    /* mt,"__index",it,"class",classname */
    mrp_rawset(L, -3);               /* mt,"__index",it */
    /* pass all methods that start with _ to the metatable, and all others
     * to the index table */
    for (; func->name; func++) {     /* mt,"__index",it */
        mrp_pushstring(L, func->name);
        mrp_pushcfunction(L, func->func);
        mrp_rawset(L, func->name[0] == '_' ? -5: -3);
    }
    mrp_rawset(L, -3);               /* mt */
    mrp_pop(L, 1);
}

/*-------------------------------------------------------------------------*\
* Prints the value of a class in a nice way
\*-------------------------------------------------------------------------*/
int mr_aux_tostring(mrp_State *L) {
    char buf[32];
    if (!mrp_getmetatable(L, 1)) goto error;
    mrp_pushstring(L, "__index");
    mrp_gettable(L, -2);
    if (!mrp_istable(L, -1)) goto error;
    mrp_pushstring(L, "class");
    mrp_gettable(L, -2);
    if (!mrp_isstring(L, -1)) goto error;
    SPRINTF(buf, "%p", mrp_touserdata(L, 1));
    mrp_pushfstring(L, "%s: %s", mrp_tostring(L, -1), buf);
    return 1;
error:
    mrp_pushstring(L, "invalid object passed to 'mr_aux.c:__str'");
    mrp_error(L);
    return 1;
}

/*-------------------------------------------------------------------------*\
* Insert class into group
\*-------------------------------------------------------------------------*/
void mr_aux_add2group(mrp_State *L, const char *classname, const char *groupname) {
    mr_L_getmetatable(L, classname);
    mrp_pushstring(L, groupname);
    mrp_pushboolean(L, 1);
    mrp_rawset(L, -3);
    mrp_pop(L, 1);
}

/*-------------------------------------------------------------------------*\
* Make sure argument is a boolean
\*-------------------------------------------------------------------------*/
int mr_aux_checkboolean(mrp_State *L, int objidx) {
    if (!mrp_isboolean(L, objidx))
        mr_L_typerror(L, objidx, mrp_typename(L, MRP_TBOOLEAN));
    return mrp_toboolean(L, objidx);
}

/*-------------------------------------------------------------------------*\
* Return userdata pointer if object belongs to a given class, abort with 
* error otherwise
\*-------------------------------------------------------------------------*/
void *mr_aux_checkclass(mrp_State *L, const char *classname, int objidx) {
    void *data = mr_aux_getclassudata(L, classname, objidx);
    if (!data) {
        char msg[45];
        SPRINTF(msg, "%.35s expected", classname);
        mr_L_argerror(L, objidx, msg);
    }
    return data;
}

/*-------------------------------------------------------------------------*\
* Return userdata pointer if object belongs to a given group, abort with 
* error otherwise
\*-------------------------------------------------------------------------*/
void *mr_aux_checkgroup(mrp_State *L, const char *groupname, int objidx) {
    void *data = mr_aux_getgroupudata(L, groupname, objidx);
    if (!data) {
        char msg[45];
        SPRINTF(msg, "%.35s expected", groupname);
        mr_L_argerror(L, objidx, msg);
    }
    return data;
}

/*-------------------------------------------------------------------------*\
* Set object class
\*-------------------------------------------------------------------------*/
void mr_aux_setclass(mrp_State *L, const char *classname, int objidx) {
    mr_L_getmetatable(L, classname);
    if (objidx < 0) objidx--;
    mrp_setmetatable(L, objidx);
}

/*-------------------------------------------------------------------------*\
* Get a userdata pointer if object belongs to a given group. Return NULL 
* otherwise
\*-------------------------------------------------------------------------*/
void *mr_aux_getgroupudata(mrp_State *L, const char *groupname, int objidx) {
    if (!mrp_getmetatable(L, objidx))
        return NULL;
    mrp_pushstring(L, groupname);
    mrp_rawget(L, -2);
    if (mrp_isnil(L, -1)) {
        mrp_pop(L, 2);
        return NULL;
    } else {
        mrp_pop(L, 2);
        return mrp_touserdata(L, objidx);
    }
}

/*-------------------------------------------------------------------------*\
* Get a userdata pointer if object belongs to a given class. Return NULL 
* otherwise
\*-------------------------------------------------------------------------*/
void *mr_aux_getclassudata(mrp_State *L, const char *classname, int objidx) {
    return mr_L_checkudata(L, objidx, classname);
}
