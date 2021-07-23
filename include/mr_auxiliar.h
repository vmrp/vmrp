

#ifndef MR_AUX_H
#define MR_AUX_H

#include "mr.h"
#include "mr_auxlib.h"

int mr_aux_open(mrp_State *L);
void mr_aux_newclass(mrp_State *L, const char *classname, mr_L_reg *func);
void mr_aux_add2group(mrp_State *L, const char *classname, const char *group);
void mr_aux_setclass(mrp_State *L, const char *classname, int objidx);
void *mr_aux_checkclass(mrp_State *L, const char *classname, int objidx);
void *mr_aux_checkgroup(mrp_State *L, const char *groupname, int objidx);
void *mr_aux_getclassudata(mrp_State *L, const char *groupname, int objidx);
void *mr_aux_getgroupudata(mrp_State *L, const char *groupname, int objidx);
int mr_aux_checkboolean(mrp_State *L, int objidx);
int mr_aux_tostring(mrp_State *L);

#endif /* AUX_H */
