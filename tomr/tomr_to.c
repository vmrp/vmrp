/* tolua: funcitons to convert to C types
** Support code for Lua bindings.
** Written by Waldemar Celes
** TeCGraf/PUC-Rio
** Apr 2003
** $Id: $
*/

/* This code is free software; you can redistribute it and/or modify it. 
** The software provided hereunder is on an "as is" basis, and 
** the author has no obligation to provide maintenance, support, updates,
** enhancements, or modifications. 
*/

#include "tomr.h"


TO_MR_API int to_mr_tonumber (mrp_State* L, int narg, int def)
{
 return mrp_gettop(L)<ABS(narg) ? def : mrp_tonumber(L,narg); //ouli brew
}

TO_MR_API const char* to_mr_tostring (mrp_State* L, int narg, const char* def)
{
 return mrp_gettop(L)<ABS(narg) ? def : mrp_tostring(L,narg); //ouli brew
}

TO_MR_API void* to_mr_touserdata (mrp_State* L, int narg, void* def)
{
 return mrp_gettop(L)<ABS(narg) ? def : mrp_touserdata(L,narg); //ouli brew
}

TO_MR_API void* to_mr_tousertype (mrp_State* L, int narg, void* def)
{
 if (mrp_gettop(L)<ABS(narg)) //ouli brew
  return def;
 else
 {
  void* u = mrp_touserdata(L,narg);
  return (u==NULL) ? NULL : *((void**)u); /* nil represents NULL */
 }
}

TO_MR_API int to_mr_tovalue (mrp_State* L, int narg, int def)
{
 return mrp_gettop(L)<ABS(narg) ? def : narg; //ouli brew
}

TO_MR_API int to_mr_toboolean (mrp_State* L, int narg, int def)
{
 return mrp_gettop(L)<ABS(narg) ?  def : mrp_toboolean(L,narg); //ouli brew
}

TO_MR_API double to_mr_tofieldnumber (mrp_State* L, int lo, int index, double def)
{
 double v;
 mrp_pushnumber(L,index);
 mrp_gettable(L,lo);
 v = mrp_isnil(L,-1) ? def : mrp_tonumber(L,-1);
 mrp_pop(L,1);
 return v;
}

TO_MR_API const char* to_mr_tofieldstring 
(mrp_State* L, int lo, int index, const char* def)
{
 const char* v;
 mrp_pushnumber(L,index);
 mrp_gettable(L,lo);
 v = mrp_isnil(L,-1) ? def : mrp_tostring(L,-1);
 mrp_pop(L,1);
 return v;
}

TO_MR_API void* to_mr_tofielduserdata (mrp_State* L, int lo, int index, void* def)
{
 void* v;
 mrp_pushnumber(L,index);
 mrp_gettable(L,lo);
 v = mrp_isnil(L,-1) ? def : mrp_touserdata(L,-1);
 mrp_pop(L,1);
 return v;
}

TO_MR_API void* to_mr_tofieldusertype (mrp_State* L, int lo, int index, void* def)
{
 void* v;
 mrp_pushnumber(L,index);
 mrp_gettable(L,lo);
 v = mrp_isnil(L,-1) ? def : mrp_unboxpointer(L,-1);
 mrp_pop(L,1);
 return v;
}

TO_MR_API int to_mr_tofieldvalue (mrp_State* L, int lo, int index, int def)
{
 int v;
 mrp_pushnumber(L,index);
 mrp_gettable(L,lo);
 v = mrp_isnil(L,-1) ? def : lo;
 mrp_pop(L,1);
 return v;
}

TO_MR_API int to_mr_getfieldboolean (mrp_State* L, int lo, int index, int def)
{
 int v;
 mrp_pushnumber(L,index);
 mrp_gettable(L,lo);
 v = mrp_isnil(L,-1) ? 0 : mrp_toboolean(L,-1);
 mrp_pop(L,1);
 return v;
}
