/* tolua: functions to push C values.
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


TO_MR_API void to_mr_pushvalue (mrp_State* L, int lo)
{
 mrp_pushvalue(L,lo);
}

TO_MR_API void to_mr_pushboolean (mrp_State* L, int value)
{
 mrp_pushboolean(L,value);
}

TO_MR_API void to_mr_pushnumber (mrp_State* L, int value)//ouli brew
{
 mrp_pushnumber(L,value);
}

TO_MR_API void to_mr_pushstring (mrp_State* L, const char* value)
{
 if (value == NULL)
  mrp_pushnil(L);
 else
  mrp_pushstring(L,value);
}

TO_MR_API void to_mr_pushuserdata (mrp_State* L, void* value)
{
 if (value == NULL)
  mrp_pushnil(L);
 else
  mrp_pushlightuserdata(L,value);
}

TO_MR_API void to_mr_pushusertype (mrp_State* L, void* value, const char* type)
{
 if (value == NULL)
  mrp_pushnil(L);
 else
 { 
  mrp_pushstring(L,"to_mr_ubox");
  mrp_rawget(L,MRP_REGISTRYINDEX);        /* stack: ubox */
  mrp_pushlightuserdata(L,value);
  mrp_rawget(L,-2);                       /* stack: ubox ubox[u] */
  if (mrp_isnil(L,-1))
  {
   mrp_pop(L,1);                          /* stack: ubox */
   mrp_pushlightuserdata(L,value);
   *(void**)mrp_newuserdata(L,sizeof(void *)) = value;   /* stack: ubox u newud */ 
   mrp_pushvalue(L,-1);                   /* stack: ubox u newud newud */
   mrp_insert(L,-4);                      /* stack: newud ubox u newud */
   mrp_rawset(L,-3);                      /* stack: newud ubox */
   mrp_pop(L,1);                          /* stack: newud */
   mr_L_getmetatable(L,type);
   mrp_setmetatable(L,-2);
  }
  else
  {
   /* check the need of updating the metatable to a more specialized class */
   mrp_insert(L,-2);                       /* stack: ubox[u] ubox */
   mrp_pop(L,1);                           /* stack: ubox[u] */
   mrp_pushstring(L,"to_mr_super");
   mrp_rawget(L,MRP_REGISTRYINDEX);        /* stack: ubox[u] super */
   mrp_getmetatable(L,-2);                 /* stack: ubox[u] super mt */
   mrp_rawget(L,-2);                       /* stack: ubox[u] super super[mt] */
			if (mrp_istable(L,-1))
   {
				mrp_pushstring(L,type);                 /* stack: ubox[u] super super[mt] type */
				mrp_rawget(L,-2);                       /* stack: ubox[u] super super[mt] flag */
				if (mrp_toboolean(L,-1) == 1)   /* if true */
				{
					mrp_pop(L,3);
					return;
				}
			}
			/* type represents a more specilized type */
			mr_L_getmetatable(L,type);             /* stack: ubox[u] super super[mt] flag mt */
			mrp_setmetatable(L,-5);                /* stack: ubox[u] super super[mt] flag */
   mrp_pop(L,3);                          /* stack: ubox[u] */
  }
 }
}

TO_MR_API void to_mr_pushfieldvalue (mrp_State* L, int lo, int index, int v)
{
 mrp_pushnumber(L,index);
 mrp_pushvalue(L,v);
 mrp_settable(L,lo);
}

TO_MR_API void to_mr_pushfieldboolean (mrp_State* L, int lo, int index, int v)
{
 mrp_pushnumber(L,index);
 mrp_pushboolean(L,v);
 mrp_settable(L,lo);
}


TO_MR_API void to_mr_pushfieldnumber (mrp_State* L, int lo, int index, int v)
{
 mrp_pushnumber(L,index);
 to_mr_pushnumber(L,v);
 mrp_settable(L,lo);
}

TO_MR_API void to_mr_pushfieldstring (mrp_State* L, int lo, int index, const char* v)
{
 mrp_pushnumber(L,index);
 to_mr_pushstring(L,v);
 mrp_settable(L,lo);
}

TO_MR_API void to_mr_pushfielduserdata (mrp_State* L, int lo, int index, void* v)
{
 mrp_pushnumber(L,index);
 to_mr_pushuserdata(L,v);
 mrp_settable(L,lo);
}

TO_MR_API void to_mr_pushfieldusertype (mrp_State* L, int lo, int index, void* v, const char* type)
{
 mrp_pushnumber(L,index);
 to_mr_pushusertype(L,v,type);
 mrp_settable(L,lo);
}

