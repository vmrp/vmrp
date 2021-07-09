/* tolua: functions to check types.
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


/* Push and returns the corresponding object typename */
TO_MR_API const char* to_mr_typename (mrp_State* L, int lo)
{
	int tag = mrp_type(L,lo);
 if (tag == MRP_TNONE)
  mrp_pushstring(L,"[no object]");
 else if (tag != MRP_TUSERDATA && tag != MRP_TTABLE)
  mrp_pushstring(L,mrp_typename(L,tag));
 else if (tag == MRP_TUSERDATA) 
 {
  if (!mrp_getmetatable(L,lo))
   mrp_pushstring(L,mrp_typename(L,tag));
		else
		{
		 mrp_rawget(L,MRP_REGISTRYINDEX);
		 if (!mrp_isstring(L,-1))
			{
		  mrp_pop(L,1);
				mrp_pushstring(L,"[undefined]");
			}
		}
	}
	else  /* is table */
	{
		mrp_pushvalue(L,lo);
		mrp_rawget(L,MRP_REGISTRYINDEX);
		if (!mrp_isstring(L,-1))
		{
			mrp_pop(L,1);
			mrp_pushstring(L,"table");
		}
		else
		{
   mrp_pushstring(L,"class ");
			mrp_insert(L,-2);
			mrp_concat(L,2);
		}
	}
	return mrp_tostring(L,-1);
}

TO_MR_API void to_mr_error (mrp_State* L, char* msg, to_mr_Error* err)
{
	if (msg[0] == '#')
	{
  const char* expected = err->type;
		const char* provided = to_mr_typename(L,err->index);
  if (msg[1]=='f')
  {
   int narg = err->index;
			if (err->array)
    mr_L_error(L,"%s\n     argument #%d is array of '%s'; array of '%s' expected.\n",
               msg+2,narg,provided,expected);
			else
    mr_L_error(L,"%s\n     argument #%d is '%s'; '%s' expected.\n",
               msg+2,narg,provided,expected);
  }
  else if (msg[1]=='v')
		{
			if (err->array)
    mr_L_error(L,"%s\n     value is array of '%s'; array of '%s' expected.\n",
               msg+2,provided,expected);
			else
    mr_L_error(L,"%s\n     value is '%s'; '%s' expected.\n",
               msg+2,provided,expected);
		}
 }
 else
  mr_L_error(L,msg);
}

/* the equivalent of mrp_is* for usertable */
static  int mrp_isusertable (mrp_State* L, int lo, const char* type)
{
	int r = 0;
	if (lo < 0) lo = mrp_gettop(L)+lo+1;
	mrp_pushvalue(L,lo);
	mrp_rawget(L,MRP_REGISTRYINDEX);  /* get registry[t] */
	if (mrp_isstring(L,-1))
	{
		r = STRCMP(mrp_tostring(L,-1),type)==0;
		if (!r)
		{
			/* try const */
			mrp_pushstring(L,"const ");
			mrp_insert(L,-2);
			mrp_concat(L,2);
			r = mrp_isstring(L,-1) && STRCMP(mrp_tostring(L,-1),type)==0;
		}
	}
	mrp_pop(L, 1);
	return r;
}

/* the equivalent of mrp_is* for usertype */
static int mrp_isusertype (mrp_State* L, int lo, const char* type)
{
	if (mrp_isuserdata(L,lo))
	{
		/* check if it is of the same type */
		int r;
	 const char *tn;
		if (mrp_getmetatable(L,lo))        /* if metatable? */
		{
		 mrp_rawget(L,MRP_REGISTRYINDEX);  /* get registry[mt] */
		 tn = mrp_tostring(L,-1);
		 r = tn && (STRCMP(tn,type) == 0);
		 mrp_pop(L, 1);
			if (r)
			 return 1;
			else
			{
				/* check if it is a specialized class */
				mrp_pushstring(L,"to_mr_super");
				mrp_rawget(L,MRP_REGISTRYINDEX); /* get super */
				mrp_getmetatable(L,lo);
				mrp_rawget(L,-2);                /* get super[mt] */
				if (mrp_istable(L,-1))
				{
					int b;
				 mrp_pushstring(L,type);
				 mrp_rawget(L,-2);                /* get super[mt][type] */
     b = mrp_toboolean(L,-1);
				 mrp_pop(L,3);
				 if (b)
					 return 1;
				}
			}
		}
 }
	return 0;
}

TO_MR_API int to_mr_isnoobj (mrp_State* L, int lo, to_mr_Error* err)
{
 if (mrp_gettop(L)<ABS(lo))  //ouli brew
		return 1;
	err->index = lo;
	err->array = 0;
	err->type = "[no object]";
 return 0;
}
TO_MR_API int to_mr_isvalue (mrp_State* L, int lo, int def, to_mr_Error* err)
{
	if (def || ABS(lo)<=mrp_gettop(L))  /* any valid index */  //ouli brew
		return 1;
	err->index = lo;
	err->array = 0;
	err->type = "value";
	return 0;
}

TO_MR_API int to_mr_isboolean (mrp_State* L, int lo, int def, to_mr_Error* err)
{
	if (def && mrp_gettop(L)<ABS(lo)) //ouli brew
		return 1;
	if (mrp_isnil(L,lo) || mrp_isboolean(L,lo))
		return 1;
	err->index = lo;
	err->array = 0;
	err->type = "boolean";
	return 0;
}

TO_MR_API int to_mr_isnumber (mrp_State* L, int lo, int def, to_mr_Error* err)
{
	if (def && mrp_gettop(L)<ABS(lo)) //ouli brew
		return 1;
	if (mrp_isnumber(L,lo))
		return 1;
	err->index = lo;
	err->array = 0;
	err->type = "number";
	return 0;
}

TO_MR_API int to_mr_isstring (mrp_State* L, int lo, int def, to_mr_Error* err)
{
	if (def && mrp_gettop(L)<ABS(lo)) //ouli brew
		return 1;
 if (mrp_isnil(L,lo) || mrp_isstring(L,lo))
		return 1;
	err->index = lo;
	err->array = 0;
	err->type = "string";
	return 0;
}

TO_MR_API int to_mr_istable (mrp_State* L, int lo, int def, to_mr_Error* err)
{
	if (def && mrp_gettop(L)<ABS(lo)) //ouli brew
		return 1;
	if (mrp_istable(L,lo))
		return 1;
	err->index = lo;
	err->array = 0;
	err->type = "table";
	return 0;
}

TO_MR_API int to_mr_isusertable (mrp_State* L, int lo, const char* type, int def, to_mr_Error* err)
{
	if (def && mrp_gettop(L)<ABS(lo)) //ouli brew
		return 1;
	if (mrp_isusertable(L,lo,type))
		return 1;
	err->index = lo;
	err->array = 0;
	err->type = type;
	return 0;
}

TO_MR_API int to_mr_isfunction (mrp_State* L, int lo, int def, to_mr_Error* err)
{
 if (def && mrp_gettop(L)<ABS(lo)) //ouli brew
  return 1;
 if (mrp_isfunction(L,lo))
  return 1;
 err->index = lo;
 err->array = 0;
 err->type = "function";
 return 0;
}

TO_MR_API int to_mr_isuserdata (mrp_State* L, int lo, int def, to_mr_Error* err)
{
	if (def && mrp_gettop(L)<ABS(lo)) //ouli brew
		return 1;
	if (mrp_isnil(L,lo) || mrp_isuserdata(L,lo))
		return 1;
	err->index = lo;
	err->array = 0;
	err->type = "object";
	return 0;
}

TO_MR_API int to_mr_isusertype (mrp_State* L, int lo, const char* type, int def, to_mr_Error* err)
{
	if (def && mrp_gettop(L)<ABS(lo)) //ouli brew
		return 1;
	if (mrp_isnil(L,lo) || mrp_isusertype(L,lo,type))
		return 1;
	err->index = lo;
	err->array = 0;
	err->type = type;
	return 0;
}

TO_MR_API int to_mr_isvaluearray 
 (mrp_State* L, int lo, int dim, int def, to_mr_Error* err)
{
	if (!to_mr_istable(L,lo,def,err))
		return 0;
	else
		return 1;
}

TO_MR_API int to_mr_isbooleanarray 
 (mrp_State* L, int lo, int dim, int def, to_mr_Error* err)
{
	if (!to_mr_istable(L,lo,def,err))
		return 0;
	else
	{
		int i;
		for (i=1; i<=dim; ++i)
		{
			mrp_pushnumber(L,i);
			mrp_gettable(L,lo);
	  if (!(mrp_isnil(L,-1) || mrp_isboolean(L,-1)) &&
					  !(def && mrp_isnil(L,-1))
						)
			{
				err->index = lo;
				err->array = 1;
				err->type = "boolean";
				return 0;
			}
			mrp_pop(L,1);
		}
 }
 return 1;
}

TO_MR_API int to_mr_isnumberarray 
 (mrp_State* L, int lo, int dim, int def, to_mr_Error* err)
{
	if (!to_mr_istable(L,lo,def,err))
		return 0;
	else
	{
		int i;
		for (i=1; i<=dim; ++i)
		{
			mrp_pushnumber(L,i);
			mrp_gettable(L,lo);
			if (!mrp_isnumber(L,-1) && 
					  !(def && mrp_isnil(L,-1))
						)
			{
				err->index = lo;
				err->array = 1;
				err->type = "number";
				return 0;
			}
			mrp_pop(L,1);
		}
 }
 return 1;
}

TO_MR_API int to_mr_isstringarray 
 (mrp_State* L, int lo, int dim, int def, to_mr_Error* err)
{
	if (!to_mr_istable(L,lo,def,err))
		return 0;
	else
	{
		int i;
		for (i=1; i<=dim; ++i)
		{
			mrp_pushnumber(L,i);
			mrp_gettable(L,lo);
   if (!(mrp_isnil(L,-1) || mrp_isstring(L,-1)) &&
			    !(def && mrp_isnil(L,-1))
						)
			{
				err->index = lo;
				err->array = 1;
				err->type = "string";
				return 0;
			}
			mrp_pop(L,1);
		}
 }
 return 1;
}

TO_MR_API int to_mr_istablearray 
 (mrp_State* L, int lo, int dim, int def, to_mr_Error* err)
{
	if (!to_mr_istable(L,lo,def,err))
		return 0;
	else
	{
		int i;
		for (i=1; i<=dim; ++i)
		{
			mrp_pushnumber(L,i);
			mrp_gettable(L,lo);
	  if (! mrp_istable(L,-1) &&
			    !(def && mrp_isnil(L,-1))
						)
			{
				err->index = lo;
				err->array = 1;
				err->type = "table";
				return 0;
			}
			mrp_pop(L,1);
		}
 }
 return 1;
}

TO_MR_API int to_mr_isuserdataarray 
 (mrp_State* L, int lo, int dim, int def, to_mr_Error* err)
{
	if (!to_mr_istable(L,lo,def,err))
		return 0;
	else
	{
		int i;
		for (i=1; i<=dim; ++i)
		{
			mrp_pushnumber(L,i);
			mrp_gettable(L,lo);
	  if (!(mrp_isnil(L,-1) || mrp_isuserdata(L,-1)) && 
			    !(def && mrp_isnil(L,-1))
						)
			{
				err->index = lo;
				err->array = 1;
				err->type = "object";
				return 0;
			}
			mrp_pop(L,1);
		}
 }
 return 1;
}

TO_MR_API int to_mr_isusertypearray 
 (mrp_State* L, int lo, const char* type, int dim, int def, to_mr_Error* err)
{
	if (!to_mr_istable(L,lo,def,err))
		return 0;
	else
	{
		int i;
		for (i=1; i<=dim; ++i)
		{
			mrp_pushnumber(L,i);
			mrp_gettable(L,lo);
	  if (!(mrp_isnil(L,-1) || mrp_isuserdata(L,-1)) && 
			    !(def && mrp_isnil(L,-1))
						)
			{
				err->index = lo;
				err->type = type;
				err->array = 1;
				return 0;
			}
			mrp_pop(L,1);
		}
 }
 return 1;
}

#if 0
int to_mr_isbooleanfield 
 (mrp_State* L, int lo, int i, int def, to_mr_Error* err)
{
	mrp_pushnumber(L,i);
	mrp_gettable(L,lo);
	if (!(mrp_isnil(L,-1) || mrp_isboolean(L,-1)) &&
			  !(def && mrp_isnil(L,-1))
				)
	{
		err->index = lo;
		err->array = 1;
		err->type = "boolean";
		return 0;
	}
	mrp_pop(L,1);
 return 1;
}

int to_mr_isnumberfield 
 (mrp_State* L, int lo, int i, int def, to_mr_Error* err)
{
	mrp_pushnumber(L,i);
	mrp_gettable(L,lo);
	if (!mrp_isnumber(L,-1) && 
			  !(def && mrp_isnil(L,-1))
				)
	{
		err->index = lo;
		err->array = 1;
		err->type = "number";
		return 0;
	}
	mrp_pop(L,1);
 return 1;
}

int to_mr_isstringfield 
 (mrp_State* L, int lo, int i, int def, to_mr_Error* err)
{
	mrp_pushnumber(L,i);
	mrp_gettable(L,lo);
 if (!(mrp_isnil(L,-1) || mrp_isstring(L,-1)) &&
	    !(def && mrp_isnil(L,-1))
				)
	{
		err->index = lo;
		err->array = 1;
		err->type = "string";
		return 0;
	}
	mrp_pop(L,1);
 return 1;
}

int to_mr_istablefield 
 (mrp_State* L, int lo, int i, int def, to_mr_Error* err)
{
	mrp_pushnumber(L,i+1);
	mrp_gettable(L,lo);
	if (! mrp_istable(L,-1) &&
	    !(def && mrp_isnil(L,-1))
				)
	{
		err->index = lo;
		err->array = 1;
		err->type = "table";
		return 0;
	}
	mrp_pop(L,1);
}

int to_mr_isusertablefield 
 (mrp_State* L, int lo, const char* type, int i, int def, to_mr_Error* err)
{
	mrp_pushnumber(L,i);
	mrp_gettable(L,lo);
	if (! mrp_isusertable(L,-1,type) &&
	    !(def && mrp_isnil(L,-1))
				)
	{
		err->index = lo;
		err->array = 1;
		err->type = type;
		return 0;
	}
	mrp_pop(L,1);
 return 1;
}

int to_mr_isuserdatafield 
 (mrp_State* L, int lo, int i, int def, to_mr_Error* err)
{
	mrp_pushnumber(L,i);
	mrp_gettable(L,lo);
	if (!(mrp_isnil(L,-1) || mrp_isuserdata(L,-1)) && 
	    !(def && mrp_isnil(L,-1))
				)
	{
		err->index = lo;
		err->array = 1;
		err->type = "object";
		return 0;
	}
	mrp_pop(L,1);
 return 1;
}

int to_mr_isusertypefield 
 (mrp_State* L, int lo, const char* type, int i, int def, to_mr_Error* err)
{
	mrp_pushnumber(L,i);
	mrp_gettable(L,lo);
	if (!(mrp_isnil(L,-1) || mrp_isusertype(L,-1,type)) && 
	    !(def && mrp_isnil(L,-1))
				)
	{
		err->index = lo;
		err->type = type;
		err->array = 1;
		return 0;
	}
	mrp_pop(L,1);
 return 1;
}

#endif
