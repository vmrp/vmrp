/* tolua: event functions
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

/* Store at peer
	* It stores, creating the corresponding table if needed,
	* the pair key/value in the corresponding peer table
*/
static void storeatpeer (mrp_State* L, int u)
{
	 /* stack: key value (to be stored) */
		mrp_pushstring(L,"to_mr_peer");
		mrp_rawget(L,MRP_REGISTRYINDEX);        /* stack: k v peer */
		mrp_pushvalue(L,u);
		mrp_rawget(L,-2);                       /* stack: k v peer peer[u] */
		if (!mrp_istable(L,-1))
		{
			mrp_pop(L,1);                          /* stack: k v peer */
			mrp_newtable(L);                       /* stack: k v peer table */
			mrp_pushvalue(L,1);
			mrp_pushvalue(L,-2);                   /* stack: k v peer table u table */
			mrp_rawset(L,-4);                      /* stack: k v peer peer[u]=table */
		}
		mrp_insert(L,-4);                       /* put table before k */
		mrp_pop(L,1);                           /* pop peer */
		mrp_rawset(L,-3);                       /* store at table */
		mrp_pop(L,1);                           /* pop peer[u] */
}

/* Module index function
*/
static int module_index_event (mrp_State* L)
{
	mrp_pushstring(L,".get");
	mrp_rawget(L,-3);
	if (mrp_istable(L,-1))
	{
		mrp_pushvalue(L,2);  /* key */
		mrp_rawget(L,-2);
		if (mrp_iscfunction(L,-1))
		{
			mrp_call(L,0,1);
			return 1;
		}
		else if (mrp_istable(L,-1))
			return 1;
	}
	/* call old index meta event */
	if (mrp_getmetatable(L,1))
	{
		mrp_pushstring(L,"__index");
		mrp_rawget(L,-2);
		mrp_pushvalue(L,1);
		mrp_pushvalue(L,2);
		if (mrp_isfunction(L,-1))
		{
			mrp_call(L,2,1);
			return 1;
		}
		else if (mrp_istable(L,-1))
		{
			mrp_gettable(L,-3);
			return 1;
		}
	}
	mrp_pushnil(L);
	return 1;
}

/* Module newindex function
*/
static int module_newindex_event (mrp_State* L)
{
	mrp_pushstring(L,".set");
	mrp_rawget(L,-4);
	if (mrp_istable(L,-1))
	{
		mrp_pushvalue(L,2);  /* key */
		mrp_rawget(L,-2);
		if (mrp_iscfunction(L,-1))
		{
			mrp_pushvalue(L,1); /* only to be compatible with non-static vars */
			mrp_pushvalue(L,3); /* value */
			mrp_call(L,2,0);
			return 0;
		}
	}
	/* call old newindex meta event */
	if (mrp_getmetatable(L,1) && mrp_getmetatable(L,-1))
	{
		mrp_pushstring(L,"__newindex");
		mrp_rawget(L,-2);
		if (mrp_isfunction(L,-1))
		{
		 mrp_pushvalue(L,1);
		 mrp_pushvalue(L,2);
		 mrp_pushvalue(L,3);
			mrp_call(L,3,0);
		}
	}
	mrp_settop(L,3);
	mrp_rawset(L,-3);
	return 0;
}

/* Class index function
	* If the object is a userdata (ie, an object), it searches the field in 
	* the alternative table stored in the corresponding "peer" table.
*/
static int class_index_event (mrp_State* L)
{
 int t = mrp_type(L,1);
	if (t == MRP_TUSERDATA)
	{
		/* Access alternative table */
		mrp_pushstring(L,"to_mr_peer");
		mrp_rawget(L,MRP_REGISTRYINDEX);        /* stack: obj key peer */
		mrp_pushvalue(L,1);
		mrp_rawget(L,-2);                       /* stack: obj key peer peer[u] */
		if (mrp_istable(L,-1))
		{
			mrp_pushvalue(L,2);  /* key */
			mrp_rawget(L,-2);                      /* stack: obj key peer peer[u] value */
			if (!mrp_isnil(L,-1))
				return 1;
		}
		mrp_settop(L,2);                        /* stack: obj key */
		/* Try metatables */
		mrp_pushvalue(L,1);                     /* stack: obj key obj */
		while (mrp_getmetatable(L,-1))
		{                                       /* stack: obj key obj mt */
			mrp_remove(L,-2);                      /* stack: obj key mt */
			if (mrp_isnumber(L,2))                 /* check if key is a numeric value */
			{
				/* try operator[] */
				mrp_pushstring(L,".geti");    
				mrp_rawget(L,-2);                      /* stack: obj key mt func */
				if (mrp_isfunction(L,-1))
				{
					mrp_pushvalue(L,1);
					mrp_pushvalue(L,2);
					mrp_call(L,2,1);
					return 1;
				}
   }
			else
			{
			 mrp_pushvalue(L,2);                    /* stack: obj key mt key */
				mrp_rawget(L,-2);                      /* stack: obj key mt value */
				if (!mrp_isnil(L,-1))
					return 1;
				else
					mrp_pop(L,1);
				/* try C/C++ variable */
				mrp_pushstring(L,".get");    
				mrp_rawget(L,-2);                      /* stack: obj key mt tget */
				if (mrp_istable(L,-1))
				{
					mrp_pushvalue(L,2);
					mrp_rawget(L,-2);                      /* stack: obj key mt value */
					if (mrp_iscfunction(L,-1))
					{
						mrp_pushvalue(L,1);
						mrp_pushvalue(L,2); 
						mrp_call(L,2,1);
						return 1;
					}
					else if (mrp_istable(L,-1))
					{
						/* deal with array: create table to be returned and cache it in peer */
						void* u = *((void**)mrp_touserdata(L,1));
						mrp_newtable(L);                /* stack: obj key mt value table */
						mrp_pushstring(L,".self");
						mrp_pushlightuserdata(L,u);
						mrp_rawset(L,-3);               /* store usertype in ".self" */
						mrp_insert(L,-2);               /* stack: obj key mt table value */
						mrp_setmetatable(L,-2);         /* set stored value as metatable */
						mrp_pushvalue(L,-1);            /* stack: obj key met table table */
						mrp_pushvalue(L,2);             /* stack: obj key mt table table key */
						mrp_insert(L,-2);               /*  stack: obj key mt table key table */
						storeatpeer(L,1);               /* stack: obj key mt table */
						return 1;
					}
				}
			}
			mrp_settop(L,3);
		}
		mrp_pushnil(L);
		return 1;
	}
	else if (t== MRP_TTABLE)
	{
		module_index_event(L);
		return 1;
	}
	mrp_pushnil(L);
	return 1;
}

/* Newindex function
	* It first searches for a C/C++ varaible to be set.
	* Then, it either stores it in the alternative peer table (in the case it is
	* an object) or in the own table (that represents the class or module).
*/
static int class_newindex_event (mrp_State* L)
{
 int t = mrp_type(L,1);
	if (t == MRP_TUSERDATA)
	{
	 /* Try accessing a C/C++ variable to be set */
		mrp_getmetatable(L,1);
		while (mrp_istable(L,-1))                /* stack: t k v mt */
		{
			if (mrp_isnumber(L,2))                 /* check if key is a numeric value */
			{
				/* try operator[] */
				mrp_pushstring(L,".seti");    
				mrp_rawget(L,-2);                      /* stack: obj key mt func */
				if (mrp_isfunction(L,-1))
				{
					mrp_pushvalue(L,1);
					mrp_pushvalue(L,2);
					mrp_pushvalue(L,3);
					mrp_call(L,3,0);
					return 0;
				}
   }
			else
			{
				mrp_pushstring(L,".set");
				mrp_rawget(L,-2);                      /* stack: t k v mt tset */
				if (mrp_istable(L,-1))
				{
					mrp_pushvalue(L,2);
					mrp_rawget(L,-2);                     /* stack: t k v mt tset func */
					if (mrp_iscfunction(L,-1))
					{
						mrp_pushvalue(L,1);
						mrp_pushvalue(L,3); 
						mrp_call(L,2,0);
						return 0;
					}
					mrp_pop(L,1);                          /* stack: t k v mt tset */
				}
				mrp_pop(L,1);                           /* stack: t k v mt */
				if (!mrp_getmetatable(L,-1))            /* stack: t k v mt mt */
					mrp_pushnil(L);
				mrp_remove(L,-2);                       /* stack: t k v mt */
			}
		}
	 mrp_settop(L,3);                          /* stack: t k v */

		/* then, store as a new field */
		storeatpeer(L,1);
	}
	else if (t== MRP_TTABLE)
	{
		module_newindex_event(L);
	}
	return 0;
}

static int do_operator (mrp_State* L, const char* op)
{
	if (mrp_isuserdata(L,1))
	{
		/* Try metatables */
		mrp_pushvalue(L,1);                     /* stack: op1 op2 */
		while (mrp_getmetatable(L,-1))
		{                                       /* stack: op1 op2 op1 mt */
			mrp_remove(L,-2);                      /* stack: op1 op2 mt */
			mrp_pushstring(L,op);                  /* stack: op1 op2 mt key */
			mrp_rawget(L,-2);                      /* stack: obj key mt func */
			if (mrp_isfunction(L,-1))
			{
				mrp_pushvalue(L,1);
				mrp_pushvalue(L,2); 
				mrp_call(L,2,1);
				return 1;
			}
			mrp_settop(L,3);
		}
	}
	to_mr_error(L,"Attempt to perform operation on an invalid operand",NULL);
	return 0;
}

static int class_add_event (mrp_State* L)
{
	return do_operator(L,".add");
}

static int class_sub_event (mrp_State* L)
{
	return do_operator(L,".sub");
}

static int class_mul_event (mrp_State* L)
{
	return do_operator(L,".mul");
}

static int class_div_event (mrp_State* L)
{
	return do_operator(L,".div");
}

static int class_lt_event (mrp_State* L)
{
	return do_operator(L,".lt");
}

static int class_le_event (mrp_State* L)
{
	return do_operator(L,".le");
}

static int class_eq_event (mrp_State* L)
{
	return do_operator(L,".eq");
}

static int class_gc_event (mrp_State* L)
{
	void* u = *((void**)mrp_touserdata(L,1));
 mrp_pushstring(L,"to_mr_gc");
 mrp_rawget(L,MRP_REGISTRYINDEX);
	mrp_pushlightuserdata(L,u);
	mrp_rawget(L,-2);
	if (mrp_isfunction(L,-1))
	{
	 mrp_pushvalue(L,1);
		mrp_call(L,1,0);
	 mrp_pushlightuserdata(L,u);
		mrp_pushnil(L);
		mrp_rawset(L,-3);
	}
	mrp_pop(L,2);
	return 0;
}

/* Register module events
	* It expects the metatable on the top of the stack
*/
TO_MR_API void to_mr_moduleevents (mrp_State* L)
{
	mrp_pushstring(L,"__index");
	mrp_pushcfunction(L,module_index_event);
	mrp_rawset(L,-3);
	mrp_pushstring(L,"__newindex");
	mrp_pushcfunction(L,module_newindex_event);
	mrp_rawset(L,-3);
}

/* Check if the object on the top has a module metatable
*/
TO_MR_API int to_mr_ismodulemetatable (mrp_State* L)
{
	int r = 0;
	if (mrp_getmetatable(L,-1))
	{
		mrp_pushstring(L,"__index");
		mrp_rawget(L,-2);
		r = (mrp_tocfunction(L,-1) == module_index_event);
		mrp_pop(L,2);
	}
	return r;
}

/* Register class events
	* It expects the metatable on the top of the stack
*/
TO_MR_API void to_mr_classevents (mrp_State* L)
{
	mrp_pushstring(L,"__index");
	mrp_pushcfunction(L,class_index_event);
	mrp_rawset(L,-3);
	mrp_pushstring(L,"__newindex");
	mrp_pushcfunction(L,class_newindex_event);
	mrp_rawset(L,-3);
 
	mrp_pushstring(L,"__add");
	mrp_pushcfunction(L,class_add_event);
	mrp_rawset(L,-3);
	mrp_pushstring(L,"__sub");
	mrp_pushcfunction(L,class_sub_event);
	mrp_rawset(L,-3);
	mrp_pushstring(L,"__mul");
	mrp_pushcfunction(L,class_mul_event);
	mrp_rawset(L,-3);
	mrp_pushstring(L,"__div");
	mrp_pushcfunction(L,class_div_event);
	mrp_rawset(L,-3);

	mrp_pushstring(L,"__lt");
	mrp_pushcfunction(L,class_lt_event);
	mrp_rawset(L,-3);
	mrp_pushstring(L,"__le");
	mrp_pushcfunction(L,class_le_event);
	mrp_rawset(L,-3);
	mrp_pushstring(L,"__eq");
	mrp_pushcfunction(L,class_eq_event);
	mrp_rawset(L,-3);

	mrp_pushstring(L,"__gc");
	mrp_pushcfunction(L,class_gc_event);
	mrp_rawset(L,-3);
}

