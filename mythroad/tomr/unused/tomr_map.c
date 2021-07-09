/* tolua: functions to map features
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

#include "tomr_event.h"


/* Create metatable
	* Create and register new metatable
*/
static int to_mr_newmetatable (mrp_State* L, char* name)
{
 int r = mr_L_newmetatable(L,name);
	if (r)
	 to_mr_classevents(L); /* set meta events */
 mrp_pop(L,1);
	return r;
}

/* Map super classes
	* It sets 'name' as being also a 'base', mapping all super classes of 'base' in 'name'
*/
static void mapsuper (mrp_State* L, const char* name, const char* base)
{
	/* push registry.super */
 mrp_pushstring(L,"to_mr_super");
 mrp_rawget(L,MRP_REGISTRYINDEX);    /* stack: super */
	mr_L_getmetatable(L,name);          /* stack: super mt */
 mrp_rawget(L,-2);                   /* stack: super table */
	if (mrp_isnil(L,-1))
	{
	 /* create table */
		mrp_pop(L,1);
	 mrp_newtable(L);                    /* stack: super table */
	 mr_L_getmetatable(L,name);          /* stack: super table mt */
		mrp_pushvalue(L,-2);                /* stack: super table mt table */
		mrp_rawset(L,-4);                   /* stack: super table */
	}

	/* set base as super class */
	mrp_pushstring(L,base);
	mrp_pushboolean(L,1);
	mrp_rawset(L,-3);                    /* stack: super table */

	/* set all super class of base as super class of name */
	mr_L_getmetatable(L,base);          /* stack: super table base_mt */
	mrp_rawget(L,-3);                   /* stack: super table base_table */
	if (mrp_istable(L,-1))
	{
		/* traverse base table */
		mrp_pushnil(L);  /* first key */
		while (mrp_next(L,-2) != 0) 
		{
			/* stack: ... base_table key value */
			mrp_pushvalue(L,-2);    /* stack: ... base_table key value key */
			mrp_insert(L,-2);       /* stack: ... base_table key key value */ 
			mrp_rawset(L,-5);       /* stack: ... base_table key */
		}
	}
	mrp_pop(L,3);                       /* stack: <empty> */
}


/* Map inheritance
	* It sets 'name' as derived from 'base' by setting 'base' as metatable of 'name'
*/
static void mapinheritance (mrp_State* L, const char* name, const char* base)
{
	/* set metatable inheritance */
	mr_L_getmetatable(L,name); 
	if (base && *base)
	 mr_L_getmetatable(L,base);
	else
		mr_L_getmetatable(L,"to_mr_commonclass");
 mrp_setmetatable(L,-2);   
	mrp_pop(L,1);
}

/* Object type
*/
static int to_mr_bnd_type (mrp_State* L)
{
	to_mr_typename(L,mrp_gettop(L));
	return 1;
}

/* Take ownership
*/
static int to_mr_bnd_takeownership (mrp_State* L)
{
	mrp_CFunction func = 0;
	if (mrp_isuserdata(L,1))
	{
		if (mrp_getmetatable(L,1))        /* if metatable? */
		{
			void* u;
			mrp_pushstring(L,".collector");
   mrp_rawget(L,-2);
			func = mrp_tocfunction(L,-1);    /* it may be NULL; it is ok */
			mrp_pop(L,2);
	  u = *((void**)mrp_touserdata(L,1));
			/* force garbage collection to avoid C to reuse a to-be-collected address */
			mrp_setgcthreshold(L,0);
			to_mr_clone(L,u,func);
		}
	}
	mrp_pushboolean(L,func!=0);
	return 1;
}

/* Release ownership
*/
static int to_mr_bnd_releaseownership (mrp_State* L)
{
	int done = 0;
	if (mrp_isuserdata(L,1))
	{
	 void* u = *((void**)mrp_touserdata(L,1));
		/* force garbage collection to avoid releasing a to-be-collected address */
		mrp_setgcthreshold(L,0);
  mrp_pushstring(L,"to_mr_gc");
  mrp_rawget(L,MRP_REGISTRYINDEX);
	 mrp_pushlightuserdata(L,u);
	 mrp_rawget(L,-2);
	 if (mrp_isfunction(L,-1))
	 {
	  mrp_pushlightuserdata(L,u);
		 mrp_pushnil(L);
		 mrp_rawset(L,-4);
   done = 1;
		}
	}
	mrp_pushboolean(L,done!=0);
	return 1;
}

/* Type casting
*/
static int to_mr_bnd_cast (mrp_State* L)
{
	void* v = to_mr_tousertype(L,1,NULL);
	const char* s = to_mr_tostring(L,2,NULL);
	if (v && s)
	 to_mr_pushusertype(L,v,s);
	else
	 mrp_pushnil(L);
	return 1;
}

TO_MR_API void to_mr_open (mrp_State* L)
{
 int top = mrp_gettop(L);
 mrp_pushstring(L,"to_mr_opened");
 mrp_rawget(L,MRP_REGISTRYINDEX);
 if (!mrp_isboolean(L,-1))
 {
  mrp_pushstring(L,"to_mr_opened"); mrp_pushboolean(L,1); mrp_rawset(L,MRP_REGISTRYINDEX);
  mrp_pushstring(L,"to_mr_super"); mrp_newtable(L); mrp_rawset(L,MRP_REGISTRYINDEX);
  mrp_pushstring(L,"to_mr_gc"); mrp_newtable(L); mrp_rawset(L,MRP_REGISTRYINDEX);
		/* weak value table */
  mrp_pushstring(L,"to_mr_ubox"); mrp_newtable(L); mrp_pushvalue(L,-1);
		mrp_pushliteral(L, "__mode"); mrp_pushliteral(L, "v"); mrp_rawset(L, -3);
		mrp_setmetatable(L, -2); mrp_rawset(L,MRP_REGISTRYINDEX);

		/* weak key table */
  mrp_pushstring(L,"to_mr_peer"); mrp_newtable(L); mrp_pushvalue(L,-1);
		mrp_pushliteral(L, "__mode"); mrp_pushliteral(L, "k"); mrp_rawset(L, -3);
		mrp_setmetatable(L, -2); mrp_rawset(L,MRP_REGISTRYINDEX);

  to_mr_newmetatable(L,"to_mr_commonclass");

  to_mr_module(L,NULL,0);
  to_mr_beginmodule(L,NULL);
  to_mr_module(L,"tomr",0);
  to_mr_beginmodule(L,"tomr");
  to_mr_function(L,"type",to_mr_bnd_type);
  to_mr_function(L,"takeownership",to_mr_bnd_takeownership);
  to_mr_function(L,"releaseownership",to_mr_bnd_releaseownership);
  to_mr_function(L,"cast",to_mr_bnd_cast);
  to_mr_endmodule(L);
  to_mr_endmodule(L);    
 }
 mrp_settop(L,top);
}

/* Copy a C object
*/
TO_MR_API void* to_mr_copy (mrp_State* L, void* value, unsigned int size)
{
	void* clone = (void*)MR_MALLOC(size);
	if (clone)
	 MEMCPY(clone,value,size);//ouli brew
	else
		to_mr_error(L,"insuficient memory",NULL);
	return clone;
}

/* Default collect function
*/
static int to_mr_default_collect (mrp_State* to_mr_S)
{
 void* self = to_mr_tousertype(to_mr_S,1,0);
 MR_FREE(self, 0);  //ouli important
 return 0;
}

/* Do clone
*/
TO_MR_API void* to_mr_clone (mrp_State* L, void* value, mrp_CFunction func)
{
 mrp_pushstring(L,"to_mr_gc");
 mrp_rawget(L,MRP_REGISTRYINDEX);
	mrp_pushlightuserdata(L,value);
	mrp_pushcfunction(L,func?func:to_mr_default_collect);
	mrp_rawset(L,-3);
	mrp_pop(L,1);
	return value;
}

/* Register a usertype
	* It creates the correspoding metatable in the registry, for both 'type' and 'const type'.
	* It maps 'const type' as being also a 'type'
*/
TO_MR_API void to_mr_usertype (mrp_State* L, char* type)
{
// char ctype[128]="const ";
 char ctype[128];
 STRCPY(ctype, "const ");//ouli brew
 STRNCAT(ctype,type,120); 

	/* create both metatables */
 if (to_mr_newmetatable(L,ctype) && to_mr_newmetatable(L,type))
	 mapsuper(L,type,ctype);             /* 'type' is also a 'const type' */
}


/* Begin module
	* It pushes the module (or class) table on the stack
*/
TO_MR_API void to_mr_beginmodule (mrp_State* L, char* name)
{
	if (name)
	{
	 mrp_pushstring(L,name);
		mrp_rawget(L,-2);
	}
	else
	 mrp_pushvalue(L,MRP_GLOBALSINDEX);
}

/* End module
	* It pops the module (or class) from the stack
*/
TO_MR_API void to_mr_endmodule (mrp_State* L)
{
	mrp_pop(L,1);
}

/* Map module
	* It creates a new module
*/
#if 1
TO_MR_API void to_mr_module (mrp_State* L, char* name, int hasvar)
{
	if (name)
	{
		/* tolua module */
		mrp_pushstring(L,name); 
		mrp_rawget(L,-2);
		if (!mrp_istable(L,-1))  /* check if module already exists */
		{
			mrp_pop(L,1);
		 mrp_newtable(L);
		 mrp_pushstring(L,name); 
			mrp_pushvalue(L,-2);
		 mrp_rawset(L,-4);       /* assing module into module */
		}
	}
	else
	{
		/* global table */
		mrp_pushvalue(L,MRP_GLOBALSINDEX);
	}
	if (hasvar)
	{
		if (!to_mr_ismodulemetatable(L))  /* check if it already has a module metatable */
		{
			/* create metatable to get/set C/C++ variable */
			mrp_newtable(L);
			to_mr_moduleevents(L);
			if (mrp_getmetatable(L,-2))
				mrp_setmetatable(L,-2);  /* set old metatable as metatable of metatable */
			mrp_setmetatable(L,-2);
		}
	}
	mrp_pop(L,1);               /* pop module */
}
#else
TO_MR_API void to_mr_module (mrp_State* L, char* name, int hasvar)
{
	if (name)
	{
		/* tolua module */
		mrp_pushstring(L,name); 
		mrp_newtable(L);
	}
	else
	{
		/* global table */
		mrp_pushvalue(L,MRP_GLOBALSINDEX);
	}
	if (hasvar)
	{
		/* create metatable to get/set C/C++ variable */
		mrp_newtable(L);
		to_mr_moduleevents(L);
		if (mrp_getmetatable(L,-2))
			mrp_setmetatable(L,-2);  /* set old metatable as metatable of metatable */
		mrp_setmetatable(L,-2);
	}
	if (name)
		mrp_rawset(L,-3);       /* assing module into module */
	else
		mrp_pop(L,1);           /* pop global table */
}
#endif

/* Map C class
	* It maps a C class, setting the appropriate inheritance and super classes.
*/
TO_MR_API void to_mr_cclass (mrp_State* L, char* lname, char* name, char* base, mrp_CFunction col)
{
//	char cname[128] = "const ";
//	char cbase[128] = "const ";
	char cname[128];
	char cbase[128];
  STRCPY(cname, "const ");//ouli brew
  STRCPY(cbase, "const ");//ouli brew

	STRNCAT(cname,name,120);
	STRNCAT(cbase,base,120);

	mapinheritance(L,name,base);
	mapinheritance(L,cname,name);

	mapsuper(L,cname,cbase);
	mapsuper(L,name,base);

	mrp_pushstring(L,lname);    
	mr_L_getmetatable(L,name);
	mrp_pushstring(L,".collector");
	mrp_pushcfunction(L,col);
	mrp_rawset(L,-3);              /* store collector function into metatable */
	mrp_rawset(L,-3);              /* assign class metatable to module */
}

/* Map function
	* It assigns a function into the current module (or class)
*/
TO_MR_API void to_mr_function (mrp_State* L, char* name, mrp_CFunction func)
{
 mrp_pushstring(L,name);
 mrp_pushcfunction(L,func);
	mrp_rawset(L,-3);
}

/* Map constant number
	* It assigns a constant number into the current module (or class)
*/
TO_MR_API void to_mr_constant (mrp_State* L, char* name, int value)
{
	mrp_pushstring(L,name);
	to_mr_pushnumber(L,value);
	mrp_rawset(L,-3);
}


/* Map variable
	* It assigns a variable into the current module (or class)
*/
TO_MR_API void to_mr_variable (mrp_State* L, char* name, mrp_CFunction get, mrp_CFunction set)
{
	/* get func */
	mrp_pushstring(L,".get");
	mrp_rawget(L,-2);
	if (!mrp_istable(L,-1))
	{
		/* create .get table, leaving it at the top */
		mrp_pop(L,1);
		mrp_newtable(L);
	 mrp_pushstring(L,".get");
		mrp_pushvalue(L,-2);
		mrp_rawset(L,-4);
	}
	mrp_pushstring(L,name);
	mrp_pushcfunction(L,get);
 mrp_rawset(L,-3);                  /* store variable */
	mrp_pop(L,1);                      /* pop .get table */

	/* set func */
	if (set)
	{
		mrp_pushstring(L,".set");
		mrp_rawget(L,-2);
		if (!mrp_istable(L,-1))
		{
			/* create .set table, leaving it at the top */
			mrp_pop(L,1);
			mrp_newtable(L);
			mrp_pushstring(L,".set");
			mrp_pushvalue(L,-2);
			mrp_rawset(L,-4);
		}
		mrp_pushstring(L,name);
		mrp_pushcfunction(L,set);
		mrp_rawset(L,-3);                  /* store variable */
		mrp_pop(L,1);                      /* pop .set table */
	}
}

/* Access const array
	* It reports an error when trying to write into a const array
*/
static int const_array (mrp_State* L)
{
 mr_L_error(L,"value of const array cannot be changed");
 return 0;
}

/* Map an array
	* It assigns an array into the current module (or class)
*/
TO_MR_API void to_mr_array (mrp_State* L, char* name, mrp_CFunction get, mrp_CFunction set)
{
	mrp_pushstring(L,".get");
	mrp_rawget(L,-2);
	if (!mrp_istable(L,-1))
	{
		/* create .get table, leaving it at the top */
		mrp_pop(L,1);
		mrp_newtable(L);
	 mrp_pushstring(L,".get");
		mrp_pushvalue(L,-2);
		mrp_rawset(L,-4);
	}
	mrp_pushstring(L,name);

 mrp_newtable(L);           /* create array metatable */
 mrp_pushvalue(L,-1);
	mrp_setmetatable(L,-2);    /* set the own table as metatable (for modules) */
 mrp_pushstring(L,"__index"); 
 mrp_pushcfunction(L,get);
	mrp_rawset(L,-3);
 mrp_pushstring(L,"__newindex"); 
 mrp_pushcfunction(L,set?set:const_array);
	mrp_rawset(L,-3);

 mrp_rawset(L,-3);                  /* store variable */
	mrp_pop(L,1);                      /* pop .get table */
}

