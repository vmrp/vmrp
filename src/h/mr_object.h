/*
** $Id: lobject.h,v 1.159 2003/03/18 12:50:04 roberto Exp $
** Type definitions for Lua objects
** See Copyright Notice in lua.h
*/

#ifndef mr_object_h
#define mr_object_h


#include "mr_limits.h"


/* tags for values visible from Lua */
#define NUM_TAGS	MRP_TTHREAD


/*
** Extra tags for non-values
*/
#define MRP_TPROTO	(NUM_TAGS+1)
#define MRP_TUPVAL	(NUM_TAGS+2)


/*
** Union of all collectable objects
*/
typedef union GCObject GCObject;


/*
** Common Header for all collectable objects (in macro form, to be
** included in other objects)
*/
#define CommonHeader	GCObject *next; lu_byte tt; lu_byte marked


/*
** Common header in struct form
*/
typedef struct GCheader {
  CommonHeader;
} GCheader;




/*
** Union of all Lua values
*/
typedef union {
  GCObject *gc;
  void *p;
  mrp_Number n;
  int b;
} Value;


/*
** Lua values (or `tagged objects')
*/
typedef struct mrp_TObject {
  int tt;
  Value value;
} TObject;


/* Macros to test type */
#define ttisnil(o)	(ttype(o) == MRP_TNIL)
#define ttisnumber(o)	(ttype(o) == MRP_TNUMBER)
#define ttisstring(o)	(ttype(o) == MRP_TSTRING)
#define ttistable(o)	(ttype(o) == MRP_TTABLE)
#define ttisfunction(o)	(ttype(o) == MRP_TFUNCTION)
#define ttisboolean(o)	(ttype(o) == MRP_TBOOLEAN)
#define ttisuserdata(o)	(ttype(o) == MRP_TUSERDATA)
#define ttisthread(o)	(ttype(o) == MRP_TTHREAD)
#define ttislightuserdata(o)	(ttype(o) == MRP_TLIGHTUSERDATA)

/* Macros to access values */
#define ttype(o)	((o)->tt)
#define gcvalue(o)	check_exp(iscollectable(o), (o)->value.gc)
#define pvalue(o)	check_exp(ttislightuserdata(o), (o)->value.p)
#define nvalue(o)	check_exp(ttisnumber(o), (o)->value.n)
#define tsvalue(o)	check_exp(ttisstring(o), &(o)->value.gc->ts)
#define uvalue(o)	check_exp(ttisuserdata(o), &(o)->value.gc->u)
#define clvalue(o)	check_exp(ttisfunction(o), &(o)->value.gc->cl)
#define hvalue(o)	check_exp(ttistable(o), &(o)->value.gc->h)
#define bvalue(o)	check_exp(ttisboolean(o), (o)->value.b)
#define thvalue(o)	check_exp(ttisthread(o), &(o)->value.gc->th)

#define l_isfalse(o)	(ttisnil(o) || (ttisboolean(o) && bvalue(o) == 0))

/* Macros to set values */
#define setnvalue(obj,x) \
  { TObject *i_o=(obj); i_o->tt=MRP_TNUMBER; i_o->value.n=(x); }

#define chgnvalue(obj,x) \
	check_exp(ttype(obj)==MRP_TNUMBER, (obj)->value.n=(x))

#define setpvalue(obj,x) \
  { TObject *i_o=(obj); i_o->tt=MRP_TLIGHTUSERDATA; i_o->value.p=(x); }

#define setbvalue(obj,x) \
  { TObject *i_o=(obj); i_o->tt=MRP_TBOOLEAN; i_o->value.b=(x); }

#define setsvalue(obj,x) \
  { TObject *i_o=(obj); i_o->tt=MRP_TSTRING; \
    i_o->value.gc=cast(GCObject *, (x)); \
    mrp_assert(i_o->value.gc->gch.tt == MRP_TSTRING); }

#define setuvalue(obj,x) \
  { TObject *i_o=(obj); i_o->tt=MRP_TUSERDATA; \
    i_o->value.gc=cast(GCObject *, (x)); \
    mrp_assert(i_o->value.gc->gch.tt == MRP_TUSERDATA); }

#define setthvalue(obj,x) \
  { TObject *i_o=(obj); i_o->tt=MRP_TTHREAD; \
    i_o->value.gc=cast(GCObject *, (x)); \
    mrp_assert(i_o->value.gc->gch.tt == MRP_TTHREAD); }

#define setclvalue(obj,x) \
  { TObject *i_o=(obj); i_o->tt=MRP_TFUNCTION; \
    i_o->value.gc=cast(GCObject *, (x)); \
    mrp_assert(i_o->value.gc->gch.tt == MRP_TFUNCTION); }

#define sethvalue(obj,x) \
  { TObject *i_o=(obj); i_o->tt=MRP_TTABLE; \
    i_o->value.gc=cast(GCObject *, (x)); \
    mrp_assert(i_o->value.gc->gch.tt == MRP_TTABLE); }

#define setnilvalue(obj) ((obj)->tt=MRP_TNIL)



/*
** for internal debug only
*/
#define checkconsistency(obj) \
  mrp_assert(!iscollectable(obj) || (ttype(obj) == (obj)->value.gc->gch.tt))


#define setobj(obj1,obj2) \
  { const TObject *o2=(obj2); TObject *o1=(obj1); \
    checkconsistency(o2); \
    o1->tt=o2->tt; o1->value = o2->value; }


/*
** different types of sets, according to destination
*/

/* from stack to (same) stack */
#define setobjs2s	setobj
/* to stack (not from same stack) */
#define setobj2s	setobj
#define setsvalue2s	setsvalue
/* from table to same table */
#define setobjt2t	setobj
/* to table */
#define setobj2t	setobj
/* to new object */
#define setobj2n	setobj
#define setsvalue2n	setsvalue

#define setttype(obj, tt) (ttype(obj) = (tt))


#define iscollectable(o)	(ttype(o) >= MRP_TSTRING)



typedef TObject *StkId;  /* index to stack elements */


/*
** String headers for string table
*/
typedef union TString {
  L_Umaxalign dummy;  /* ensures maximum alignment for strings */
  struct {
    CommonHeader;
    lu_byte reserved;
    lu_hash hash;
    size_t len;
  } tsv;
} TString;


#define getstr(ts)	cast(const char *, (ts) + 1)
#define svalue(o)       getstr(tsvalue(o))



typedef union Udata {
  L_Umaxalign dummy;  /* ensures maximum alignment for `local' udata */
  struct {
    CommonHeader;
    struct Table *metatable;
    size_t len;
  } uv;
} Udata;




/*
** Function Prototypes
*/
typedef struct Proto {
  CommonHeader;
  TObject *k;  /* constants used by the function */
  Instruction *code;
  struct Proto **p;  /* functions defined inside the function */
  int *lineinfo;  /* map from opcodes to source lines */
  struct LocVar *locvars;  /* information about local variables */
  TString **upvalues;  /* upvalue names */
  TString  *source;
  int sizeupvalues;
  int sizek;  /* size of `k' */
  int sizecode;
  int sizelineinfo;
  int sizep;  /* size of `p' */
  int sizelocvars;
  int lineDefined;
  GCObject *gclist;
  lu_byte nups;  /* number of upvalues */
  lu_byte numparams;
  lu_byte is_vararg;
  lu_byte maxstacksize;
} Proto;


typedef struct LocVar {
  TString *varname;
  int startpc;  /* first point where variable is active */
  int endpc;    /* first point where variable is dead */
} LocVar;



/*
** Upvalues
*/

typedef struct UpVal {
  CommonHeader;
  TObject *v;  /* points to stack or to its own value */
  TObject value;  /* the value (when closed) */
} UpVal;


/*
** Closures
*/

#define ClosureHeader \
	CommonHeader; lu_byte isC; lu_byte nupvalues; GCObject *gclist

typedef struct CClosure {
  ClosureHeader;
  mrp_CFunction f;
  TObject upvalue[1];
} CClosure;


typedef struct LClosure {
  ClosureHeader;
  struct Proto *p;
  TObject g;  /* global table for this closure */
  UpVal *upvals[1];
} LClosure;


typedef union Closure {
  CClosure c;
  LClosure l;
} Closure;


#define iscfunction(o)	(ttype(o) == MRP_TFUNCTION && clvalue(o)->c.isC)
#define isLfunction(o)	(ttype(o) == MRP_TFUNCTION && !clvalue(o)->c.isC)


/*
** Tables
*/

typedef struct Node {
  TObject i_key;
  TObject i_val;
  struct Node *next;  /* for chaining */
} Node;


typedef struct Table {
  CommonHeader;
  lu_byte flags;  /* 1<<p means tagmethod(p) is not present */ 
  lu_byte lsizenode;  /* log2 of size of `node' array */
  struct Table *metatable;
  TObject *array;  /* array part */
  Node *node;
  Node *firstfree;  /* this position is free; all positions after it are full */
  GCObject *gclist;
  int sizearray;  /* size of `array' array */
} Table;



/*
** `module' operation for hashing (size is always a power of 2)
*/
#define lmod(s,size) \
	check_exp((size&(size-1))==0, (cast(int, (s) & ((size)-1))))


#define twoto(x)	(1<<(x))
#define sizenode(t)	(twoto((t)->lsizenode))



extern const TObject mr_O_nilobject;

int mr_O_log2 (unsigned int x);
int mr_O_int2fb (unsigned int x);
#define fb2int(x)	(((x) & 7) << ((x) >> 3))

int mr_O_rawequalObj (const TObject *t1, const TObject *t2);
int mr_O_str2d (const char *s, mrp_Number *result);

const char *mr_O_pushvfstring (mrp_State *L, const char *fmt, va_list argp);
const char *mr_O_pushfstring (mrp_State *L, const char *fmt, ...);
void mr_O_chunkid (char *out, const char *source, int len);


#endif
