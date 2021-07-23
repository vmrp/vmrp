
#include "./include/mr.h"
#include "./include/mr_store.h"
#include "./include/mr_auxlib.h"

#include "./src/h/mr_api.h"
#include "./src/h/mr_do.h"
#include "./src/h/mr_func.h"
#include "./src/h/mr_gc.h"
#include "./src/h/mr_limits.h"
#include "./src/h/mr_mem.h"
#include "./src/h/mr_object.h"
#include "./src/h/mr_opcodes.h"
#include "./src/h/mr_state.h"
#include "./src/h/mr_string.h"



/* #define PLUTO_DEBUG */





#define PLUTO_TPERMANENT 101

#if 1
#define verify(x) mrp_assert((int)((x)))
#else
#define verify(x) { \
      int v = (int)((x)); \
      if(!v) {\
         mrp_pushstring(upi->L, "load/save table err!");\
         mrp_error(upi->L);\
      } \
   }
#endif

typedef struct PersistInfo_t {
   mrp_State *L;
   int counter;
   mrp_Chunkwriter writer;
   void *ud;
#ifdef PLUTO_DEBUG
   int level;
#endif
} PersistInfo;

#ifdef PLUTO_DEBUG
void printindent(int indent)
{
   int il;
   for(il=0; il<indent; il++) {
      printf("  ");
   }
}
#endif

/* Mutual recursion requires prototype */
static void persist(PersistInfo *pi);

/* A simple reimplementation of the unfortunately static function mr_A_index.
 * Does not support the global table, registry, or upvalues. */
static StkId getobject(mrp_State *L, int stackpos)
{
   if(stackpos > 0) {
      mrp_assert(L->base+stackpos-1 < L->top);
      return L->base+stackpos-1;
   } else {
      mrp_assert(L->top-stackpos >= L->base);
      return L->top+stackpos;
   }
}

/* Choose whether to do a regular or special persistence based on an object's
 * metatable. "default" is whether the object, if it doesn't have a __persist
 * entry, is literally persistable or not.
 * Pushes the unpersist closure and returns true if special persistence is 
 * used. */
static int persistspecialobject(PersistInfo *pi, int defaction)
{
               /* perms reftbl ... obj */
   /* Check whether we should persist literally, or via the __persist
    * metafunction */
   if(!mrp_getmetatable(pi->L, -1)) {
      if(defaction) {
         {
            int zero = 0;
            pi->writer(pi->L, &zero, sizeof(int), pi->ud);
         }
         return 0;
      } else {
         mrp_pushstring(pi->L, "Type not literally persistable by default");
         mrp_error(pi->L);
      }
   }
               /* perms reftbl sptbl ... obj mt */
   mrp_pushstring(pi->L, "__persist");
               /* perms reftbl sptbl ... obj mt "__persist" */
   mrp_rawget(pi->L, -2);
               /* perms reftbl sptbl ... obj mt __persist? */
   if(mrp_isnil(pi->L, -1)) {
               /* perms reftbl sptbl ... obj mt nil */
      mrp_pop(pi->L, 2);
               /* perms reftbl sptbl ... obj */
      if(defaction) {
         {
            int zero = 0;
            pi->writer(pi->L, &zero, sizeof(int), pi->ud);
         }
         return 0;
      } else {
         mrp_pushstring(pi->L, "Type not literally persistable by default");
         mrp_error(pi->L);
         return 0; /* not reached */
      }
   } else if(mrp_isboolean(pi->L, -1)) {
               /* perms reftbl sptbl ... obj mt bool */
      if(mrp_toboolean(pi->L, -1)) {
               /* perms reftbl sptbl ... obj mt true */
         mrp_pop(pi->L, 2);
               /* perms reftbl sptbl ... obj */
         {
            int zero = 0;
            pi->writer(pi->L, &zero, sizeof(int), pi->ud);
         }
         return 0;
      } else {
         mrp_pushstring(pi->L, "Metatable forbade persistence");
         mrp_error(pi->L);
         return 0; /* not reached */
      }
   } else if(!mrp_isfunction(pi->L, -1)) { 
      mrp_pushstring(pi->L, "__persist not nil, boolean, or function");
      mrp_error(pi->L);
   }
               /* perms reftbl ... obj mt __persist */
   mrp_pushvalue(pi->L, -3);
               /* perms reftbl ... obj mt __persist obj */
#ifdef PLUTO_PASS_USERDATA_TO_PERSIST
   mrp_pushlightuserdata(pi->L, (void*)pi->writer);
   mrp_pushlightuserdata(pi->L, pi->ud);
               /* perms reftbl ... obj mt __persist obj ud */
   mrp_call(pi->L, 3, 1);
               /* perms reftbl ... obj mt func? */
#else
   mrp_call(pi->L, 1, 1);
               /* perms reftbl ... obj mt func? */
#endif
               /* perms reftbl ... obj mt func? */
   if(!mrp_isfunction(pi->L, -1)) {
      mrp_pushstring(pi->L, "__persist function did not return a function");
      mrp_error(pi->L);
   }
               /* perms reftbl ... obj mt func */
   {
      int one = 1;
      pi->writer(pi->L, &one, sizeof(int), pi->ud);
   }
   persist(pi);
               /* perms reftbl ... obj mt func */
   mrp_pop(pi->L, 2);
               /* perms reftbl ... obj */
   return 1;
}

static void persisttable(PersistInfo *pi)
{
               /* perms reftbl ... tbl */
   if(persistspecialobject(pi, 1)) {
               /* perms reftbl ... tbl */
      return;
   }
               /* perms reftbl ... tbl */
   /* First, persist the metatable (if any) */
   if(!mrp_getmetatable(pi->L, -1)) {
      mrp_pushnil(pi->L);
   }
               /* perms reftbl ... tbl mt/nil */
   persist(pi);
   mrp_pop(pi->L, 1);
               /* perms reftbl ... tbl */

   /* Now, persist all k/v pairs */
   mrp_pushnil(pi->L);   
               /* perms reftbl ... tbl nil */
   while(mrp_next(pi->L, -2)) {
               /* perms reftbl ... tbl k v */
      mrp_pushvalue(pi->L, -2);
               /* perms reftbl ... tbl k v k */
      persist(pi);
      mrp_pop(pi->L, 1);
               /* perms reftbl ... tbl k v */
      persist(pi);
      mrp_pop(pi->L, 1);
               /* perms reftbl ... tbl k */
   }
               /* perms reftbl ... tbl */
   /* Terminate list */
   mrp_pushnil(pi->L);
               /* perms reftbl ... tbl nil */
   persist(pi);
   mrp_pop(pi->L, 1);
               /* perms reftbl ... tbl */
}

static void persistuserdata(PersistInfo *pi) {
               /* perms reftbl ... udata */
   if(persistspecialobject(pi, 0)) {
               /* perms reftbl ... udata */
      return;
   } else {
   /* Use literal persistence */
      int length = uvalue(getobject(pi->L, -2))->uv.len;
      pi->writer(pi->L, &length, sizeof(int), pi->ud);
      pi->writer(pi->L, mrp_touserdata(pi->L, -1), length, pi->ud);
      if(!mrp_getmetatable(pi->L, -1)) {
               /* perms reftbl ... udata */
         mrp_pushnil(pi->L);
               /* perms reftbl ... udata mt/nil */
      }
      persist(pi);
      mrp_pop(pi->L, 1);
               /* perms reftbl ... udata */
   }
}


static Proto *toproto(mrp_State *L, int stackpos)
{
   return gcotop(getobject(L, stackpos)->value.gc);
}

static UpVal *toupval(mrp_State *L, int stackpos)
{
   return gcotouv(getobject(L, stackpos)->value.gc);
}

static void pushproto(mrp_State *L, Proto *proto)
{
   TObject o;
   o.tt = MRP_TPROTO;
   o.value.gc = valtogco(proto);
   mr_A_pushobject(L, &o);
}

static void pushupval(mrp_State *L, UpVal *upval)
{
   TObject o;
   o.tt = MRP_TUPVAL;
   o.value.gc = valtogco(upval);
   mr_A_pushobject(L, &o);
}

static void pushclosure(mrp_State *L, Closure *closure)
{
   TObject o;
   o.tt = MRP_TFUNCTION;
   o.value.gc = valtogco(closure);
   mr_A_pushobject(L, &o);
}

static void persistfunction(PersistInfo *pi)
{
               /* perms reftbl ... func */
   Closure *cl = clvalue(getobject(pi->L, -1));
   if(cl->c.isC) {
      /* It's a C function. For now, we aren't going to allow
       * persistence of C closures, even if the "C proto" is
       * already in the permanents table. */
      mrp_pushstring(pi->L, "Attempt to persist a C function");
      mrp_error(pi->L);
   } else { 
      /* It's a Lua closure. */
      {
         /* We don't really _NEED_ the number of upvals,
          * but it'll simplify things a bit */
         pi->writer(pi->L, &cl->l.p->nups, sizeof(lu_byte), pi->ud);
      }
      /* Persist prototype */
      {
         pushproto(pi->L, cl->l.p);
               /* perms reftbl ... func proto */
         persist(pi);
         mrp_pop(pi->L, 1);
               /* perms reftbl ... func */
      }
      /* Persist upvalue values (not the upvalue objects
       * themselves) */
      {
         int i;
         for(i=0; i<cl->l.p->nups; i++) {
               /* perms reftbl ... func */
            pushupval(pi->L, cl->l.upvals[i]);
               /* perms reftbl ... func upval */
            persist(pi);
            mrp_pop(pi->L, 1);
               /* perms reftbl ... func */
         }   
               /* perms reftbl ... func */
      }
      /* Persist function environment */
      {
         mrp_getfenv(pi->L, -1);
               /* perms reftbl ... func fenv */
         if(mrp_equal(pi->L, -1, MRP_GLOBALSINDEX)) {
            /* Function has the default fenv */
               /* perms reftbl ... func _G */
            mrp_pop(pi->L, 1);
               /* perms reftbl ... func */
            mrp_pushnil(pi->L);
               /* perms reftbl ... func nil */
         }
               /* perms reftbl ... func fenv/nil */
         persist(pi);
         mrp_pop(pi->L, 1);
               /* perms reftbl ... func */
      }
   }
}


/* Upvalues are tricky. Here's why.
 *
 * A particular upvalue may be either "open", in which case its member v
 * points into a thread's stack, or "closed" in which case it points to the
 * upvalue itself. An upvalue is closed under any of the following conditions:
 * -- The function that initially declared the variable "local" returns
 * -- The thread in which the closure was created is garbage collected 
 *
 * To make things wackier, just because a thread is reachable by Lua doesn't
 * mean it's in our root set. We need to be able to treat an open upvalue
 * from an unreachable thread as a closed upvalue.
 *
 * The solution:
 * (a) For the purposes of persisting, don't indicate whether an upvalue is
 * closed or not.
 * (b) When unpersisting, pretend that all upvalues are closed.
 * (c) When persisting, persist all open upvalues referenced by a thread
 * that is persisted, and tag each one with the corresponding stack position
 * (d) When unpersisting, "reopen" each of these upvalues as the thread is
 * unpersisted
 */
static void persistupval(PersistInfo *pi)
{
               /* perms reftbl ... upval */
   UpVal *uv = toupval(pi->L, -1);

   mr_A_pushobject(pi->L, uv->v);
               /* perms reftbl ... upval obj */
   persist(pi);
   mrp_pop(pi->L, 1);
               /* perms reftbl ... upval */
}

static void persistproto(PersistInfo *pi)
{
               /* perms reftbl ... proto */
   Proto *p = toproto(pi->L, -1);

   /* Persist constant refs */
   {
      int i;
      pi->writer(pi->L, &p->sizek, sizeof(int), pi->ud);
      for(i=0; i<p->sizek; i++) {
         mr_A_pushobject(pi->L, &p->k[i]);
               /* perms reftbl ... proto const */
         persist(pi);
         mrp_pop(pi->L, 1);
               /* perms reftbl ... proto */
      }
   }
               /* perms reftbl ... proto */

   /* serialize inner Proto refs */
   {
      int i;
      pi->writer(pi->L, &p->sizep, sizeof(int), pi->ud);
      for(i=0; i<p->sizep; i++)
      {
         pushproto(pi->L, p->p[i]);
               /* perms reftbl ... proto subproto */
         persist(pi);
         mrp_pop(pi->L, 1);
               /* perms reftbl ... proto */
      }
   }
               /* perms reftbl ... proto */
   /* Serialize code */
   {
      pi->writer(pi->L, &p->sizecode, sizeof(int), pi->ud);
      pi->writer(pi->L, p->code, sizeof(Instruction) * p->sizecode, pi->ud);
   }
   /* Serialize misc values */
   {
      pi->writer(pi->L, &p->nups, sizeof(lu_byte), pi->ud);
      pi->writer(pi->L, &p->numparams, sizeof(lu_byte), pi->ud);
      pi->writer(pi->L, &p->is_vararg, sizeof(lu_byte), pi->ud);
      pi->writer(pi->L, &p->maxstacksize, sizeof(lu_byte), pi->ud);
   }
   /* We do not currently persist upvalue names, local variable names,
    * variable lifetimes, line info, or source code. */
}

/* Copies a stack, but the stack is reversed in the process
 */
static int revappendstack(mrp_State *from, mrp_State *to) 
{
   StkId o;
   for(o=from->top-1; o>=from->stack; o--) {
      setobj2s(to->top, o);
      to->top++;
   }
   return from->top - from->stack;
}

/* Persist all stack members
 */
static void persistthread(PersistInfo *pi)
{
   int posremaining;
   mrp_State *L2;
               /* perms reftbl ... thr */
   L2 = mrp_tothread(pi->L, -1);
   if(pi->L == L2) {
      mrp_pushstring(pi->L, "Can't persist currently running thread");
      mrp_error(pi->L);
      return; /* not reached */
   }
   posremaining = revappendstack(L2, pi->L);
               /* perms reftbl ... thr (rev'ed contents of L2) */
   pi->writer(pi->L, &posremaining, sizeof(int), pi->ud);
   for(; posremaining > 0; posremaining--) {
      persist(pi);
      mrp_pop(pi->L, 1);
   }
               /* perms reftbl ... thr */
   /* Now, persist the CallInfo stack. */
   {
      int i, numframes = (L2->ci - L2->base_ci) + 1;
      pi->writer(pi->L, &numframes, sizeof(int), pi->ud);
      for(i=0; i<numframes; i++) {
         CallInfo *ci = L2->base_ci + i;
         int stackbase = ci->base - L2->stack; 
         int stacktop = ci->top - L2->stack;
         int pc = (ci != L2->base_ci) ? 
            ci->u.l.savedpc - ci_func(ci)->l.p->code :
            0;
         pi->writer(pi->L, &stackbase, sizeof(int), pi->ud);
         pi->writer(pi->L, &stacktop, sizeof(int), pi->ud);
         pi->writer(pi->L, &pc, sizeof(int), pi->ud);
         pi->writer(pi->L, &(ci->state), sizeof(int), pi->ud);
      }
   }

   /* Serialize the state's top and base */
   {
      int stackbase = L2->base - L2->stack; 
      int stacktop = L2->top - L2->stack;
      pi->writer(pi->L, &stackbase, sizeof(int), pi->ud);
      pi->writer(pi->L, &stacktop, sizeof(int), pi->ud);
   }

   /* Finally, record upvalues which need to be reopened */
   /* See the comment above persistupval() for why we do this */
   {
      UpVal *uv;
               /* perms reftbl ... thr */
      for(uv = gcotouv(L2->openupval); uv != NULL; uv = gcotouv(uv->next)) {
         int stackpos;
         /* Make sure upvalue is really open */
         mrp_assert(uv->v != &uv->value);
         pushupval(pi->L, uv);
               /* perms reftbl ... thr uv */
         persist(pi);
         mrp_pop(pi->L, 1);
               /* perms reftbl ... thr */
         stackpos = uv->v - L2->stack;
         pi->writer(pi->L, &stackpos, sizeof(int), pi->ud);
      }
               /* perms reftbl ... thr */
      mrp_pushnil(pi->L);
               /* perms reftbl ... thr nil */
      persist(pi);
      mrp_pop(pi->L, 1);
               /* perms reftbl ... thr */
   }
               /* perms reftbl ... thr */
}

static void persistboolean(PersistInfo *pi)
{
   int b = mrp_toboolean(pi->L, -1);
   pi->writer(pi->L, &b, sizeof(int), pi->ud);
}

static void persistlightuserdata(PersistInfo *pi)
{
   void *p = mrp_touserdata(pi->L, -1);
   pi->writer(pi->L, &p, sizeof(void *), pi->ud);
}

static void persistnumber(PersistInfo *pi)
{
   mrp_Number n = mrp_tonumber(pi->L, -1);
   pi->writer(pi->L, &n, sizeof(mrp_Number), pi->ud);
}

static void persiststring(PersistInfo *pi)
{
   int length = mrp_strlen(pi->L, -1);
   pi->writer(pi->L, &length, sizeof(int), pi->ud);
   pi->writer(pi->L, mrp_tostring(pi->L, -1), length, pi->ud);
}

/* Top-level delegating persist function
 */
static void persist(PersistInfo *pi)
{
               /* perms reftbl ... obj */
   /* If the object has already been written, write a reference to it */
   mrp_pushvalue(pi->L, -1);
               /* perms reftbl ... obj obj */
   mrp_rawget(pi->L, 2);
               /* perms reftbl ... obj ref? */
   if(!mrp_isnil(pi->L, -1)) {
               /* perms reftbl ... obj ref */
      int zero = 0;
      int ref = (int)mrp_touserdata(pi->L, -1);
      pi->writer(pi->L, &zero, sizeof(int), pi->ud);
      pi->writer(pi->L, &ref, sizeof(int), pi->ud);
      mrp_pop(pi->L, 1);
               /* perms reftbl ... obj ref */
#ifdef PLUTO_DEBUG
      printindent(pi->level);
      printf("0 %d\n", ref);
#endif
      return;
   }
               /* perms reftbl ... obj nil */
   mrp_pop(pi->L, 1);
               /* perms reftbl ... obj */
   /* If the object is nil, write the pseudoreference 0 */
   if(mrp_isnil(pi->L, -1)) {
      int zero = 0;
      /* firsttime */
      pi->writer(pi->L, &zero, sizeof(int), pi->ud);
      /* ref */
      pi->writer(pi->L, &zero, sizeof(int), pi->ud);
#ifdef PLUTO_DEBUG
      printindent(pi->level);
      printf("0 0\n");
#endif
      return;
   }
   {
      /* indicate that it's the first time */
      int one = 1;
      pi->writer(pi->L, &one, sizeof(int), pi->ud);
   }
   mrp_pushvalue(pi->L, -1);
               /* perms reftbl ... obj obj */
   mrp_pushlightuserdata(pi->L, (void*)(++(pi->counter)));
               /* perms reftbl ... obj obj ref */
   mrp_rawset(pi->L, 2);
               /* perms reftbl ... obj */

   pi->writer(pi->L, &pi->counter, sizeof(int), pi->ud);


   /* At this point, we'll give the permanents table a chance to play. */
   {
      mrp_pushvalue(pi->L, -1);
               /* perms reftbl ... obj obj */
      mrp_gettable(pi->L, 1);
               /* perms reftbl ... obj permkey? */
      if(!mrp_isnil(pi->L, -1)) {
               /* perms reftbl ... obj permkey */
         int type = PLUTO_TPERMANENT;
#ifdef PLUTO_DEBUG
         printindent(pi->level);
         printf("1 %d PERM\n", pi->counter);
         pi->level++;
#endif
         pi->writer(pi->L, &type, sizeof(int), pi->ud);
         persist(pi);
         mrp_pop(pi->L, 1);
               /* perms reftbl ... obj */
#ifdef PLUTO_DEBUG
         pi->level--;
#endif
         return;
      } else {
               /* perms reftbl ... obj nil */
         mrp_pop(pi->L, 1);
               /* perms reftbl ... obj */
      }
               /* perms reftbl ... obj */
   }
   {
      int type = mrp_type(pi->L, -1);
      pi->writer(pi->L, &type, sizeof(int), pi->ud);

#ifdef PLUTO_DEBUG
      printindent(pi->level);
      printf("1 %d %d\n", pi->counter, type);
      pi->level++;
#endif
   }

   switch(mrp_type(pi->L, -1)) {
      case MRP_TBOOLEAN:
         persistboolean(pi);
         break;
      case MRP_TLIGHTUSERDATA:
         persistlightuserdata(pi);
         break;
      case MRP_TNUMBER:
         persistnumber(pi);
         break;
      case MRP_TSTRING:
         persiststring(pi);
         break;
      case MRP_TTABLE:
         persisttable(pi);
         break;
      case MRP_TFUNCTION:
         persistfunction(pi);
         break;
      case MRP_TTHREAD:
         persistthread(pi);
         break;
      case MRP_TPROTO:
         persistproto(pi);
         break;
      case MRP_TUPVAL:
         persistupval(pi);
         break;
      case MRP_TUSERDATA:
         persistuserdata(pi);
         break;
      default:
         mrp_assert(0);
   }
#ifdef PLUTO_DEBUG
   pi->level--;
#endif
}

void mr_store_persist(mrp_State *L, mrp_Chunkwriter writer, void *ud)
{
   PersistInfo pi;
   
   pi.counter = 0;
   pi.L = L;
   pi.writer = writer;
   pi.ud = ud;
#ifdef PLUTO_DEBUG
   pi.level = 0;
#endif

               /* perms rootobj */
   mrp_newtable(L);
               /* perms rootobj reftbl */

   /* Now we're going to make the table weakly keyed. This prevents the
    * GC from visiting it and trying to mark things it doesn't want to
    * mark in tables, e.g. upvalues. All objects in the table are
    * a priori reachable, so it doesn't matter that we do this. */
   mrp_newtable(L);
               /* perms rootobj reftbl mt */
   mrp_pushstring(L, "__mode");
               /* perms rootobj reftbl mt "__mode" */
   mrp_pushstring(L, "k");
               /* perms rootobj reftbl mt "__mode" "k" */
   mrp_settable(L, 4);
               /* perms rootobj reftbl mt */
   mrp_setmetatable(L, 3);
               /* perms rootobj reftbl */
   mrp_insert(L, 2);
               /* perms reftbl rootobj */
   persist(&pi);
               /* perms reftbl rootobj */
   mrp_remove(L, 2);
               /* perms rootobj */
}

int mr_str_bufwriter (mrp_State *L, const void* p, size_t sz, void* ud) {
   WriterInfo *wi = (WriterInfo *)ud;

   mr_M_reallocvector(L, wi->buf, wi->buflen, wi->buflen+sz, char);
   while(sz)
   {
      wi->buf[wi->buflen++] = *((const char*)p);
      p = (const char*)p + 1;
      sz--;
   }
   return 0;
}

int persist_l(mrp_State *L)
{
               /* perms? rootobj? ...? */
   WriterInfo wi;

   wi.buf = NULL;
   wi.buflen = 0;

   mrp_settop(L, 2);
               /* perms? rootobj? */
   mr_L_checktype(L, 1, MRP_TTABLE);
               /* perms rootobj? */
   mr_L_checktype(L, 2, MRP_TTABLE);
               /* perms rootobj */
   
   mr_store_persist(L, mr_str_bufwriter, &wi);

   mrp_settop(L, 0);
               /* (empty) */
   mrp_pushlstring(L, wi.buf, wi.buflen);
               /* str */
   mr_M_freearray(L, wi.buf, wi.buflen, char);
   return 1;
}

typedef struct UnpersistInfo_t {
   mrp_State *L;
   ZIO zio;
#ifdef PLUTO_DEBUG
   int level;
#endif
} UnpersistInfo;

static void unpersist(UnpersistInfo *upi);

/* The object is left on the stack. This is primarily used by unpersist, but
 * may be used by GCed objects that may incur cycles in order to preregister
 * the object. */
static void registerobject(int ref, UnpersistInfo *upi)
{
               /* perms reftbl ... obj */
   mrp_pushlightuserdata(upi->L, (void*)ref);
               /* perms reftbl ... obj ref */
   mrp_pushvalue(upi->L, -2);
               /* perms reftbl ... obj ref obj */
   mrp_settable(upi->L, 2);
               /* perms reftbl ... obj */
}

static void unpersistboolean(UnpersistInfo *upi)
{
               /* perms reftbl ... */
   int b=0;
   verify(mr_Z_read(&upi->zio, &b, sizeof(int)) == 0);
   mrp_pushboolean(upi->L, b);
               /* perms reftbl ... bool */
}

static void unpersistlightuserdata(UnpersistInfo *upi)
{
               /* perms reftbl ... */
   void *p=NULL;
   verify(mr_Z_read(&upi->zio, &p, sizeof(void *)) == 0);
   mrp_pushlightuserdata(upi->L, p);
               /* perms reftbl ... ludata */
}

static void unpersistnumber(UnpersistInfo *upi)
{
               /* perms reftbl ... */
   mrp_Number n=0;
   verify(mr_Z_read(&upi->zio, &n, sizeof(mrp_Number)) == 0);
   mrp_pushnumber(upi->L, n);
               /* perms reftbl ... num */
}

static void unpersiststring(UnpersistInfo *upi)
{
               /* perms reftbl sptbl ref */
   int length=0;
   char* string;
   verify(mr_Z_read(&upi->zio, &length, sizeof(int)) == 0);
   string = mr_M_malloc(upi->L, length);
   verify(mr_Z_read(&upi->zio, string, length) == 0);
   mrp_pushlstring(upi->L, string, length);
               /* perms reftbl sptbl ref str */
   mr_M_free(upi->L, string, length);
}

static void unpersistspecialtable(int ref, UnpersistInfo *upi)
{
               /* perms reftbl ... */
   unpersist(upi);
               /* perms reftbl ... spfunc? */
   mrp_assert(mrp_isfunction(upi->L, -1));
               /* perms reftbl ... spfunc */
   mrp_call(upi->L, 0, 1);
               /* perms reftbl ... tbl? */
   mrp_assert(mrp_istable(upi->L, -1));
               /* perms reftbl ... tbl */
}

static void unpersistliteraltable(int ref, UnpersistInfo *upi)
{
               /* perms reftbl ... */
   /* Preregister table for handling of cycles */
   mrp_newtable(upi->L);
               /* perms reftbl ... tbl */
   registerobject(ref, upi);
               /* perms reftbl ... tbl */
   /* Unpersist metatable */
   {
      unpersist(upi);
               /* perms reftbl ... tbl mt/nil? */
      if(mrp_istable(upi->L, -1)) {
               /* perms reftbl ... tbl mt */
         mrp_setmetatable(upi->L, -2);
               /* perms reftbl ... tbl */
      } else {
               /* perms reftbl ... tbl nil? */
         mrp_assert(mrp_isnil(upi->L, -1));
               /* perms reftbl ... tbl nil */
         mrp_pop(upi->L, 1);
               /* perms reftbl ... tbl */
      }
               /* perms reftbl ... tbl */
   }

   while(1)
   {
               /* perms reftbl ... tbl */
      unpersist(upi);
               /* perms reftbl ... tbl key/nil */
      if(mrp_isnil(upi->L, -1)) {
               /* perms reftbl ... tbl nil */
         mrp_pop(upi->L, 1);
               /* perms reftbl ... tbl */
         break;
      }
               /* perms reftbl ... tbl key */
      unpersist(upi);
               /* perms reftbl ... tbl key value? */
      mrp_assert(!mrp_isnil(upi->L, -1));
               /* perms reftbl ... tbl key value */
      mrp_settable(upi->L, -3);
               /* perms reftbl ... tbl */
   }
}

static void unpersisttable(int ref, UnpersistInfo *upi)
{
               /* perms reftbl ... */
   {
      int isspecial=0;
      verify(mr_Z_read(&upi->zio, &isspecial, sizeof(int)) == 0);
      if(isspecial) {
         unpersistspecialtable(ref, upi);
               /* perms reftbl ... tbl */
      } else {
         unpersistliteraltable(ref, upi);
               /* perms reftbl ... tbl */
      }
               /* perms reftbl ... tbl */
   }
}

static UpVal *makeupval(mrp_State *L, int stackpos)
{
   UpVal *uv = mr_M_new(L, UpVal);
   uv->tt = MRP_TUPVAL;
   uv->v = &uv->value;
   setobj(uv->v, getobject(L, stackpos));
   mr_C_link(L, valtogco(uv), MRP_TUPVAL);
   return uv;
}

static Proto *makefakeproto(mrp_State *L, lu_byte nups)
{
   Proto *p = mr_F_newproto(L);
   p->sizelineinfo = 1;
   p->lineinfo = mr_M_newvector(L, 1, int);
   p->lineinfo[0] = 1;
   p->sizecode = 1;
   p->code = mr_M_newvector(L, 1, Instruction);
   p->code[0] = CREATE_ABC(OP_RETURN, 0, 1, 0);
   p->source = mr_S_newlstr(L, "", 0);
   p->maxstacksize = 2;
   p->nups = nups;
   p->sizek = 0;
   p->sizep = 0;

   return p;
}

/* The GC is not fond of finding upvalues in tables. We get around this
 * during persistence using a weakly keyed table, so that the GC doesn't
 * bother to mark them. This won't work in unpersisting, however, since
 * if we make the values weak they'll be collected (since nothing else
 * references them). Our solution, during unpersisting, is to represent
 * upvalues as dummy functions, each with one upvalue. */
static void boxupval(mrp_State *L)
{
               /* ... upval */
   LClosure *lcl;
   UpVal *uv;

   uv = toupval(L, -1);
   mrp_pop(L, 1);
               /* ... */
   lcl = (LClosure*)mr_F_newLclosure(L, 1, &L->_gt);
   pushclosure(L, (Closure*)lcl);
               /* ... func */
   lcl->p = makefakeproto(L, 1);
   lcl->upvals[0] = uv;
}

static void unboxupval(mrp_State *L)
{
               /* ... func */
   LClosure *lcl;
   UpVal *uv;

   lcl = (LClosure*)clvalue(getobject(L, -1));
   uv = lcl->upvals[0];
   mrp_pop(L, 1);
               /* ... */
   pushupval(L, uv);
               /* ... upval */
}

static void unpersistfunction(int ref, UnpersistInfo *upi)
{
               /* perms reftbl ... */
   LClosure *lcl;
   int i;
   lu_byte nupvalues=0;

   verify(mr_Z_read(&upi->zio, &nupvalues, sizeof(lu_byte)) == 0);

   lcl = (LClosure*)mr_F_newLclosure(upi->L, nupvalues, &upi->L->_gt);
   pushclosure(upi->L, (Closure*)lcl);

               /* perms reftbl ... func */
   /* Put *some* proto in the closure, before the GC can find it */
   lcl->p = makefakeproto(upi->L, nupvalues);

   /* Also, we need to temporarily fill the upvalues */
   mrp_pushnil(upi->L);
               /* perms reftbl ... func nil */
   for(i=0; i<nupvalues; i++) {
      lcl->upvals[i] = makeupval(upi->L, -1);
   }
   mrp_pop(upi->L, 1);
               /* perms reftbl ... func */

   /* I can't see offhand how a function would ever get to be self-
    * referential, but just in case let's register it early */
   registerobject(ref, upi);

   /* Now that it's safe, we can get the real proto */
   unpersist(upi);
               /* perms reftbl ... func proto? */
   mrp_assert(mrp_type(upi->L, -1) == MRP_TPROTO);
               /* perms reftbl ... func proto */
   lcl->p = toproto(upi->L, -1);
   mrp_pop(upi->L, 1);
               /* perms reftbl ... func */

   for(i=0; i<nupvalues; i++) {
               /* perms reftbl ... func */
      unpersist(upi);
               /* perms reftbl ... func func2 */
      unboxupval(upi->L);
               /* perms reftbl ... func upval */
      lcl->upvals[i] = toupval(upi->L, -1);
      mrp_pop(upi->L, 1);
               /* perms reftbl ... func */
   }
               /* perms reftbl ... func */

   /* Finally, the fenv */
   unpersist(upi);
               /* perms reftbl ... func fenv/nil? */
   mrp_assert(mrp_type(upi->L, -1) == MRP_TNIL ||
      mrp_type(upi->L, -1) == MRP_TTABLE);
               /* perms reftbl ... func fenv/nil */
   if(!mrp_isnil(upi->L, -1)) {
               /* perms reftbl ... func fenv */
      mrp_setfenv(upi->L, -2);
               /* perms reftbl ... func */
   } else {
               /* perms reftbl ... func nil */
      mrp_pop(upi->L, 1);
               /* perms reftbl ... func */
   }
               /* perms reftbl ... func */
}

static void unpersistupval(int ref, UnpersistInfo *upi)
{
               /* perms reftbl ... */
   UpVal *uv;

   unpersist(upi);
               /* perms reftbl ... obj */
   uv = makeupval(upi->L, -1);
   mrp_pop(upi->L, 1);
               /* perms reftbl ... */
   pushupval(upi->L, uv);
               /* perms reftbl ... upval */
   boxupval(upi->L);
               /* perms reftbl ... func */
}
   
static void unpersistproto(int ref, UnpersistInfo *upi)
{
               /* perms reftbl ... */
   Proto *p;
   int i;
   int sizep=0, sizek=0;

   /* We have to be careful. The GC expects a lot out of protos. In
    * particular, we need to give the function a valid string for its
    * source, and valid code, even before we actually read in the real
    * code. */
   TString *source = mr_S_newlstr(upi->L, "", 0);
   p = mr_F_newproto(upi->L);
   p->source = source;
   p->sizecode=1;
   p->code = mr_M_newvector(upi->L, 1, Instruction);
   p->code[0] = CREATE_ABC(OP_RETURN, 0, 1, 0);
   p->maxstacksize = 2;
   p->sizek = 0;
   p->sizep = 0;
   

   pushproto(upi->L, p);
               /* perms reftbl ... proto */
   /* We don't need to register early, since protos can never ever be
    * involved in cyclic references */

   /* Read in constant references */
   {
      verify(mr_Z_read(&upi->zio, &sizek, sizeof(int)) == 0);
      mr_M_reallocvector(upi->L, p->k, 0, sizek, TObject);
      for(i=0; i<sizek; i++) {
               /* perms reftbl ... proto */
         unpersist(upi);
               /* perms reftbl ... proto k */
         setobj2s(&p->k[i], getobject(upi->L, -1));
         p->sizek++;
         mrp_pop(upi->L, 1);
               /* perms reftbl ... proto */
      }
               /* perms reftbl ... proto */
   }
   /* Read in sub-proto references */
   {
      verify(mr_Z_read(&upi->zio, &sizep, sizeof(int)) == 0);
      mr_M_reallocvector(upi->L, p->p, 0, sizep, Proto*);
      for(i=0; i<sizep; i++) {
               /* perms reftbl ... proto */
         unpersist(upi);
               /* perms reftbl ... proto subproto */
         p->p[i] = toproto(upi->L, -1);
         p->sizep++;
         mrp_pop(upi->L, 1);
               /* perms reftbl ... proto */
      }
               /* perms reftbl ... proto */
   }

   /* Read in code */
   {
      verify(mr_Z_read(&upi->zio, &p->sizecode, sizeof(int)) == 0);
      mr_M_reallocvector(upi->L, p->code, 1, p->sizecode, Instruction);
      verify(mr_Z_read(&upi->zio, p->code, 
         sizeof(Instruction) * p->sizecode) == 0);
   }

   /* Read in misc values */
   {
      verify(mr_Z_read(&upi->zio, &p->nups, sizeof(lu_byte)) == 0);
      verify(mr_Z_read(&upi->zio, &p->numparams, sizeof(lu_byte)) == 0);
      verify(mr_Z_read(&upi->zio, &p->is_vararg, sizeof(lu_byte)) == 0);
      verify(mr_Z_read(&upi->zio, &p->maxstacksize, sizeof(lu_byte)) == 0);
   }
}


/* Does basically the opposite of mr_C_link().
 * Right now this function is rather inefficient; it requires traversing the
 * entire root GC set in order to find one object. If the GC list were doubly
 * linked this would be much easier, but there's no reason for Lua to have
 * that. */
static void gcunlink(mrp_State *L, GCObject *gco)
{
   GCObject *prevslot;
   if(G(L)->rootgc == gco) {
      G(L)->rootgc = G(L)->rootgc->gch.next;
      return;
   }

   prevslot = G(L)->rootgc;
   while(prevslot->gch.next != gco) {
      mrp_assert(prevslot->gch.next != NULL);
      prevslot = prevslot->gch.next;
   }

   prevslot->gch.next = prevslot->gch.next->gch.next;
}

static void unpersistthread(int ref, UnpersistInfo *upi)
{
               /* perms reftbl ... */
   mrp_State *L2;
   L2 = mrp_newthread(upi->L);
               /* L1: perms reftbl ... thr */
               /* L2: (empty) */
   registerobject(ref, upi);

   /* First, deserialize the object stack. */
   {
      int i, stacksize=0;
      verify(mr_Z_read(&upi->zio, &stacksize, sizeof(int)) == 0);
      mr_D_growstack(L2, stacksize);
      /* Make sure that the first stack element (a nil, representing
       * the imaginary top-level C function) is written to the very,
       * very bottom of the stack */
      L2->top--;
      for(i=0; i<stacksize; i++) {
         unpersist(upi);
               /* L1: perms reftbl ... thr obj* */
      }
      mrp_xmove(upi->L, L2, stacksize);
               /* L1: perms reftbl ... thr */
               /* L2: obj* */
   }

   /* Now, deserialize the CallInfo stack. */
   {
      int i, numframes=0;
      verify(mr_Z_read(&upi->zio, &numframes, sizeof(int)) == 0);
      mr_D_reallocCI(L2,numframes*2);
      for(i=0; i<numframes; i++) {
         CallInfo *ci = L2->base_ci + i;
         int stackbase=0, stacktop=0, pc=0;
         verify(mr_Z_read(&upi->zio, &stackbase, sizeof(int)) == 0);
         verify(mr_Z_read(&upi->zio, &stacktop, sizeof(int)) == 0);
         verify(mr_Z_read(&upi->zio, &pc, sizeof(int)) == 0);
         verify(mr_Z_read(&upi->zio, &(ci->state), sizeof(int)) == 0);

         ci->base = L2->stack+stackbase;
         ci->top = L2->stack+stacktop;
         if(!(ci->state & CI_C)) {
            ci->u.l.savedpc = ci_func(ci)->l.p->code + pc;
         }
         ci->u.l.tailcalls = 0;
         /* Update the pointer each time, to keep the GC 
          * happy*/
         L2->ci = ci; 
      }
   }
               /* L1: perms reftbl ... thr */
   {
      int stackbase=0, stacktop=0;
      verify(mr_Z_read(&upi->zio, &stackbase, sizeof(int)) == 0);
      verify(mr_Z_read(&upi->zio, &stacktop, sizeof(int)) == 0);
      L2->base = L2->stack + stackbase;
      L2->top = L2->stack + stacktop;
   }
   /* Finally, "reopen" upvalues (see persistupval() for why) */
   {
      UpVal* uv;
      GCObject **nextslot = &L2->openupval;
      while(1) {
         int stackpos=0;
         unpersist(upi);
               /* perms reftbl ... thr uv/nil */
         if(mrp_isnil(upi->L, -1)) {
               /* perms reftbl ... thr nil */
            mrp_pop(upi->L, 1);
               /* perms reftbl ... thr */
            break;
         }
               /* perms reftbl ... thr boxeduv */
         unboxupval(upi->L);
               /* perms reftbl ... thr uv */
         uv = toupval(upi->L, -1);
         mrp_pop(upi->L, 1);
               /* perms reftbl ... thr */

         verify(mr_Z_read(&upi->zio, &stackpos, sizeof(int)) == 0);
         uv->v = L2->stack + stackpos;
         gcunlink(upi->L, valtogco(uv));
         uv->marked = 1;
         *nextslot = valtogco(uv);
         nextslot = &uv->next;
      }
      *nextslot = NULL;
   }
}

static void unpersistuserdata(int ref, UnpersistInfo *upi)
{
               /* perms reftbl ... */
   int isspecial=0;
   verify(mr_Z_read(&upi->zio, &isspecial, sizeof(int)) == 0);
   if(isspecial) {
      unpersist(upi);
               /* perms reftbl ... spfunc? */
      mrp_assert(mrp_isfunction(upi->L, -1));
               /* perms reftbl ... spfunc */
#ifdef PLUTO_PASS_USERDATA_TO_PERSIST
      mrp_pushlightuserdata(upi->L, &upi->zio);
      mrp_call(upi->L, 1, 1);
#else
      mrp_call(upi->L, 0, 1);
#endif
               /* perms reftbl ... udata? */
/* This assertion might not be necessary; it's conceivable, for
 * example, that the SP function might decide to return a table
 * with equivalent functionality. For the time being, we'll
 * ignore this possibility in favor of stricter and more testable
 * requirements. */
      mrp_assert(mrp_isuserdata(upi->L, -1));
               /* perms reftbl ... udata */
   } else {
      int length=0;
      verify(mr_Z_read(&upi->zio, &length, sizeof(int)) == 0);

      mrp_newuserdata(upi->L, length);
               /* perms reftbl ... udata */
      registerobject(ref, upi);
      verify(mr_Z_read(&upi->zio, mrp_touserdata(upi->L, -1), length) == 0);

      unpersist(upi);
               /* perms reftbl ... udata mt/nil? */
      mrp_assert(mrp_istable(upi->L, -1) || mrp_isnil(upi->L, -1));
               /* perms reftbl ... udata mt/nil */
      mrp_setmetatable(upi->L, -2);
               /* perms reftbl ... udata */
   }
               /* perms reftbl ... udata */
}

static void unpersistpermanent(int ref, UnpersistInfo *upi)
{
               /* perms reftbl ... */
   unpersist(upi);
               /* perms reftbl permkey */
   mrp_gettable(upi->L, 1);
               /* perms reftbl perm? */
   /* We assume currently that the substituted permanent value
    * shouldn't be nil. This may be a bad assumption. Real-life
    * experience is needed to evaluate this. */
   mrp_assert(!mrp_isnil(upi->L, -1));
               /* perms reftbl perm */
}

/* For debugging only; not called when mrp_assert is empty */
int inreftable(mrp_State *L, int ref)
{
   int res;
               /* perms reftbl ... */
   mrp_pushlightuserdata(L, (void*)ref);
               /* perms reftbl ... ref */
   mrp_gettable(L, 2);
               /* perms reftbl ... obj? */
   res = !mrp_isnil(L, -1);
   mrp_pop(L, 1);
               /* perms reftbl ... */
   return res;
}

static void unpersist(UnpersistInfo *upi)
{
               /* perms reftbl ... */
   int firstTime=0;
   int stacksize = mrp_gettop(upi->L); /* DEBUG */
   verify(mr_Z_read(&upi->zio, &firstTime, sizeof(int)) == 0);
   
   if(firstTime) {
      int ref=0;
      int type=0;
      verify(mr_Z_read(&upi->zio, &ref, sizeof(int)) == 0);
      mrp_assert(!inreftable(upi->L, ref));
      verify(mr_Z_read(&upi->zio, &type, sizeof(int)) == 0);
#ifdef PLUTO_DEBUG
      printindent(upi->level);
      printf("1 %d %d\n", ref, type);
      upi->level++;
#endif
      switch(type) {
      case MRP_TBOOLEAN:
         unpersistboolean(upi);
         break;
      case MRP_TLIGHTUSERDATA:
         unpersistlightuserdata(upi);
         break;
      case MRP_TNUMBER:
         unpersistnumber(upi);
         break;
      case MRP_TSTRING:
         unpersiststring(upi);
         break;
      case MRP_TTABLE:
         //MRDBGPRINTF("start time=%d",mr_getTime());
         unpersisttable(ref, upi);
         //MRDBGPRINTF("end time=%d",mr_getTime());
         break;
      case MRP_TFUNCTION:
         unpersistfunction(ref, upi);
         break;
      case MRP_TTHREAD:
         unpersistthread(ref, upi);
         break;
      case MRP_TPROTO:
         unpersistproto(ref, upi);
         break;
      case MRP_TUPVAL:
         unpersistupval(ref, upi);
         break;
      case MRP_TUSERDATA:
         unpersistuserdata(ref, upi);
         break;
      case PLUTO_TPERMANENT:
         unpersistpermanent(ref, upi);
         break;
      default:
         mrp_assert(0);
      }
               /* perms reftbl ... obj */
      mrp_assert(mrp_type(upi->L, -1) == type || 
         type == PLUTO_TPERMANENT ||
         /* Remember, upvalues get a special dispensation, as
          * described in boxupval */
         (mrp_type(upi->L, -1) == MRP_TFUNCTION && 
            type == MRP_TUPVAL));
      registerobject(ref, upi);
               /* perms reftbl ... obj */
#ifdef PLUTO_DEBUG
      upi->level--;
#endif
   } else {
      int ref=0;
      verify(mr_Z_read(&upi->zio, &ref, sizeof(int)) == 0);
#ifdef PLUTO_DEBUG
      printindent(upi->level);
      printf("0 %d\n", ref);
#endif
      if(ref == 0) {
         mrp_pushnil(upi->L);
               /* perms reftbl ... nil */
      } else {
         mrp_pushlightuserdata(upi->L, (void*)ref);
               /* perms reftbl ... ref */
         mrp_gettable(upi->L, 2);
               /* perms reftbl ... obj? */
         mrp_assert(!mrp_isnil(upi->L, -1));
      }
               /* perms reftbl ... obj/nil */
   }
               /* perms reftbl ... obj/nil */
   mrp_assert(mrp_gettop(upi->L) == stacksize + 1);
   //mrp_setgcthreshold(upi->L, 0);
   //mrp_setgcthreshold(upi->L, 0);
   firstTime = stacksize; // 抑制gcc编译时的set but not used警告
}

void mr_store_unpersist(mrp_State *L, mrp_Chunkreader reader, void *ud)
{
   /* We use the graciously provided ZIO (what the heck does the Z stand
    * for?) library so that we don't have to deal with the reader directly.
    * Letting the reader function decide how much data to return can be
    * very unpleasant.
    */
   UnpersistInfo upi;
   upi.L = L;
#ifdef PLUTO_DEBUG
   upi.level = 0;
#endif

   mr_Z_init(&upi.zio, reader, ud, "");

               /* perms */
   mrp_newtable(L);
               /* perms reftbl */
   unpersist(&upi);
               /* perms reftbl rootobj */
   mrp_replace(L, 2);
               /* perms rootobj  */
}


const char *mr_str_bufreader(mrp_State *L, void *ud, size_t *sz) {
   LoadInfo *li = (LoadInfo *)ud;
   if(li->size == 0) {
      return NULL;
   }
   *sz = li->size;
   li->size = 0;
   return li->buf;
}

int unpersist_l(mrp_State *L)
{
   LoadInfo li;
               /* perms? str? ...? */
   mrp_settop(L, 2);
               /* perms? str? */
   li.buf = mr_L_checklstring(L, 2, &li.size);
               /* perms? str */
   mrp_pop(L, 1);
   /* It is conceivable that the buffer might now be collectable,
    * which would cause problems in the reader. I can't think of
    * any situation where there would be no other reference to the
    * buffer, so for now I'll leave it alone, but this is a potential
    * bug. */
               /* perms? */
   mr_L_checktype(L, 1, MRP_TTABLE);
               /* perms */
   mr_store_unpersist(L, mr_str_bufreader, &li);
               /* perms rootobj */
   return 1;
}

static mr_L_reg pluto_reg[3];

void mr_pluto_init() {
    pluto_reg[0].name = "store", pluto_reg[0].func = persist_l;
    pluto_reg[1].name = "load", pluto_reg[1].func = unpersist_l;
    pluto_reg[2].name = NULL, pluto_reg[2].func = NULL;
}

int mr_store_open(mrp_State *L) {
   mr_L_openlib(L, "_store", pluto_reg, 0);
   return 1;
}
