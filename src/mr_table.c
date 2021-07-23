

//#define ltable_c


#include "./h/mr_debug.h"
#include "./h/mr_do.h"
#include "./h/mr_gc.h"
#include "./h/mr_mem.h"
#include "./h/mr_object.h"
#include "./h/mr_state.h"
#include "./h/mr_table.h"


/*
** max size of array part is 2^MAXBITS
*/
#if BITS_INT > 26
#define MAXBITS		24
#else
#define MAXBITS		(BITS_INT-2)
#endif

/* check whether `x' < 2^MAXBITS */
#define toobig(x)	((((x)-1) >> MAXBITS) != 0)


/* function to convert a mrp_Number to int (with any rounding method) */
#ifndef mrp_number2int
#define mrp_number2int(i,n)	((i)=(int)(n))
#endif


#define hashpow2(t,n)      (gnode(t, lmod((n), sizenode(t))))
  
#define hashstr(t,str)  hashpow2(t, (str)->tsv.hash)
#define hashboolean(t,p)        hashpow2(t, p)


/*
** for some types, it is better to avoid modulus by power of 2, as
** they tend to have many 2 factors.
*/
#define hashmod(t,n)	(gnode(t, ((n) % ((sizenode(t)-1)|1))))


#define hashpointer(t,p)	hashmod(t, IntPoint(p))


/*
** number of ints inside a mrp_Number
*/
#define numints		cast(int, sizeof(mrp_Number)/sizeof(int))


/*
** hash for mrp_Numbers
*/
static Node *hashnum (const Table *t, mrp_Number n) {
  unsigned int a[numints];
  int i;
  n += 1;  /* normalize number (avoid -0) */
  mrp_assert(sizeof(a) <= sizeof(n));
  MEMCPY(a, &n, sizeof(a));//ouli brew
  for (i = 1; i < numints; i++) a[0] += a[i];
  return hashmod(t, cast(lu_hash, a[0]));
}



/*
** returns the `main' position of an element in a table (that is, the index
** of its hash value)
*/
Node *mr_H_mainposition (const Table *t, const TObject *key) {
  switch (ttype(key)) {
    case MRP_TNUMBER:
      return hashnum(t, nvalue(key));
    case MRP_TSTRING:
      return hashstr(t, tsvalue(key));
    case MRP_TBOOLEAN:
      return hashboolean(t, bvalue(key));
    case MRP_TLIGHTUSERDATA:
      return hashpointer(t, pvalue(key));
    default:
      return hashpointer(t, gcvalue(key));
  }
}


/*
** returns the index for `key' if `key' is an appropriate key to live in
** the array part of the table, -1 otherwise.
*/
static int arrayindex (const TObject *key) {
  if (ttisnumber(key)) {
    int k;
    mrp_number2int(k, (nvalue(key)));
    if (cast(mrp_Number, k) == nvalue(key) && k >= 1 && !toobig(k))
      return k;
  }
  return -1;  /* `key' did not match some condition */
}


/*
** returns the index of a `key' for table traversals. First goes all
** elements in the array part, then elements in the hash part. The
** beginning and end of a traversal are signalled by -1.
*/
static int mr_H_index (mrp_State *L, Table *t, StkId key) {
  int i;
  if (ttisnil(key)) return -1;  /* first iteration */
  i = arrayindex(key);
  if (0 <= i && i <= t->sizearray) {  /* is `key' inside array part? */
    return i-1;  /* yes; that's the index (corrected to C) */
  }
  else {
    const TObject *v = mr_H_get(t, key);
    if (v == &mr_O_nilobject)
      mr_G_runerror(L, "key err: 2021"); //invalid key for `next'
    i = cast(int, (cast(const lu_byte *, v) -
                   cast(const lu_byte *, gval(gnode(t, 0)))) / sizeof(Node));
    return i + t->sizearray;  /* hash elements are numbered after array ones */
  }
}


int mr_H_next (mrp_State *L, Table *t, StkId key) {
  int i = mr_H_index(L, t, key);  /* find original element */
  for (i++; i < t->sizearray; i++) {  /* try first array part */
    if (!ttisnil(&t->array[i])) {  /* a non-nil value? */
      setnvalue(key, cast(mrp_Number, i+1));
      setobj2s(key+1, &t->array[i]);
      return 1;
    }
  }
  for (i -= t->sizearray; i < sizenode(t); i++) {  /* then hash part */
    if (!ttisnil(gval(gnode(t, i)))) {  /* a non-nil value? */
      setobj2s(key, gkey(gnode(t, i)));
      setobj2s(key+1, gval(gnode(t, i)));
      return 1;
    }
  }
  return 0;  /* no more elements */
}


/*
** {=============================================================
** Rehash
** ==============================================================
*/


static void computesizes  (int nums[], int ntotal, int *narray, int *nhash) {
  int i;
  int a = nums[0];  /* number of elements smaller than 2^i */
  int na = a;  /* number of elements to go to array part */
  int n = (na == 0) ? -1 : 0;  /* (log of) optimal size for array part */
  for (i = 1; a < *narray && *narray >= twoto(i-1); i++) {
    if (nums[i] > 0) {
      a += nums[i];
      if (a >= twoto(i-1)) {  /* more than half elements in use? */
        n = i;
        na = a;
      }
    }
  }
  mrp_assert(na <= *narray && *narray <= ntotal);
  *nhash = ntotal - na;
  *narray = (n == -1) ? 0 : twoto(n);
  mrp_assert(na <= *narray && na >= *narray/2);
}


static void numuse (const Table *t, int *narray, int *nhash) {
  int nums[MAXBITS+1];
  int i, lg;
  int totaluse = 0;
  /* count elements in array part */
  for (i=0, lg=0; lg<=MAXBITS; lg++) {  /* for each slice [2^(lg-1) to 2^lg) */
    int ttlg = twoto(lg);  /* 2^lg */
    if (ttlg > t->sizearray) {
      ttlg = t->sizearray;
      if (i >= ttlg) break;
    }
    nums[lg] = 0;
    for (; i<ttlg; i++) {
      if (!ttisnil(&t->array[i])) {
        nums[lg]++;
        totaluse++;
      }
    }
  }
  for (; lg<=MAXBITS; lg++) nums[lg] = 0;  /* reset other counts */
  *narray = totaluse;  /* all previous uses were in array part */
  /* count elements in hash part */
  i = sizenode(t);
  while (i--) {
    Node *n = &t->node[i];
    if (!ttisnil(gval(n))) {
      int k = arrayindex(gkey(n));
      if (k >= 0) {  /* is `key' an appropriate array index? */
        nums[mr_O_log2(k-1)+1]++;  /* count as such */
        (*narray)++;
      }
      totaluse++;
    }
  }
  computesizes(nums, totaluse, narray, nhash);
}


static void setarrayvector (mrp_State *L, Table *t, int size) {
  int i;
  mr_M_reallocvector(L, t->array, t->sizearray, size, TObject);
  for (i=t->sizearray; i<size; i++)
     setnilvalue(&t->array[i]);
  t->sizearray = size;
}


static void setnodevector (mrp_State *L, Table *t, int lsize) {
  int i;
  int size = twoto(lsize);
  if (lsize > MAXBITS)
    mr_G_runerror(L, "table err:2013");  //key overflow
  if (lsize == 0) {  /* no elements to hash part? */
    t->node = G(L)->dummynode;  /* use common `dummynode' */
    mrp_assert(ttisnil(gkey(t->node)));  /* assert invariants: */
    mrp_assert(ttisnil(gval(t->node)));
    mrp_assert(t->node->next == NULL);  /* (`dummynode' must be empty) */
  }
  else {
    t->node = mr_M_newvector(L, size, Node);
    for (i=0; i<size; i++) {
      t->node[i].next = NULL;
      setnilvalue(gkey(gnode(t, i)));
      setnilvalue(gval(gnode(t, i)));
    }
  }
  t->lsizenode = cast(lu_byte, lsize);
  t->firstfree = gnode(t, size-1);  /* first free position to be used */
}


static void resize (mrp_State *L, Table *t, int nasize, int nhsize) {
  int i;
  int oldasize = t->sizearray;
  int oldhsize = t->lsizenode;
  Node *nold;
  Node temp[1];
  if (oldhsize)
    nold = t->node;  /* save old hash ... */
  else {  /* old hash is `dummynode' */
    mrp_assert(t->node == G(L)->dummynode);
    temp[0] = t->node[0];  /* copy it to `temp' */
    nold = temp;
    setnilvalue(gkey(G(L)->dummynode));  /* restate invariant */
    setnilvalue(gval(G(L)->dummynode));
    mrp_assert(G(L)->dummynode->next == NULL);
  }
  if (nasize > oldasize)  /* array part must grow? */
    setarrayvector(L, t, nasize);
  /* create new hash part with appropriate size */
  setnodevector(L, t, nhsize);  
  /* re-insert elements */
  if (nasize < oldasize) {  /* array part must shrink? */
    t->sizearray = nasize;
    /* re-insert elements from vanishing slice */
    for (i=nasize; i<oldasize; i++) {
      if (!ttisnil(&t->array[i]))
        setobjt2t(mr_H_setnum(L, t, i+1), &t->array[i]);
    }
    /* shrink array */
    mr_M_reallocvector(L, t->array, oldasize, nasize, TObject);
  }
  /* re-insert elements in hash part */
  for (i = twoto(oldhsize) - 1; i >= 0; i--) {
    Node *old = nold+i;
    if (!ttisnil(gval(old)))
      setobjt2t(mr_H_set(L, t, gkey(old)), gval(old));
  }
  if (oldhsize)
    mr_M_freearray(L, nold, twoto(oldhsize), Node);  /* free old array */
}


static void rehash (mrp_State *L, Table *t) {
  int nasize, nhsize;
  numuse(t, &nasize, &nhsize);  /* compute new sizes for array and hash parts */
  resize(L, t, nasize, mr_O_log2(nhsize)+1);
}



/*
** }=============================================================
*/


Table *mr_H_new (mrp_State *L, int narray, int lnhash) {
  Table *t = mr_M_new(L, Table);
  mr_C_link(L, valtogco(t), MRP_TTABLE);
  t->metatable = hvalue(defaultmeta(L));
  t->flags = cast(lu_byte, ~0);
  /* temporary values (kept only if some malloc fails) */
  t->array = NULL;
  t->sizearray = 0;
  t->lsizenode = 0;
  t->node = NULL;
  setarrayvector(L, t, narray);
  setnodevector(L, t, lnhash);
  return t;
}


void mr_H_free (mrp_State *L, Table *t) {
  if (t->lsizenode)
    mr_M_freearray(L, t->node, sizenode(t), Node);
  mr_M_freearray(L, t->array, t->sizearray, TObject);
  mr_M_freelem(L, t);
}


#if 0
/*
** try to remove an element from a hash table; cannot move any element
** (because gc can call `remove' during a table traversal)
*/
void mr_H_remove (Table *t, Node *e) {
  Node *mp = mr_H_mainposition(t, gkey(e));
  if (e != mp) {  /* element not in its main position? */
    while (mp->next != e) mp = mp->next;  /* find previous */
    mp->next = e->next;  /* remove `e' from its list */
  }
  else {
    if (e->next != NULL) ??
  }
  mrp_assert(ttisnil(gval(node)));
  setnilvalue(gkey(e));  /* clear node `e' */
  e->next = NULL;
}
#endif


/*
** inserts a new key into a hash table; first, check whether key's main 
** position is free. If not, check whether colliding node is in its main 
** position or not: if it is not, move colliding node to an empty place and 
** put new key in its main position; otherwise (colliding node is in its main 
** position), new key goes to an empty position. 
*/
static TObject *newkey (mrp_State *L, Table *t, const TObject *key) {
  TObject *val;
  Node *mp = mr_H_mainposition(t, key);
  if (!ttisnil(gval(mp))) {  /* main position is not free? */
    Node *othern = mr_H_mainposition(t, gkey(mp));  /* `mp' of colliding node */
    Node *n = t->firstfree;  /* get a free place */
    if (othern != mp) {  /* is colliding node out of its main position? */
      /* yes; move colliding node into free position */
      while (othern->next != mp) othern = othern->next;  /* find previous */
      othern->next = n;  /* redo the chain with `n' in place of `mp' */
      *n = *mp;  /* copy colliding node into free pos. (mp->next also goes) */
      mp->next = NULL;  /* now `mp' is free */
      setnilvalue(gval(mp));
    }
    else {  /* colliding node is in its own main position */
      /* new node will go into free position */
      n->next = mp->next;  /* chain new position */
      mp->next = n;
      mp = n;
    }
  }
  setobj2t(gkey(mp), key);  /* write barrier */
  mrp_assert(ttisnil(gval(mp)));
  for (;;) {  /* correct `firstfree' */
    if (ttisnil(gkey(t->firstfree)))
      return gval(mp);  /* OK; table still has a free place */
    else if (t->firstfree == t->node) break;  /* cannot decrement from here */
    else (t->firstfree)--;
  }
  /* no more free places; must create one */
  setbvalue(gval(mp), 0);  /* avoid new key being removed */
  rehash(L, t);  /* grow table */
  val = cast(TObject *, mr_H_get(t, key));  /* get new position */
  mrp_assert(ttisboolean(val));
  setnilvalue(val);
  return val;
}


/*
** generic search function
*/
static const TObject *mr_H_getany (Table *t, const TObject *key) {
  if (ttisnil(key)) return &mr_O_nilobject;
  else {
    Node *n = mr_H_mainposition(t, key);
    do {  /* check whether `key' is somewhere in the chain */
      if (mr_O_rawequalObj(gkey(n), key)) return gval(n);  /* that's it */
      else n = n->next;
    } while (n);
    return &mr_O_nilobject;
  }
}


/*
** search function for integers
*/
const TObject *mr_H_getnum (Table *t, int key) {
  if (1 <= key && key <= t->sizearray)
    return &t->array[key-1];
  else {
    mrp_Number nk = cast(mrp_Number, key);
    Node *n = hashnum(t, nk);
    do {  /* check whether `key' is somewhere in the chain */
      if (ttisnumber(gkey(n)) && nvalue(gkey(n)) == nk)
        return gval(n);  /* that's it */
      else n = n->next;
    } while (n);
    return &mr_O_nilobject;
  }
}


/*
** search function for strings
*/
const TObject *mr_H_getstr (Table *t, TString *key) {
  Node *n = hashstr(t, key);
  do {  /* check whether `key' is somewhere in the chain */
    if (ttisstring(gkey(n)) && tsvalue(gkey(n)) == key)
      return gval(n);  /* that's it */
    else n = n->next;
  } while (n);
  return &mr_O_nilobject;
}


/*
** main search function
*/
const TObject *mr_H_get (Table *t, const TObject *key) {
  switch (ttype(key)) {
    case MRP_TSTRING: return mr_H_getstr(t, tsvalue(key));
    case MRP_TNUMBER: {
      int k;
      mrp_number2int(k, (nvalue(key)));
      if (cast(mrp_Number, k) == nvalue(key))  /* is an integer index? */
        return mr_H_getnum(t, k);  /* use specialized version */
      /* else go through */
    }
    default: return mr_H_getany(t, key);
  }
}


TObject *mr_H_set (mrp_State *L, Table *t, const TObject *key) {
  const TObject *p = mr_H_get(t, key);
  t->flags = 0;
  if (p != &mr_O_nilobject)
    return cast(TObject *, p);
  else {
    if (ttisnil(key)) mr_G_runerror(L, "key err: 2020"); //table index is nil
    else if (ttisnumber(key) && nvalue(key) != nvalue(key))
      mr_G_runerror(L, "key err: 2022"); //table index is NaN
    return newkey(L, t, key);
  }
}


TObject *mr_H_setnum (mrp_State *L, Table *t, int key) {
  const TObject *p = mr_H_getnum(t, key);
  if (p != &mr_O_nilobject)
    return cast(TObject *, p);
  else {
    TObject k;
    setnvalue(&k, cast(mrp_Number, key));
    return newkey(L, t, &k);
  }
}

