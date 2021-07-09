

//#define lstring_c


#include "./h/mr_mem.h"
#include "./h/mr_object.h"
#include "./h/mr_state.h"
#include "./h/mr_string.h"



void mr_S_freeall (mrp_State *L) {
  mrp_assert(G(L)->strt.nuse==0);
  mr_M_freearray(L, G(L)->strt.hash, G(L)->strt.size, TString *);
}


void mr_S_resize (mrp_State *L, int newsize) {
  GCObject **newhash = mr_M_newvector(L, newsize, GCObject *);
  stringtable *tb = &G(L)->strt;
  int i;
  for (i=0; i<newsize; i++) newhash[i] = NULL;
  /* rehash */
  for (i=0; i<tb->size; i++) {
    GCObject *p = tb->hash[i];
    while (p) {  /* for each node in the list */
      GCObject *next = p->gch.next;  /* save next */
      lu_hash h = gcotots(p)->tsv.hash;
      int h1 = lmod(h, newsize);  /* new position */
      mrp_assert(cast(int, h%newsize) == lmod(h, newsize));
      p->gch.next = newhash[h1];  /* chain it */
      newhash[h1] = p;
      p = next;
    }
  }
  mr_M_freearray(L, tb->hash, tb->size, TString *);
  tb->size = newsize;
  tb->hash = newhash;
}


static TString *newlstr (mrp_State *L, const char *str, size_t l, lu_hash h) {
  TString *ts = cast(TString *, mr_M_malloc(L, sizestring(l)));
  stringtable *tb;
  ts->tsv.len = l;
  ts->tsv.hash = h;
  ts->tsv.marked = 0;
  ts->tsv.tt = MRP_TSTRING;
  ts->tsv.reserved = 0;
  MEMCPY(ts+1, str, l*sizeof(char));//ouli brew
  ((char *)(ts+1))[l] = '\0';  /* ending 0 */
  tb = &G(L)->strt;
  h = lmod(h, tb->size);
  ts->tsv.next = tb->hash[h];  /* chain new entry */
  tb->hash[h] = valtogco(ts);
  tb->nuse++;
  if (tb->nuse > cast(ls_nstr, tb->size) && tb->size <= MAX_INT/2)
    mr_S_resize(L, tb->size*2);  /* too crowded */
  return ts;
}


TString *mr_S_newlstr (mrp_State *L, const char *str, size_t l) {
  GCObject *o;
  lu_hash h = (lu_hash)l;  /* seed */
  size_t step = (l>>5)+1;  /* if string is too long, don't hash all its chars */
  size_t l1;
  for (l1=l; l1>=step; l1-=step)  /* compute hash */
    h = h ^ ((h<<5)+(h>>2)+(unsigned char)(str[l1-1]));
  for (o = G(L)->strt.hash[lmod(h, G(L)->strt.size)];
       o != NULL;
       o = o->gch.next) {
    TString *ts = gcotots(o);
    if (ts->tsv.len == l && (MEMCMP(str, getstr(ts), l) == 0))
      return ts;
  }
  return newlstr(L, str, l, h);  /* not found */
}


Udata *mr_S_newudata (mrp_State *L, size_t s) {
  Udata *u;
  u = cast(Udata *, mr_M_malloc(L, sizeudata(s)));
  u->uv.marked = (1<<1);  /* is not finalized */
  u->uv.tt = MRP_TUSERDATA;
  u->uv.len = s;
  u->uv.metatable = hvalue(defaultmeta(L));
  /* chain it on udata list */
  u->uv.next = G(L)->rootudata;
  G(L)->rootudata = valtogco(u);
  return u;
}

