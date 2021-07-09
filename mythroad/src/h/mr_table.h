/*
** $Id: ltable.h,v 1.44 2003/03/18 12:50:04 roberto Exp $
** Lua tables (hash)
** See Copyright Notice in lua.h
*/

#ifndef mr_table_h
#define mr_table_h

#include "mr_object.h"


#define gnode(t,i)	(&(t)->node[i])
#define gkey(n)		(&(n)->i_key)
#define gval(n)		(&(n)->i_val)


const TObject *mr_H_getnum (Table *t, int key);
TObject *mr_H_setnum (mrp_State *L, Table *t, int key);
const TObject *mr_H_getstr (Table *t, TString *key);
const TObject *mr_H_get (Table *t, const TObject *key);
TObject *mr_H_set (mrp_State *L, Table *t, const TObject *key);
Table *mr_H_new (mrp_State *L, int narray, int lnhash);
void mr_H_free (mrp_State *L, Table *t);
int mr_H_next (mrp_State *L, Table *t, StkId key);

/* exported only for debugging */
Node *mr_H_mainposition (const Table *t, const TObject *key);


#endif
