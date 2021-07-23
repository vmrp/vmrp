/* luadec, based on luac */


#define DEBUG_PRINT


#include "StringBuffer.h"
#include "proto.h"

#include "print.h"
#include "structs.h"

#include "../include/mrporting.h"
#include "../include/mem.h"

/*
 * ------------------------------------------------------------------------- 
 */

#define GLOBAL(r) (char*)svalue(&f->k[r])
#define UPVALUE(r) (char*)getstr(F->f->upvalues[r])
#define REGISTER(r) F->R[r]
#define PRIORITY(r) (r>=MAXSTACK ? 0 : F->Rprio[r])
#define LOCAL(r) (char*)getstr(F->f->locvars[r].varname)
#define LOCAL_STARTPC(r) F->f->locvars[r].startpc
#define PENDING(r) F->Rpend[r]
#define CALL(r) F->Rcall[r]
#define IS_TABLE(r) F->Rtabl[r]
#define IS_VARIABLE(r) F->Rvar[r]
#define IS_CONSTANT(r) (r >= MAXSTACK)

#define SET_CTR(s) s->ctr
#define SET(s,y) s->values[y]
#define SET_IS_EMPTY(s) (s->ctr == 0)

#define opstr(o) ((o)==OP_EQ?"==":(o)==OP_LE?"<=":(o)==OP_LT?"<":(o)==OP_TEST?NULL:"?")
#define invopstr(o) ((o)==OP_EQ?"!=":(o)==OP_LE?">":(o)==OP_LT?">=":(o)==OP_TEST?"!":"?")

#define IsMain(f)	(f->lineDefined==0)
#define fb2int(x)	(((x) & 7) << ((x) >> 3))

#define SET_ERROR(e)    error = e; errorCode = __LINE__; if (debug) { mr_printf("DECOMPILER ERROR: %s\n", e); while(1); }

static int debug;

static char* error;
static int errorCode;

Statement *NewStatement(char *code, int line, int indent) {
   Statement *self = mr_mallocExt0(sizeof(Statement));
   cast(ListItem*, self)->next = NULL;
   self->code = code;
   self->line = line;
   self->indent = indent;
   return self;
}

void DeleteStatement(Statement * self, void* dummy) {
   mr_freeExt(self->code);
}

void PrintStatement(Statement * self, void* F_) {
   int i;
   Function* F = cast(Function*, F_);
   
   for (i = 0; i < self->indent; i++) {
      StringBuffer_add(F->decompiledCode, "   ");
   }
   StringBuffer_addPrintf(F->decompiledCode, "%s\n", self->code);
}

LogicExp* MakeExpNode(BoolOp* boolOp) {
   LogicExp* node = cast(LogicExp*, mr_mallocExt0(sizeof(LogicExp)));
   node->parent = NULL;
   node->subexp = NULL;
   node->next = NULL;
   node->prev = NULL;
   node->op1 = boolOp->op1;
   node->op2 = boolOp->op2;
   node->op = boolOp->op;
   node->dest = boolOp->dest;
   node->neg = boolOp->neg;
   node->is_chain = 0;
   return node;
}

LogicExp* MakeExpChain(int dest) {
   LogicExp* node = cast(LogicExp*, mr_mallocExt0(sizeof(LogicExp)));
   node->parent = NULL;
   node->subexp = NULL;
   node->next = NULL;
   node->prev = NULL;
   node->dest = dest;
   node->is_chain = 1;
   return node;
}

StringBuffer* PrintLogicItem(StringBuffer* str, LogicExp* exp, int inv, int rev) {
   if (exp->subexp) {
      StringBuffer_addChar(str, '(');
      str = PrintLogicExp(str, exp->dest, exp->subexp, inv, rev);
      StringBuffer_addChar(str, ')');
   } else {
      char *op;
      int cond = exp->neg;
      if (inv) cond = !cond;
      if (rev) cond = !cond;
      if (cond)
         op = invopstr(exp->op);
      else
         op = opstr(exp->op);
      if (exp->op != OP_TEST) {
         StringBuffer_addPrintf(str, "%s %s %s", exp->op1, op, exp->op2);
      } else {
         if (op) 
            StringBuffer_addPrintf(str, "%s %s", op, exp->op2);
         else 
            StringBuffer_addPrintf(str, "%s", exp->op2);
      }
   }
   return str;
}

StringBuffer* PrintLogicExp(StringBuffer* str, int dest, LogicExp* exp, int inv_, int rev) {
   int inv = inv_;
   if (!str)
      str = StringBuffer_new(NULL);
   while (exp->next) {
      char* op;
      int cond = exp->dest > dest;
      inv = cond ? inv_ : !inv_;
      str = PrintLogicItem(str, exp, inv, rev);
      exp = exp->next;
      if (inv_) cond = !cond;
      if (rev) cond = !cond;
      op = cond ? "&&" : "||";
      StringBuffer_addPrintf(str, " %s ", op);
   }
   return PrintLogicItem(str, exp, inv_, rev);
}

void TieAsNext(LogicExp* curr, LogicExp* item) {
   curr->next = item;
   item->prev = curr;
   item->parent = curr->parent;
}

void Untie(LogicExp* curr, int* thenaddr) {
   LogicExp* previous = curr->prev;
   if (previous)
      previous->next = NULL;
   curr->prev = NULL;
   curr->parent = NULL;
}


void TieAsSubExp(LogicExp* parent, LogicExp* item) {
   parent->subexp = item;
   while (item) {
      item->parent = parent;
      item = item->next;
   }
}

LogicExp* MakeBoolean(Function * F, int* endif, int* thenaddr)
{
   int i;
   int firstaddr, elseaddr, last, realLast;
   LogicExp *curr, *first;
   int dest;

   if (endif)
      *endif = 0;
      
   if (F->nextBool == 0) {
      SET_ERROR("Attempted to build a boolean expression without a pending context");
      return NULL;
   }
   
   realLast = F->nextBool - 1;
   last = realLast;
   firstaddr = F->bools[0]->pc + 2;
   *thenaddr = F->bools[last]->pc + 2;
   elseaddr = F->bools[last]->dest;

   for (i = realLast; i >= 0; i--) {
      int dest = F->bools[i]->dest;
      if ((elseaddr > *thenaddr) &&
         ( F->bools[i]->op == OP_TEST ? (dest > elseaddr+1) :
                                        (dest > elseaddr))) {
         last = i;
         *thenaddr = F->bools[i]->pc + 2;
         elseaddr = dest;
      }
   }

   {
      int tmpLast = last;
      for (i = 0; i < tmpLast; i++) {
         int dest = F->bools[i]->dest;
         if (elseaddr > firstaddr) {
            if (dest < firstaddr) {
               last = i;
               *thenaddr = F->bools[i]->pc + 2;
               elseaddr = dest;
            }
         } else {
            if (dest == firstaddr) {
               last = i;
               *thenaddr = F->bools[i]->pc + 2;
               elseaddr = dest;
            } else {
               break;
            }
         }
      }
   }

   dest = F->bools[0]->dest;
   curr = MakeExpNode(F->bools[0]);

   if (dest > firstaddr && dest <= *thenaddr) {
      first = MakeExpChain(dest);
      TieAsSubExp(first, curr);
   } else {
      first = curr;
      if (endif)
         *endif = dest;
   }

if (debug) {
mr_printf("\n");
   for (i = 0; i <= last; i++) {
      BoolOp* op = F->bools[i];
      if (debug) {
         mr_printf("Exps(%d): at %d\tdest %d\tneg %d\t(%s %s %s) cpd %d \n", i,
         op->pc, op->dest, op->neg, op->op1, opstr(op->op), op->op2, curr->parent ? curr->parent->dest : -1);
      }
   }
mr_printf("\n");
}

   for (i = 1; i <= last; i++) {
      BoolOp* op = F->bools[i];
      int at = op->pc;
      int dest = op->dest;

      LogicExp* exp = MakeExpNode(op);
      if (dest < firstaddr) {
         /* jump to loop in a while */
         TieAsNext(curr, exp);
         curr = exp;
         if (endif)
            *endif = dest;
      } else if (dest > *thenaddr) {
         /* jump to "else" */
         TieAsNext(curr, exp);
         curr = exp;
         if (endif) {
            if (op->op != OP_TEST) {
               if (*endif != 0 && *endif != dest) {
                  SET_ERROR("unhandled construct in 'if'");
                  return NULL;
               }
            }
            *endif = dest;
         }
      } else if (dest == curr->dest) {
         /* within current chain */
         TieAsNext(curr, exp);
         curr = exp;
      } else if (dest > curr->dest) {
         if (curr->parent == NULL || dest < curr->parent->dest) {
            /* creating a new level */
            LogicExp* subexp = MakeExpChain(dest);
            // LogicExp* savecurr;
            TieAsNext(curr, exp);
            curr = exp;
            // savecurr = curr;
            if (curr->parent == NULL) {
               TieAsSubExp(subexp, first);
               first = subexp;
            }
         } else if (dest > curr->parent->dest) {
            /* start a new chain */
            LogicExp* prevParent;
	    LogicExp* chain;
            TieAsNext(curr, exp);
            curr = curr->parent;
            if (!curr->is_chain) {
               SET_ERROR("unhandled construct in 'if'");
               return NULL;
            };
            prevParent = curr->parent;
            chain = MakeExpChain(dest);
            Untie(curr, thenaddr);
            if (prevParent)
               if (prevParent->is_chain)
                  prevParent = prevParent->subexp;
            TieAsSubExp(chain, curr);

            curr->parent = prevParent;
            if (prevParent == NULL) {
               first = chain;
            } else {
               // todo
               TieAsNext(prevParent, chain);
            }
         }
      } else if (dest > firstaddr && dest < curr->dest) {
         /* start a new chain */
         LogicExp* subexp = MakeExpChain(dest);
         TieAsSubExp(subexp, exp);
         TieAsNext(curr, subexp);
         curr = exp;
      } else {
         SET_ERROR("unhandled construct in 'if'");
         return NULL;
      }

      if (curr->parent && at+3 > curr->parent->dest) {
         curr->parent->dest = curr->dest;
         if (i < last) {
            LogicExp* chain = MakeExpChain(curr->dest);
            TieAsSubExp(chain, first);
            first = chain;
         }
         curr = curr->parent;
      }
   }
   if (first->is_chain)
      first = first->subexp;
   for (i = last+1; i < F->nextBool; i++)
      F->bools[i-last-1] = F->bools[i];
   if (!F->bools[0])
      F->bools[0] = mr_mallocExt0(sizeof(BoolOp));
   F->nextBool -= last + 1;
   if (endif)
      if (*endif == 0) {
         *endif = *thenaddr;
      }
   return first;
}

char* WriteBoolean(LogicExp* exp, int* thenaddr, int* endif, int test) {
   char* result;
   StringBuffer* str;

   str = PrintLogicExp(NULL, *thenaddr, exp, 0, test);

   if (test && endif && *endif == 0) {
      SET_ERROR("Unhandled construct in boolean test");
      return NULL;
   }

   result = StringBuffer_getBuffer(str);
   StringBuffer_delete(str);
   return result;
}

void FlushElse(Function* F);

char* OutputBoolean(Function* F, int* endif, int test) {
   int thenaddr;
   char* result;
   LogicExp* exp;

   FlushElse(F);
   if (error) return NULL;
   exp = MakeBoolean(F, endif, &thenaddr);
   if (error) return NULL;
   result = WriteBoolean(exp, &thenaddr, endif, test);
   if (error) return NULL;
   return result;
}

void StoreEndifAddr(Function * F, int addr) {
   Endif* at = F->nextEndif;
   Endif* prev = NULL;
   Endif* newEndif = mr_mallocExt0(sizeof(Endif));
   newEndif->addr = addr;
   while (at && at->addr < addr) {
      prev = at;
      at = at->next;
   }
   if (!prev) {
      newEndif->next = F->nextEndif;
      F->nextEndif = newEndif;
   } else {
      newEndif->next = at;
      prev->next = newEndif;
   }
   if (debug) {
      mr_printf("Stored at endif list: ");
      for (at = F->nextEndif; at != NULL; at = at->next) {
         if (at == newEndif)
            mr_printf("<%d> ", at->addr);
         else
            mr_printf("%d ", at->addr);
      }
      mr_printf("\n");
   }
}

int PeekEndifAddr(Function* F, int addr) {
   Endif* at = F->nextEndif;
   while (at) {
      if (at->addr == addr)
         return 1;
      else if (at->addr > addr)
         break;
      at = at->next;
   }
   return 0;
}

int GetEndifAddr(Function* F, int addr) {
   Endif* at = F->nextEndif;
   Endif* prev = NULL;
   while (at) {
      if (at->addr == addr) {
         if (prev)
            prev->next = at->next;
         else
            F->nextEndif = at->next;
         mr_freeExt(at);
         return 1;
      } else if (at->addr > addr)
         break;
      prev = at;
      at = at->next;
   }
   return 0;
}

void BackpatchStatement(Function * F, char * code, int line) {
   ListItem *walk = F->statements.head;
   while (walk) {
      Statement* stmt = (Statement*) walk;
      walk = walk->next;
      if (stmt->backpatch && stmt->line == line) {
         mr_freeExt(stmt->code);
         stmt->code = code;
         return;
      }
   }
   SET_ERROR("Confused while interpreting a jump as a 'while'");
}

void RawAddStatement(Function * F, StringBuffer * str)
{
   char *copy;
   Statement* stmt;
   copy = StringBuffer_getCopy(str);
   if (F->released_local) {
      int i = 0;
      int lpc = F->released_local;
      char* scopeclose[4];
      scopeclose[0] = "end";
      scopeclose[0] = "else";
      scopeclose[0] = "until";
      scopeclose[0] = NULL;

      F->released_local = 0;
      for (i = 0; scopeclose[i]; i++)
         if (strstr2(copy, scopeclose[i]) == copy)
            break;
      if (!scopeclose[i]) {
         int added = 0;
         Statement* stmt = cast(Statement*, F->statements.head);
         Statement* prev = NULL;
         Statement* newst; 
         while (stmt) {
            if (!added) {
               if (stmt->line >= lpc) {
                  Statement *newst = NewStatement(strdup2("do"), lpc, stmt->indent);
                  if (prev) {
                     prev->super.next = cast(ListItem*, newst);
                     newst->super.next = cast(ListItem*, stmt);
                  } else {
                     F->statements.head = cast(ListItem*, newst);
                     newst->super.next = cast(ListItem*, stmt);
                  }
                  added = 1;
                  stmt->indent++;
               }
            } else {
               stmt->indent++;
            }
            prev = stmt;
            stmt = cast(Statement*, stmt->super.next);
         }
         newst = NewStatement(strdup2("end"), F->pc, F->indent);
         AddToList(&(F->statements), cast(ListItem*, newst));
      }
   }
   stmt = NewStatement(copy, F->pc, F->indent);
   AddToList(&(F->statements), cast(ListItem*, stmt));
   F->lastLine = F->pc;
}

void FlushBoolean(Function * F) {
   FlushElse(F);
   while (F->nextBool > 0) {
      char* test;
      int endif;
      int thenaddr;
      StringBuffer* str = StringBuffer_new(NULL);
      LogicExp* exp = MakeBoolean(F, &endif, &thenaddr);
      if (error) return;
      if (endif < F->pc - 1) {
         test = WriteBoolean(exp, &thenaddr, &endif, 1);
         if (error) return;
         StringBuffer_printf(str, "while %s do", test);
         /* verify this '- 2' */
         BackpatchStatement(F, StringBuffer_getBuffer(str), endif - 2);
         if (error) return;
         F->indent--;
         StringBuffer_add(str, "end");
         RawAddStatement(F, str);
      } else {
         test = WriteBoolean(exp, &thenaddr, &endif, 0);
         if (error) return;
         StoreEndifAddr(F, endif);
         StringBuffer_addPrintf(str, "if %s then", test);
         F->elseWritten = 0;
         RawAddStatement(F, str);
         F->indent++;
      }
      StringBuffer_delete(str);
   }
   F->testpending = 0;
}

void AddStatement(Function * F, StringBuffer * str)
{
   FlushBoolean(F);
   if (error) return;
   RawAddStatement(F, str);
}

void MarkBackpatch(Function* F) {
   Statement* stmt = (Statement*) LastItem(&(F->statements));
   stmt->backpatch = 1;
}

void FlushElse(Function* F) {
   if (F->elsePending > 0) {
      StringBuffer* str = StringBuffer_new(NULL);
      int fpc = F->bools[0]->pc;
      /* Should elseStart be a stack? */
      if (F->nextBool > 0 && (fpc == F->elseStart || fpc-1 == F->elseStart)) {
         char* test;
         int endif;
         int thenaddr;
         LogicExp* exp;
         exp = MakeBoolean(F, &endif, &thenaddr);
         if (error) return;
         test = WriteBoolean(exp, &thenaddr, &endif, 0);
         if (error) return;
         StoreEndifAddr(F, endif);
         StringBuffer_addPrintf(str, "elif %s then", test);
         F->elseWritten = 0;
         RawAddStatement(F, str);
         F->indent++;
      } else {
         StringBuffer_printf(str, "else");
         RawAddStatement(F, str);
         /* this test circumvents jump-to-jump optimization at
            the end of if blocks */
         if (!PeekEndifAddr(F, F->pc + 3))
            StoreEndifAddr(F, F->elsePending);
         F->indent++;
         F->elseWritten = 1;
      }
      F->elsePending = 0;
      F->elseStart = 0;
      StringBuffer_delete(str);
   }
}

/*
 * ------------------------------------------------------------------------- 
 */

DecTableItem *NewTableItem(char *value, int num, char *key)
{
   DecTableItem *self = mr_mallocExt0(sizeof(DecTableItem));
   ((ListItem *) self)->next = NULL;
   self->value = strdup2(value);
   self->numeric = num;
   if (key)
      self->key = strdup2(key);
   else
      self->key = NULL;
   return self;
}

/*
 * ------------------------------------------------------------------------- 
 */

void Assign(Function * F, char* dest, char* src, int reg, int prio, int mayTest)
{
   char* nsrc = src ? strdup2(src) : NULL;

   if (PENDING(reg)) {
      SET_ERROR("overwrote pending register!");
      return;
   }

   if (reg != -1) {
      PENDING(reg) = 1;
      CALL(reg) = 0;
      F->Rprio[reg] = prio;
   }

if (debug) { mr_printf("SET_CTR(Tpend) = %d \n", SET_CTR(F->tpend)); }

   if (reg != -1 && F->testpending == reg+1 && mayTest && F->testjump == F->pc+2) {
      int endif;
      StringBuffer* str = StringBuffer_new(NULL);
      char* test = OutputBoolean(F, &endif, 1);
      if (error) {
         return;
      }
      if (endif >= F->pc) {
         StringBuffer_printf(str, "%s || %s", test, src);
         mr_freeExt(nsrc);
         nsrc = StringBuffer_getBuffer(str);
         mr_freeExt(test);
         StringBuffer_delete(str);
         F->testpending = 0;
         F->Rprio[reg] = 8;
      }
   }
   F->testjump = 0;

   if (reg != -1 && !IS_VARIABLE(reg)) {
      if (REGISTER(reg))
         mr_freeExt(REGISTER(reg));
      REGISTER(reg) = nsrc;
      AddToSet(F->tpend, reg);
   } else {
      char* ndest = strdup2(dest);
      AddToVarStack(F->vpend, ndest, nsrc, reg);
   }
}

int MatchTable(DecTable * tbl, int *name)
{
   return tbl->reg == *name;
}

void DeleteTable(DecTable * tbl)
{
   /*
    * TODO: delete values from table 
    */
   mr_freeExt(tbl);
}

void CloseTable(Function * F, int r)
{
   DecTable *tbl = (DecTable *) PopFromList(&(F->tables));
   if (tbl->reg != r) {
      SET_ERROR("Unhandled construct in table");
      return;
   }
   DeleteTable(tbl);
   F->Rtabl[r] = 0;
}

char *PrintTable(Function * F, int r, int returnCopy)
{
   char *result = NULL;
   StringBuffer *str = StringBuffer_new("{");
   DecTable *tbl =
       (DecTable *) FindInList(&(F->tables), (ListItemCmpFn) MatchTable,
                               &r);
   int numerics = 0;
   DecTableItem *item = (DecTableItem *) tbl->numeric.head;
   if (item) {
      StringBuffer_add(str, item->value);
      item = (DecTableItem *) item->super.next;
      numerics = 1;
      while (item) {
         StringBuffer_add(str, ", ");
         StringBuffer_add(str, item->value);
         item = (DecTableItem *) item->super.next;
      }
   }
   item = (DecTableItem *) tbl->keyed.head;
   if (item) {
      int first;
      if (numerics)
         StringBuffer_add(str, "; ");
      first = 1;
      while (item) {
         char* key = item->key;
         if (first)
            first = 0;
         else
            StringBuffer_add(str, ", ");
         if (key[0] == '\"') {
            char* last = strrchr2(key, '\"');
            *last = '\0';
            key++;
         }
         StringBuffer_addPrintf(str, "%s = %s", key, item->value);
         item = (DecTableItem *) item->super.next;
      }
   }
   StringBuffer_addChar(str, '}');
   PENDING(r) = 0;
   Assign(F, REGISTER(r), StringBuffer_getRef(str), r, 0, 0);
   if (error) {
      return NULL;
   }
   if (returnCopy)
      result = StringBuffer_getCopy(str);
   StringBuffer_delete(str);
   CloseTable(F, r);
   if (error) return NULL;
   return result;
}


DecTable *NewTable(int r, Function * F, int b, int c)
{
   DecTable *self = mr_mallocExt0(sizeof(DecTable));
   ((ListItem *) self)->next = NULL;
   InitList(&(self->numeric));
   InitList(&(self->keyed));
   self->reg = r;
   self->topNumeric = 0;
   self->F = F;
   self->arraySize = fb2int(b);
   self->keyedSize = 1<<c;
   PENDING(r) = 1;
   return self;
}

void AddToTable(Function* F, DecTable * tbl, char *value, char *key)
{
   DecTableItem *item;
   List *type;
   int index;
   if (key == NULL) {
      type = &(tbl->numeric);
      index = tbl->topNumeric;
      tbl->topNumeric++;
   } else {
      type = &(tbl->keyed);
      tbl->used++;
      index = 0;
   }
   item = NewTableItem(value, index, key);
   AddToList(type, (ListItem *) item);
   // FIXME: should work with arrays, too
   if (tbl->keyedSize == tbl->used && tbl->arraySize == 0) {
      PrintTable(F, tbl->reg, 0);
      if (error)
         return;
   }
}

void StartTable(Function * F, int r, int b, int c)
{
   DecTable *tbl = NewTable(r, F, b, c);
   AddToList(&(F->tables), (ListItem *) tbl);
   F->Rtabl[r] = 1;
   F->Rtabl[r] = 1;
   if (b == 0 && c == 0) {
      PrintTable(F, r, 1);
      if (error)
         return;
   }
}

void SetList(Function * F, int a, int bc)
{
   int i;
   DecTable *tbl = (DecTable *) LastItem(&(F->tables));
   if (tbl->reg != a) {
      SET_ERROR("Unhandled construct in list");
      return;
   }
   for (i = 1; i <= bc+1; i++) {
      char* rstr = GetR(F, a + i);
      if (error)
         return;
      AddToTable(F, tbl, rstr, NULL);
      if (error)
         return;
   }
   PrintTable(F, tbl->reg, 0);
   if (error)
      return;
}

void UnsetPending(Function * F, int r)
{
   if (!IS_VARIABLE(r)) {
      if (!PENDING(r) && !CALL(r)) {
         SET_ERROR("Confused about usage of registers");
         return;
      }
      PENDING(r) = 0;
      RemoveFromSet(F->tpend, r);
   }
}

int SetTable(Function * F, int a, char *bstr, char *cstr)
{
   DecTable *tbl = (DecTable *) LastItem(&(F->tables));
   if ((!tbl) || (tbl->reg != a)) {
      /*
       * SetTable is not being applied to the table being generated. (This
       * will probably need a more strict check)
       */
      UnsetPending(F, a);
      if (error) return 0;
      return 0;
   }
   AddToTable(F, tbl, cstr, bstr);
   if (error) return 0;
   return 1;
}

/*
 * ------------------------------------------------------------------------- 
 */

Function *NewFunction(const Proto * f)
{
   Function *self;
   /*
    * mr_mallocExt0, to ensure all parameters are 0/NULL 
    */
   self = mr_mallocExt0(sizeof(Function));
   InitList(&(self->statements));
   self->f = f;
   self->vpend = mr_mallocExt0(sizeof(VarStack));
   self->tpend = mr_mallocExt0(sizeof(IntSet));
   self->whiles = mr_mallocExt0(sizeof(IntSet));
   self->repeats = mr_mallocExt0(sizeof(IntSet));
   self->repeats->mayRepeat = 1;
   self->untils = mr_mallocExt0(sizeof(IntSet));
   self->do_opens = mr_mallocExt0(sizeof(IntSet));
   self->do_closes = mr_mallocExt0(sizeof(IntSet));
   self->decompiledCode = StringBuffer_new(NULL);
   self->bools[0] = mr_mallocExt0(sizeof(BoolOp));
   return self;
}

void DeleteFunction(Function * self)
{
   int i;
   LoopList(&(self->statements), (ListItemFn) DeleteStatement, NULL);
   /*
    * clean up registers 
    */
   for (i = 0; i < MAXARG_A; i++) {
      if (self->R[i])
         mr_freeExt(self->R[i]);
   }
   StringBuffer_delete(self->decompiledCode);
   mr_freeExt(self->vpend);
   mr_freeExt(self->tpend);
   mr_freeExt(self->whiles);
   mr_freeExt(self->repeats);
   mr_freeExt(self->untils);
   mr_freeExt(self->do_opens);
   mr_freeExt(self->do_closes);
   mr_freeExt(self);
}

char *GetR(Function * F, int r)
{
   if (IS_TABLE(r)) {
      PrintTable(F, r, 0);
      if (error) return NULL;
   }
   UnsetPending(F, r);
   if (error) return NULL;
   return F->R[r];
}

void DeclareVariable(Function * F, const char *name, int reg)
{
   F->Rvar[reg] = 1;
   if (F->R[reg])
      mr_freeExt(F->R[reg]);
   F->R[reg] = strdup2(name);
   F->Rprio[reg] = 0;
   UnsetPending(F, reg);
   if (error) return;
}

void OutputAssignments(Function * F)
{
   int i, srcs, size;
   StringBuffer *vars;
   StringBuffer *exps;
   if (!SET_IS_EMPTY(F->tpend))
      return;
   vars = StringBuffer_new(NULL);
   exps = StringBuffer_new(NULL);
   size = SET_CTR(F->vpend);
   srcs = 0;
   for (i = 0; i < size; i++) {
      int r = F->vpend->regs[i];
      if (!(r == -1 || PENDING(r))) {
         SET_ERROR("Attempted to generate an assignment, but got confused about usage of registers");
         return;
      }

      if (i > 0)
         StringBuffer_prepend(vars, ", ");
      StringBuffer_prepend(vars, F->vpend->dests[i]);
      
      if (F->vpend->srcs[i] && (srcs > 0 || (srcs == 0 && strcmp2(F->vpend->srcs[i], "nil") != 0) || i == size-1)) {
         if (srcs > 0)
            StringBuffer_prepend(exps, ", ");
         StringBuffer_prepend(exps, F->vpend->srcs[i]);
         srcs++;
      }
      
   }

   for (i = 0; i < size; i++) {
      int r = F->vpend->regs[i];
      if (r != -1)
         PENDING(r) = 0;
      mr_freeExt(F->vpend->dests[i]);
      if (F->vpend->srcs[i])
         mr_freeExt(F->vpend->srcs[i]);
   }
   F->vpend->ctr = 0;

   if (i > 0) {
      StringBuffer_add(vars, " = ");
      StringBuffer_add(vars, StringBuffer_getRef(exps));
      AddStatement(F, vars);
      if (error)
         return;
   }
   StringBuffer_delete(vars);
   StringBuffer_delete(exps);
}

void ReleaseLocals(Function * F) {
   int i;
   for (i = 0; i < F->f->sizelocvars; i++) {
      if (F->f->locvars[i].endpc == F->pc) {
         int r;
         F->freeLocal--;
         r = F->freeLocal;
         if (!IS_VARIABLE(r)) {
            SET_ERROR("Confused about usage of registers for local variables");
            return;
         }
         F->Rvar[r] = 0;
         F->Rprio[r] = 0;
         if (!F->ignore_for_variables && !F->released_local) 
            F->released_local = F->f->locvars[i].startpc;
      }
   }
   F->ignore_for_variables = 0;
}

void DeclareLocals(Function * F)
{
   int i;
   int locals;
   int internalLocals = 0;
   StringBuffer *str;
   StringBuffer *rhs;
   char *names[MAXARG_A];
   /*
    * Those are declaration of parameters. 
    */
   if (F->pc == 0)
      return;
   str = StringBuffer_new("local ");
   rhs = StringBuffer_new(" = ");
   locals = 0;
   for (i = 0; i < F->f->sizelocvars; i++) {
      if (F->f->locvars[i].startpc == F->pc) {
         int r = F->freeLocal + locals + internalLocals;
         if (F->internal[r]) {
            names[r] = LOCAL(i);
            F->internal[r] = 0;
            internalLocals++;
            continue;
         }
         if (PENDING(r)) {
            if (locals > 0) {
               StringBuffer_add(str, ", ");
               StringBuffer_add(rhs, ", ");
            }
            StringBuffer_add(str, LOCAL(i));
            StringBuffer_add(rhs, GetR(F, r));
            if (error) return;
         } else {
            if (!(locals > 0)) {
               SET_ERROR("Confused at declaration of local variable");
               return;
            }
            StringBuffer_add(str, ", ");
            StringBuffer_add(str, LOCAL(i));
         }
         CALL(r) = 0;
         IS_VARIABLE(r) = 1;
         names[r] = LOCAL(i);
         locals++;
      }
   }
   if (locals > 0) {
      StringBuffer_add(str, StringBuffer_getRef(rhs));
      AddStatement(F, str);
      if (error) return;
   }
   StringBuffer_delete(rhs);
   StringBuffer_prune(str);
   for (i = 0; i < locals + internalLocals; i++) {
      int r = F->freeLocal + i;
      DeclareVariable(F, names[r], r);
      if (error) return;
   }
   F->freeLocal += locals + internalLocals;
}

char* PrintFunction(Function * F)
{
   char* result;
   StringBuffer_prune(F->decompiledCode);
   LoopList(&(F->statements), (ListItemFn) PrintStatement, F);
   result = StringBuffer_getBuffer(F->decompiledCode);
   return result;
}

/*
 * ------------------------------------------------------------------------- 
 */

static char *operators[20];
static int priorities[20];

void init_print(void) {
   operators[0] = " "; operators[1] = " "; operators[2] = " "; operators[3] = " "; operators[4] = " "; operators[5] = " "; operators[6] = " ";
   operators[7] = " "; operators[8] = " "; operators[9] = " "; operators[10] = " "; operators[11] = " "; operators[12] = "+"; operators[13] = "-";
   operators[14] = "*"; operators[15] = "/"; operators[16] = "^"; operators[17] = "-"; operators[18] = "! "; operators[19] = "..";

   priorities[0] = 0; priorities[1] = 0; priorities[2] = 0; priorities[3] = 0; priorities[4] = 0; priorities[5] = 0; priorities[6] = 0;
   priorities[7] = 0; priorities[8] = 0; priorities[9] = 0; priorities[10] = 0; priorities[11] = 0; priorities[12] = 4; priorities[13] = 4;
   priorities[14] = 3; priorities[15] = 3; priorities[16] = 1; priorities[17] = 2; priorities[18] = 2; priorities[19] = 5 ;
}

char *RegisterOrConstant(Function * F, int r)
{
   if (IS_CONSTANT(r)) {
      return DecompileConstant(F->f, r - MAXSTACK);
   } else {
      char *copy;
      char *reg = GetR(F, r);
      if (error)
         return NULL;
      copy = mr_mallocExt0(strlen2(reg) + 1);
      strcpy2(copy, reg);
      return copy;
   }
}

void MakeIndex(Function * F, StringBuffer * str, char* rstr, int self)
{
   int dot = 0;
   /*
    * see if index can be expressed without quotes 
    */
   if (rstr[0] == '\"') {
      if (mr_isalpha(rstr[1]) || rstr[1] == '_') {
         char *at = rstr + 1;
         dot = 1;
         while (*at != '"') {
            if (!mr_isalnum(*at) && *at != '_') {
               dot = 0;
               break;
            }
            at++;
         }
      }
   }
   if (dot) {
      rstr++;
      rstr[strlen2(rstr) - 1] = '\0';
      if (self)
         StringBuffer_addPrintf(str, ":%s", rstr);
      else
         StringBuffer_addPrintf(str, ".%s", rstr);
      rstr--;
   } else
      StringBuffer_addPrintf(str, "[%s]", rstr);
}

void FunctionHeader(Function * F) {
   int saveIndent = F->indent;
   const Proto* f = F->f;
   StringBuffer* str = StringBuffer_new(NULL);
   F->indent = 0;
   if (f->numparams > 0) {
      int i;
      StringBuffer_addPrintf(str, "(");
      for (i = 0; i < f->numparams - 1; i++)
         StringBuffer_addPrintf(str, "%s, ", LOCAL(i));
      StringBuffer_addPrintf(str, "%s", LOCAL(i));
      if (f->is_vararg)
         StringBuffer_add(str, ", ...");
      StringBuffer_addPrintf(str, ")");
      AddStatement(F, str);
      if (error)
         return;
      StringBuffer_prune(str);
   } else if (!IsMain(f)) {
      if (f->is_vararg)
         StringBuffer_add(str, "(...)");
      else
         StringBuffer_add(str, "()");
      AddStatement(F, str);
      if (error)
         return;
      StringBuffer_prune(str);
   }
   F->indent = saveIndent;
   if (!IsMain(f))
      F->indent++;
   StringBuffer_delete(str);
}

void ShowState(Function * F)
{
   int i;
   mr_printf("\n");
   mr_printf("next bool: %d\n", F->nextBool);
   mr_printf("locals(%d): ", F->freeLocal);
   for (i = 0; i < F->freeLocal; i++) {
      mr_printf("%d{%s} ", i, REGISTER(i));
   }
   mr_printf("\n");
   mr_printf("vpend(%d): ", SET_CTR(F->vpend));
   for (i = 0; i < SET_CTR(F->vpend); i++) {
      int r = F->vpend->regs[i];
      if (r != -1 && !PENDING(r)) {
         SET_ERROR("Confused about usage of registers for variables");
         return;
      }
      mr_printf("%d{%s=%s} ", r, F->vpend->dests[i], F->vpend->srcs[i]);
   }
   mr_printf("\n");
   mr_printf("tpend(%d): ", SET_CTR(F->tpend));
   for (i = 0; i < SET_CTR(F->tpend); i++) {
      int r = SET(F->tpend, i);
      mr_printf("%d{%s} ", r, REGISTER(r));
      if (!PENDING(r)) {
         SET_ERROR("Confused about usage of registers for temporaries");
         return;
      }
   }
   mr_printf("\n");
}

#define TRY(x)  x; if (error) goto errorHandler

char* ProcessCode(const Proto * f, int indent)
{
   int i = 0;

   int ignoreNext = 0;

   /*
    * State variables for the boolean operations. 
    */
   int boolpending = 0;

   Function *F;
   StringBuffer *str = StringBuffer_new(NULL);

   const Instruction *code = f->code;
   int pc, n = f->sizecode;
   int baseIndent = indent;

   char* output;

   F = NewFunction(f);
   F->indent = indent;
   F->pc = 0;
   error = NULL;

   /*
    * Function parameters are stored in registers from 0 on.  
    */
   for (i = 0; i < f->numparams; i++) {
      TRY(DeclareVariable(F, LOCAL(i), i));
   }
   F->freeLocal = f->numparams;

   TRY(FunctionHeader(F));

   if (f->is_vararg) {
      TRY(DeclareVariable(F, "arg", F->freeLocal));
      F->freeLocal++;
   }

   for (pc = n - 1; pc >= 0; pc--) {
      Instruction i = code[pc];
      OpCode o = GET_OPCODE(i);
      if (o == OP_JMP) {
         int sbc = GETARG_sBx(i);
         int dest = sbc + pc;
         if (dest < pc) {
            if (dest+2 > 0
            && GET_OPCODE(code[dest]) == OP_JMP
            && !PeekSet(F->whiles, dest)) {
               AddToSet(F->whiles, dest);
            } else if (GET_OPCODE(code[dest]) != OP_TFORPREP) {
               AddToSet(F->repeats, dest+2);
               AddToSet(F->untils, pc);
            }
         }
      } else if (o == OP_CLOSE) {
         int a = GETARG_A(i);
         AddToSet(F->do_opens, f->locvars[a].startpc);
         AddToSet(F->do_closes, f->locvars[a].endpc);
      }
   }

   for (pc = 0; pc < n; pc++) {
      Instruction i = code[pc];
      OpCode o = GET_OPCODE(i);
      int a = GETARG_A(i);
      int b = GETARG_B(i);
      int c = GETARG_C(i);
      int bc = GETARG_Bx(i);
      int sbc = GETARG_sBx(i);
      F->pc = pc;

      if (ignoreNext) {
         ignoreNext--;
         continue;
      }
      
      /*
       * Disassembler info 
       */
      if (debug) {
         mr_printf("----------------------------------------------");
         mr_printf("\t%d\t", pc + 1);
         mr_printf("%-9s\t", mr_P_opnames[o]);
         switch (getOpMode(o)) {
         case iABC:
            mr_printf( "%d %d %d", a, b, c);
            break;
         case iABx:
            mr_printf( "%d %d", a, bc);
            break;
         case iAsBx:
            mr_printf( "%d %d", a, sbc);
            break;
         }
         mr_printf( "\n");
      }

      TRY(DeclareLocals(F));
      TRY(ReleaseLocals(F));
      
      while (RemoveFromSet(F->do_opens, pc)) {
         StringBuffer_set(str, "do");
         TRY(AddStatement(F, str));
         StringBuffer_prune(str);
         F->indent++;
      }

      while (RemoveFromSet(F->do_closes, pc)) {
         StringBuffer_set(str, "end");
         F->indent--;
         TRY(AddStatement(F, str));
         StringBuffer_prune(str);
      }
      
      while (GetEndifAddr(F, pc+1)) {
         StringBuffer_set(str, "end");
         F->elseWritten = 0;
         F->elsePending = 0;
         F->indent--;
         TRY(AddStatement(F, str));
         StringBuffer_prune(str);
      }

      while (RemoveFromSet(F->repeats, F->pc+1)) {
         StringBuffer_set(str, "repeat");
         TRY(AddStatement(F, str));
         StringBuffer_prune(str);
         F->indent++;
      }

      StringBuffer_prune(str);

      switch (o) {
      case OP_MOVE:
         {
            char* bstr = NULL;
            if (a == b)
               break;
            if (CALL(b) < 2)
               bstr = GetR(F, b);
            else
               UnsetPending(F, b);
            if (error)
               goto errorHandler;
            /*
             * Copy from one register to another 
             */
            TRY(Assign(F, REGISTER(a), bstr, a, PRIORITY(b), 1));
            break;
         }
      case OP_LOADK:
         {
            /*
             * Constant. Store it in register. 
             */
            char *ctt = DecompileConstant(f, bc);
            TRY(Assign(F, REGISTER(a), ctt, a, 0, 1));
            break;
            mr_freeExt(ctt);
         }
      case OP_LOADBOOL:
         {
            if (F->nextBool == 0) {
               /*
                * assign boolean constant
                */ 
               if (PENDING(a)) {
                  // some boolean constructs overwrite pending regs :(
                  TRY(UnsetPending(F, a));
               }
               TRY(Assign(F, REGISTER(a), b ? "true" : "false", a, 0, 1));
            } else {
               /*
                * assign boolean value
                */ 
               char *test;
               TRY(test = OutputBoolean(F, NULL, 1));
               StringBuffer_printf(str, "%s", test);
               TRY(Assign(F, REGISTER(a), StringBuffer_getRef(str), a, 0, 0));
               mr_freeExt(test);
            }
            if (c)
               ignoreNext = 1;
            break;
         }
      case OP_LOADNIL:
         {
            int i;
            /*
             * Read nil into register. 
             */
            for(i = a; i <= b; i++) {
               TRY(Assign(F, REGISTER(i), "nil", i, 0, 1));
            }
            break;
         }
      case OP_GETUPVAL:
         {
            TRY(Assign(F, REGISTER(a), UPVALUE(b), a, 0, 1));
            break;
         }
      case OP_GETGLOBAL:
         {
            /*
             * Read global into register. 
             */
            TRY(Assign(F, REGISTER(a), GLOBAL(bc), a, 0, 1));
            break;
         }
      case OP_GETTABLE:
         {
            /*
             * Read table entry into register. 
             */
            char *bstr, *cstr;
            TRY(cstr = RegisterOrConstant(F, c));
            TRY(bstr = GetR(F, b));
            if (bstr[0] == '{') {
               StringBuffer_printf(str, "(%s)", bstr);
            } else {
               StringBuffer_set(str, bstr);
            }
            MakeIndex(F, str, cstr, 0);
            TRY(Assign(F, REGISTER(a), StringBuffer_getRef(str), a, 0, 0));
            mr_freeExt(cstr);
            break;
         }
      case OP_SETGLOBAL:
         {
            /*
             * Global Assignment statement. 
             */
            char *var = GLOBAL(bc);
            if (IS_TABLE(a)) {
               TRY(PrintTable(F, a, 0));
            }
            {
               char *astr;
               TRY(astr = GetR(F, a));
               TRY(Assign(F, var, astr, -1, 0, 0));
            }
            break;
         }
      case OP_SETUPVAL:
         {
            /*
             * Global Assignment statement. 
             */
            char *var = UPVALUE(bc);
            if (IS_TABLE(a)) {
               TRY(CloseTable(F, a));
            }
            {
               char *astr;
               TRY(astr = GetR(F, a));
               TRY(Assign(F, var, astr, -1, 0, 0));
            }
            break;
         }
      case OP_SETTABLE:
         {
            char *bstr, *cstr;
            int settable;
            TRY(bstr = RegisterOrConstant(F, b));
            TRY(cstr = RegisterOrConstant(F, c));
            /*
             * first try to add into a table 
             */
            TRY(settable = SetTable(F, a, bstr, cstr));
            if (!settable) {
               /*
                * if failed, just output an assignment 
                */
               StringBuffer_set(str, REGISTER(a));
               MakeIndex(F, str, bstr, 0);
               TRY(Assign(F, StringBuffer_getRef(str), cstr, -1, 0, 0));
            }
            mr_freeExt(bstr);
            mr_freeExt(cstr);
            break;
         }
      case OP_NEWTABLE:
         {
            TRY(StartTable(F, a, b, c));
            break;
         }
      case OP_SELF:
         {
            /*
             * Read table entry into register. 
             */
            char *bstr, *cstr;
            TRY(cstr = RegisterOrConstant(F, c));
            TRY(bstr = GetR(F, b));
            
            bstr = strdup2(bstr);

            TRY(Assign(F, REGISTER(a+1), bstr, a+1, PRIORITY(b), 0));

            StringBuffer_set(str, bstr);
            MakeIndex(F, str, cstr, 1);
            TRY(Assign(F, REGISTER(a), StringBuffer_getRef(str), a, 0, 0));
            mr_freeExt(bstr);
            mr_freeExt(cstr);
            break;
         }
      case OP_ADD:
      case OP_SUB:
      case OP_MUL:
      case OP_DIV:
      case OP_POW:
         {
            char *bstr, *cstr;
            char *oper = operators[o];
            int prio = priorities[o];
            int bprio = PRIORITY(b);
            int cprio = PRIORITY(c);
            TRY(bstr = RegisterOrConstant(F, b));
            TRY(cstr = RegisterOrConstant(F, c));
            // FIXME: might need to change from <= to < here
            if ((prio != 1 && bprio <= prio) || (prio == 1 && bstr[0] != '-')) {
               StringBuffer_add(str, bstr);
            } else {
               StringBuffer_addPrintf(str, "(%s)", bstr);
            }
            StringBuffer_addPrintf(str, " %s ", oper);
            // FIXME: being conservative in the use of parentheses
            if (cprio < prio) {
               StringBuffer_add(str, cstr);
            } else {
               StringBuffer_addPrintf(str, "(%s)", cstr);
            }
            TRY(Assign(F, REGISTER(a), StringBuffer_getRef(str), a, prio, 0));
            mr_freeExt(bstr);
            mr_freeExt(cstr);
            break;
         }
      case OP_UNM:
      case OP_NOT:
         {
            char *bstr;
            int prio = priorities[o];
            int bprio = PRIORITY(b);
            TRY(bstr = GetR(F, b));
            StringBuffer_add(str, operators[o]);
            if (bprio <= prio) {
               StringBuffer_add(str, bstr);
            } else {
               StringBuffer_addPrintf(str, "(%s)", bstr);
            }
            TRY(Assign(F, REGISTER(a), StringBuffer_getRef(str), a, 0, 0));
            break;
         }
      case OP_CONCAT:
         {
            int i;
            for (i = b; i <= c; i++) {
               char *istr;
               TRY(istr = GetR(F, i));
               if (PRIORITY(i) > priorities[o]) {
                  StringBuffer_addPrintf(str, "(%s)", istr);
               } else {
                  StringBuffer_add(str, istr);
               }
               if (i < c)
                  StringBuffer_add(str, " .. ");
            }
            TRY(Assign(F, REGISTER(a), StringBuffer_getRef(str), a, 0, 0));
            break;
         }
      case OP_JMP:
         {
            int dest = sbc + pc + 2;
            Instruction idest = code[dest - 1];
            if (boolpending) {
               boolpending = 0;
               F->bools[F->nextBool]->dest = dest;
               F->nextBool++;
               F->bools[F->nextBool] = mr_mallocExt0(sizeof(BoolOp));
               if (F->testpending) {
                  F->testjump = dest;
               }
               if (RemoveFromSet(F->untils, F->pc)) {
                  int endif, thenaddr;
                  char* test;
                  LogicExp* exp;
                  TRY(exp = MakeBoolean(F, &endif, &thenaddr));
                  TRY(test = WriteBoolean(exp, &thenaddr, &endif, 0));
                  StringBuffer_printf(str, "until %s", test);
                  F->indent--;
                  RawAddStatement(F, str);
                  mr_freeExt(test);
               }
            } else if (GET_OPCODE(idest) == OP_FORLOOP) {
               /*
                * numeric 'for' 
                */
               int i;
               int step;
               char *idxname = NULL;
               char *initial;
               char *findSign;
               char *a1str;
               int stepLen;
               int a = GETARG_A(idest);
               // int b = GETARG_B(idest);
               // int c = GETARG_C(idest);
               /*
                * if A argument for FORLOOP is not a known variable,
                * it was declared in the 'for' statement. Look for
                * its name in the locals table. 
                */
               for (i = 0; i < f->sizelocvars; i++) {
                  if (f->locvars[i].startpc == pc + 1) {
                     idxname = LOCAL(i);
                     break;
                  }
               }
               TRY(initial = GetR(F, a));
               initial = strdup2(initial);
               step = atoi2(REGISTER(a + 2));
               stepLen = strlen2(REGISTER(a + 2));
               findSign = strrchr2(initial, '-');
               if (findSign) {
                  initial[strlen2(initial) - stepLen - 3] = '\0';
               }
               TRY(a1str = GetR(F, a + 1));
               if (step == 1) {
                  StringBuffer_printf(str, "for %s = %s, %s do",
                                      idxname, initial, a1str);
               } else {
                  /* step parameter is not pending because it
                     was used in the calculation of the first step */
                  StringBuffer_printf(str, "for %s = %s, %s, %s do",
                                      idxname, initial,
                                      a1str, REGISTER(a + 2));
               }

               /*
                * Every numeric 'for' declares 3 variables. 
                */
               F->internal[a] = 1;
               F->internal[a + 1] = 1;
               F->internal[a + 2] = 1;
               TRY(AddStatement(F, str));
               F->indent++;
            } else if (GetEndifAddr(F, pc + 2)) {
               if (F->elseWritten) {
                  F->indent--;
                  StringBuffer_printf(str, "end");
                  TRY(AddStatement(F, str));
               }
               F->indent--;
               F->elsePending = dest;
               F->elseStart = pc + 2;
            } else if (PeekSet(F->whiles, pc)) {
               StringBuffer_printf(str, "while 1 do");
               TRY(AddStatement(F, str));
               MarkBackpatch(F);
               F->indent++;
            } else if (RemoveFromSet(F->whiles, dest - 2)) {
               F->indent--;
               StringBuffer_printf(str, "end");
               TRY(AddStatement(F, str));
               /* end while 1 */
            } else if (sbc == 2 && GET_OPCODE(code[pc+2]) == OP_LOADBOOL) {
               int boola = GETARG_A(code[pc+1]);
               char* test;
               /* skip */
               char* ra = strdup2(REGISTER(boola));
               char* rb = strdup2(ra);
               F->bools[F->nextBool]->op1 = ra;
               F->bools[F->nextBool]->op2 = rb;
               F->bools[F->nextBool]->op = OP_TEST;
               F->bools[F->nextBool]->neg = c;
               F->bools[F->nextBool]->pc = pc + 3;
               F->testpending = a+1;
               F->bools[F->nextBool]->dest = dest;
               F->nextBool++;
               F->bools[F->nextBool] = mr_mallocExt0(sizeof(BoolOp));
               F->testjump = dest;
               TRY(test = OutputBoolean(F, NULL, 1));
               StringBuffer_printf(str, "%s", test);
               TRY(UnsetPending(F, boola));
               TRY(Assign(F, REGISTER(boola), StringBuffer_getRef(str), boola, 0, 0));
               ignoreNext = 2;
            } else if (GET_OPCODE(idest) == OP_LOADBOOL) {
               /*
                * constant boolean value
                */
               pc = dest - 2;
            } else if (sbc == 0) {
               /* dummy jump -- ignore it */
               break;
            } else {
               int nextpc = pc+1;
               int nextsbc = sbc-1;
               for (;;) {
                  Instruction nextins = code[nextpc];
                  if (GET_OPCODE(nextins) == OP_JMP && GETARG_sBx(nextins) == nextsbc) {
                     nextpc++;
                     nextsbc--;
                  } else
                     break;
                  if (nextsbc == -1) {
                     break;
                  }
               }
               if (nextsbc == -1) {
                  pc = nextpc-1;
                  break;
               }
               if (F->indent > baseIndent) {
                  StringBuffer_printf(str, "do break end");
               } else {
                  pc = dest-2;
               }
               TRY(AddStatement(F, str));
            }

            break;
         }
      case OP_EQ:
      case OP_LT:
      case OP_LE:
         {
            if (IS_CONSTANT(b)) {
               int swap = b;
               b = c;
               c = swap;
               a = !a;
               if (o == OP_LT) o = OP_LE;
               else if (o == OP_LE) o = OP_LT;
            }
            TRY(F->bools[F->nextBool]->op1 = RegisterOrConstant(F, b));
            TRY(F->bools[F->nextBool]->op2 = RegisterOrConstant(F, c));
            F->bools[F->nextBool]->op = o;
            F->bools[F->nextBool]->neg = a;
            F->bools[F->nextBool]->pc = pc + 1;
            boolpending = 1;
            break;
         }
      case OP_TEST:
         {
            char *ra, *rb;
            if (!IS_VARIABLE(a)) {
               ra = strdup2(REGISTER(a));
               TRY(rb = GetR(F, b));
               rb = strdup2(rb);
               PENDING(a) = 0;
            } else {
               TRY(ra = GetR(F, a));
               if (a != b) {
                  TRY(rb = GetR(F, b));
                  rb = strdup2(rb);
               } else
                  rb = strdup2(ra);
            }
            F->bools[F->nextBool]->op1 = ra;
            F->bools[F->nextBool]->op2 = rb;
            F->bools[F->nextBool]->op = o;
            F->bools[F->nextBool]->neg = c;
            F->bools[F->nextBool]->pc = pc + 1;
            // Within an IF, a and b are the same, avoiding side-effects
            if (a != b || !IS_VARIABLE(a)) {
               F->testpending = a+1;
            }
            boolpending = 1;
            break;
         }
      case OP_CALL:
      case OP_TAILCALL:
         {
            /*
             * Function call. The CALL opcode works like this:
             * R(A),...,R(A+F-2) := R(A)(R(A+1),...,R(A+B-1)) 
             */
            int i, limit, self;
            char* astr;
            self = 0;

            if (b == 0)
               limit = F->lastCall + 1;
            else
               limit = a + b;
            if (o == OP_TAILCALL) {
               StringBuffer_set(str, "return ");
               ignoreNext = 1;
            }
            TRY(astr = GetR(F, a));
            StringBuffer_addPrintf(str, "%s(", astr);
            
            {
               char* at = astr + strlen2(astr) - 1;
               while (at > astr && (mr_isalpha(*at) || *at == '_')) {
                  at--;
               }
               if (*at == ':')
                  self = 1;
            }
            
            for (i = a + 1; i < limit; i++) {
               char *ireg;
               TRY(ireg = GetR(F, i));
               if (self && i == a+1)
                  continue;
               if (i > a + 1 + self)
                  StringBuffer_add(str, ", ");
               if (ireg)
                  StringBuffer_add(str, ireg);
            }
            StringBuffer_addChar(str, ')');

            if (c == 0) {
               F->lastCall = a;
            }
            if (GET_OPCODE(code[pc+1]) == OP_LOADNIL && GETARG_A(code[pc+1]) == a+1) {
               StringBuffer_prepend(str, "(");
               StringBuffer_add(str, ")");
               c += GETARG_B(code[pc+1]) - GETARG_A(code[pc+1]) + 1;
               // ignoreNext = 1;
            }
            if (o == OP_TAILCALL || c == 1) {
               TRY(AddStatement(F, str));
            } else {
               TRY(Assign(F, REGISTER(a), StringBuffer_getRef(str), a, 0, 0));
               for (i = 0; i < c-1; i++) {
                  CALL(a+i) = i+1;
               }
            }
            break;
         }
      case OP_RETURN:
         {
            /*
             * Return call. The RETURN opcode works like this: return
             * R(A),...,R(A+B-2) 
             */
            int i, limit;

            /* skip the last RETURN */
            if (pc == n - 1)
               break;
            if (b == 0)
               limit = F->lastCall;
            else
               limit = a + b - 1;
            StringBuffer_set(str, "return ");
            for (i = a; i < limit; i++) {
               char* istr;
               if (i > a)
                  StringBuffer_add(str, ", ");
               istr = GetR(F, i);
               TRY(StringBuffer_add(str, istr));
            }
            TRY(AddStatement(F, str));
            break;
         }
      case OP_FORLOOP:
         {
            F->indent--;
            F->ignore_for_variables = 1;
            StringBuffer_set(str, "end");
            TRY(AddStatement(F, str));
            break;
         }
      case OP_TFORLOOP:
         {
            F->indent--;
            F->ignore_for_variables = 1;
            StringBuffer_set(str, "end");
            TRY(AddStatement(F, str));
            ignoreNext = 1;
            break;
         }
      case OP_TFORPREP:
         {
            int prepCtr = 0;
            int prep = 0;
            int preps[10];
            char* astr;
            TRY(astr = GetR(F, a));
            for (i = 0; i < F->f->sizelocvars; i++) {
               if (F->f->locvars[i].startpc == pc+1) {
                  int reg = F->freeLocal + prepCtr;
                  if (prepCtr == 0)
                     prep = i;
                  F->internal[reg] = 1;
                  RemoveFromSet(F->tpend, reg);
                  preps[prepCtr] = reg;
                  prepCtr++;
               }
            }
            StringBuffer_printf(str, "for %s", LOCAL(prep+2));
            for (i = 3; i < prepCtr; i++) {
               StringBuffer_addPrintf(str, ", %s", LOCAL(prep+i));
            }
            StringBuffer_addPrintf(str, " in %s do", astr);
            TRY(GetR(F, a+1));
            TRY(AddStatement(F, str));
            for (i = 0; i < prepCtr; i++) {
               CALL(a+i) = 0;
               PENDING(preps[i]) = 0;
            }
            F->indent++;
            // TRY(DeclareVariable(F, LOCAL(c), a + 2));
            break;
         }
      case OP_SETLIST:
      case OP_SETLISTO:
         {
            TRY(SetList(F, a, bc));
            break;
         }
      case OP_CLOSE:
         /*
          * Handled in do_opens/do_closes variables.
          */
         break;
      case OP_CLOSURE:
         {
            /*
             * Function. 
             */
            StringBuffer_set(str, "def");
            StringBuffer_add(str, ProcessCode(f->p[c], F->indent));
            for (i = 0; i < F->indent; i++) {
               StringBuffer_add(str, "   ");
            }
            StringBuffer_add(str, "end");
            if (F->indent == 0)
               StringBuffer_add(str, "\n");
            TRY(Assign(F, REGISTER(a), StringBuffer_getRef(str), a, 0, 0));
            ignoreNext = f->p[c]->sizeupvalues;
            
            break;
         }
      default:
         StringBuffer_printf(str, "-- unhandled opcode? : %-9s\t\n", mr_P_opnames[o]);
         TRY(AddStatement(F, str));
         break;
      }

      if (debug) {
         TRY(ShowState(F));
         {
            char* f = PrintFunction(F);
            mr_printf("%s", f);
            mr_freeExt(f);
         }
      }

      if (GetEndifAddr(F, pc)) {
         StringBuffer_set(str, "end");
         F->elseWritten = 0;
         F->indent--;
         TRY(AddStatement(F, str));
         StringBuffer_prune(str);
      }

      TRY(OutputAssignments(F));

   }
   
   if (GetEndifAddr(F, pc+1)) {
      StringBuffer_set(str, "end");
      F->indent--;
      TRY(AddStatement(F, str));
      StringBuffer_prune(str);
   }

   TRY(FlushBoolean(F));

   output = PrintFunction(F);

   DeleteFunction(F);

   return output;

errorHandler:
   {
      char *copy;
      Statement *stmt; 
      StringBuffer_printf(str, "--[[ DECOMPILER ERROR %d: %s ]]", errorCode, error);
      copy = StringBuffer_getCopy(str);
      stmt = NewStatement(copy, F->pc, F->indent);
      AddToList(&(F->statements), (ListItem *) stmt);
      F->lastLine = F->pc;
   }
   output = PrintFunction(F);
   DeleteFunction(F);
   error = NULL;
   return output;
}

void luaU_decompile(const Proto * f, int dflag, char* outputFile)
{
   char* code;

   debug = dflag;
   code = ProcessCode(f, 0);
   writeFile(outputFile, code, strlen2(code));
   mr_freeExt(code);
}

void luaU_decompileFunctions(const Proto* f, int dflag, char* outputFile)
{
 int i,n=f->sizep;
 char* code;
 int32 outf = mr_open(outputFile, MR_FILE_WRONLY | MR_FILE_CREATE);

 debug = dflag;

 for (i=0; i<n; i++) {
    code = "-----\nfunction";
    mr_write(outf, code, strlen2(code));

    code = ProcessCode(f->p[i], 0);
    mr_write(outf, code, strlen2(code));
    mr_freeExt(code);

    code = "end\n";
    mr_write(outf, code, strlen2(code));
 }
 mr_close(outf);
}
