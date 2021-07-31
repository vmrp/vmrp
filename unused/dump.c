/*
** $Id: luac.c,v 1.44a 2003/04/07 20:34:20 lhf Exp $
** Lua compiler (saves bytecodes to files; also list bytecodes)
** See Copyright Notice in lua.h
*/
#include <stdio.h>
#include "./include/mr.h"
#include "./include/mr_auxlib.h"

#include "./src/h/mr_func.h"
#include "./src/h/mr_mem.h"
#include "./src/h/mr_object.h"
#include "./src/h/mr_opcodes.h"
#include "./src/h/mr_string.h"
#include "./src/h/mr_undump.h"
#include "./src/h/mr_debug.h"
#include "./include/fileLib.h"

// #define DEBUG_PRINT

#ifndef MRP_DEBUG
#define mr_B_opentests(L)
#endif

#ifndef PROGNAME
#define PROGNAME "mrc" /* program name */
#endif

static int listing = 1;   /* list bytecodes? */
static int dumping = 1;   /* dump bytecodes? */
static int stripping = 0; /* strip debug information? */

static Proto* toproto(mrp_State* L, int i) {
    const Closure* c = (const Closure*)mrp_topointer(L, i);
    return c->l.p;
}

static Proto* combine(mrp_State* L, int n) {
    if (n == 1)
        return toproto(L, -1);
    else {
        int i, pc = 0;
        Proto* f = mr_F_newproto(L);
        f->source = mr_S_newliteral(L, "=(" PROGNAME ")");
        f->maxstacksize = 1;
        f->p = mr_M_newvector(L, n, Proto*);
        f->sizep = n;
        f->sizecode = 2 * n + 1;
        f->code = mr_M_newvector(L, f->sizecode, Instruction);
        for (i = 0; i < n; i++) {
            f->p[i] = toproto(L, i - n);
            f->code[pc++] = CREATE_ABx(OP_CLOSURE, 0, i);
            f->code[pc++] = CREATE_ABC(OP_CALL, 0, 1, 1);
        }
        f->code[pc++] = CREATE_ABC(OP_RETURN, 0, 1, 0);
        return f;
    }
}

static void strip(mrp_State* L, Proto* f) {
    int i, n = f->sizep;
    mr_M_freearray(L, f->lineinfo, f->sizelineinfo, int);
    mr_M_freearray(L, f->locvars, f->sizelocvars, struct LocVar);
    mr_M_freearray(L, f->upvalues, f->sizeupvalues, TString*);
    f->lineinfo = NULL;
    f->sizelineinfo = 0;
    f->locvars = NULL;
    f->sizelocvars = 0;
    f->upvalues = NULL;
    f->sizeupvalues = 0;
    f->source = mr_S_newliteral(L, "=(none)");
    for (i = 0; i < n; i++) strip(L, f->p[i]);
}

static int writer(mrp_State* L, const void* p, size_t size, void* u) {
    UNUSED(L);
    return my_write((int32)u, (void*)p, size);
}

int dumpMr(mrp_State* L) {
    Proto* f;
    int n = 1;
    mr_B_opentests(L);

    const char* filename = "start.mr";
    if (mr_L_loadfile(L, filename) != 0) {
        mr_printf("dump loadfile fail %s", mrp_tostring(L, -1));
    }

    f = combine(L, n);
    if (listing) mr_U_print(f);
    if (dumping) {
        int32 fh = my_open("dump.lua", MR_FILE_CREATE | MR_FILE_RDWR);
        if (stripping) strip(L, f);
        mrp_lock(L);
        mr_U_dump(L, f, writer, (void*)fh);
        mrp_unlock(L);
        my_close(fh);
    }
    return 0;
}

#define Sizeof(x) ((int)sizeof(x))
#define VOID(p) ((const void*)(p))

static void PrintString(const Proto* f, int n) {
    const char* s = svalue(&f->k[n]);
    putchar('"');
    for (; *s; s++) {
        switch (*s) {
            case '"':
                printf("\\\"");
                break;
            case '\a':
                printf("\\a");
                break;
            case '\b':
                printf("\\b");
                break;
            case '\f':
                printf("\\f");
                break;
            case '\n':
                printf("\\n");
                break;
            case '\r':
                printf("\\r");
                break;
            case '\t':
                printf("\\t");
                break;
            case '\v':
                printf("\\v");
                break;
            default:
                putchar(*s);
                break;
        }
    }
    putchar('"');
}

static void PrintConstant(const Proto* f, int i) {
    const TObject* o = &f->k[i];
    switch (ttype(o)) {
        case MRP_TNUMBER:
            printf(MRP_NUMBER_FMT, nvalue(o));
            break;
        case MRP_TSTRING:
            PrintString(f, i);
            break;
        case MRP_TNIL:
            printf("nil");
            break;
        default: /* cannot happen */
            printf("? type=%d", ttype(o));
            break;
    }
}

static void PrintCode(const Proto* f) {
    const Instruction* code = f->code;
    int pc, n = f->sizecode;
    for (pc = 0; pc < n; pc++) {
        Instruction i = code[pc];
        OpCode o = GET_OPCODE(i);
        int a = GETARG_A(i);
        int b = GETARG_B(i);
        int c = GETARG_C(i);
        int bc = GETARG_Bx(i);
        int sbc = GETARG_sBx(i);
        int line = getline(f, pc);
#if 0
  printf("%0*lX",Sizeof(i)*2,i);
#endif
        printf("\t%d\t", pc + 1);
        if (line > 0)
            printf("[%d]\t", line);
        else
            printf("[-]\t");
        printf("%-9s\t", mr_P_opnames[o]);
        switch (getOpMode(o)) {
            case iABC:
                printf("%d %d %d", a, b, c);
                break;
            case iABx:
                printf("%d %d", a, bc);
                break;
            case iAsBx:
                printf("%d %d", a, sbc);
                break;
        }
        switch (o) {
            case OP_LOADK:
                printf("\t; ");
                PrintConstant(f, bc);
                break;
            case OP_GETUPVAL:
            case OP_SETUPVAL:
                printf("\t; %s", (f->sizeupvalues > 0) ? getstr(f->upvalues[b]) : "-");
                break;
            case OP_GETGLOBAL:
            case OP_SETGLOBAL:
                printf("\t; %s", svalue(&f->k[bc]));
                break;
            case OP_GETTABLE:
            case OP_SELF:
                if (c >= MAXSTACK) {
                    printf("\t; ");
                    PrintConstant(f, c - MAXSTACK);
                }
                break;
            case OP_SETTABLE:
            case OP_ADD:
            case OP_SUB:
            case OP_MUL:
            case OP_DIV:
            case OP_POW:
            case OP_EQ:
            case OP_LT:
            case OP_LE:
                if (b >= MAXSTACK || c >= MAXSTACK) {
                    printf("\t; ");
                    if (b >= MAXSTACK)
                        PrintConstant(f, b - MAXSTACK);
                    else
                        printf("-");
                    printf(" ");
                    if (c >= MAXSTACK) PrintConstant(f, c - MAXSTACK);
                }
                break;
            case OP_JMP:
            case OP_FORLOOP:
            case OP_TFORPREP:
                printf("\t; to %d", sbc + pc + 2);
                break;
            case OP_CLOSURE:
                printf("\t; %p", VOID(f->p[bc]));
                break;
            default:
                break;
        }
        printf("\n");
    }
}

static const char* Source(const Proto* f) {
    const char* s = getstr(f->source);
    if (*s == '@' || *s == '=')
        return s + 1;
    else if (*s == MRP_SIGNATURE[0])
        return "(bstring)";
    else
        return "(string)";
}

#define IsMain(f) (f->lineDefined == 0)

#define SS(x) (x == 1) ? "" : "s"
#define S(x) x, SS(x)

static void PrintHeader(const Proto* f) {
    printf("\n%s <%s:%d> (%d instruction%s, %d bytes at %p)\n",
           IsMain(f) ? "main" : "function", Source(f), f->lineDefined,
           S(f->sizecode), f->sizecode * Sizeof(Instruction), VOID(f));
    printf("%d%s param%s, %d stack%s, %d upvalue%s, ",
           f->numparams, f->is_vararg ? "+" : "", SS(f->numparams), S(f->maxstacksize),
           S(f->nups));
    printf("%d local%s, %d constant%s, %d function%s\n",
           S(f->sizelocvars), S(f->sizek), S(f->sizep));
}

#ifdef DEBUG_PRINT
static void PrintConstants(const Proto* f) {
    int i, n = f->sizek;
    printf("constants (%d) for %p:\n", n, VOID(f));
    for (i = 0; i < n; i++) {
        printf("\t%d\t", i);
        PrintConstant(f, i);
        printf("\n");
    }
}

static void PrintLocals(const Proto* f) {
    int i, n = f->sizelocvars;
    printf("locals (%d) for %p:\n", n, VOID(f));
    for (i = 0; i < n; i++) {
        printf("\t%d\t%s\t%d\t%d\n",
               i, getstr(f->locvars[i].varname), f->locvars[i].startpc, f->locvars[i].endpc);
    }
}

static void PrintUpvalues(const Proto* f) {
    int i, n = f->sizeupvalues;
    printf("upvalues (%d) for %p:\n", n, VOID(f));
    if (f->upvalues == NULL) return;
    for (i = 0; i < n; i++) {
        printf("\t%d\t%s\n", i, getstr(f->upvalues[i]));
    }
}
#endif

void mr_U_print(const Proto* f) {
    int i, n = f->sizep;
    PrintHeader(f);
    PrintCode(f);
#ifdef DEBUG_PRINT
    PrintConstants(f);
    PrintLocals(f);
    PrintUpvalues(f);
#endif
    for (i = 0; i < n; i++) mr_U_print(f->p[i]);
}