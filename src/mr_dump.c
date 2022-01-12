

//#define ldump_c

#include "./h/mr_object.h"
#include "./h/mr_opcodes.h"
#include "./h/mr_state.h"
#include "./h/mr_undump.h"

#define DumpVector(b, n, size, D) DumpBlock(b, (n) * (size), D)
#define DumpLiteral(s, D) DumpBlock("" s, (sizeof(s)) - 1, D)

typedef struct {
    mrp_State* L;
    mrp_Chunkwriter write;
    int32 ver; // ++ 原lua没有
    void* data;
} DumpState;

static void DumpBlock(const void* b, size_t size, DumpState* D) {
    mrp_unlock(D->L);
    (*D->write)(D->L, b, size, D->data);
    mrp_lock(D->L);
}

static void DumpByte(int y, DumpState* D) {
    char x = (char)y;
    DumpBlock(&x, sizeof(x), D);
}

static void DumpInt(int x, DumpState* D) {
    DumpBlock(&x, sizeof(x), D);
}

static void DumpSize(size_t x, DumpState* D) {
    DumpBlock(&x, sizeof(x), D);
}

static void DumpNumber(mrp_Number x, DumpState* D) {
    DumpBlock(&x, sizeof(x), D);
}

static void DumpString(TString* s, DumpState* D) {
    if (s == NULL || getstr(s) == NULL)
        DumpSize(0, D);
    else {
        size_t size = s->tsv.len + 1; /* include trailing '\0' */
        DumpSize(size, D);
        DumpBlock(getstr(s), size, D);
    }
}

static void DumpCode(const Proto* f, DumpState* D) {
    DumpInt(f->sizecode, D);
    DumpVector(f->code, f->sizecode, sizeof(*f->code), D);
}

static void DumpLocals(const Proto* f, DumpState* D) {
    int i, n = f->sizelocvars;
    DumpInt(n, D);
    for (i = 0; i < n; i++) {
        DumpString(f->locvars[i].varname, D);
        DumpInt(f->locvars[i].startpc, D);
        DumpInt(f->locvars[i].endpc, D);
    }
}

static void DumpLines(const Proto* f, DumpState* D) {
    DumpInt(f->sizelineinfo, D);
    DumpVector(f->lineinfo, f->sizelineinfo, sizeof(*f->lineinfo), D);
}

static void DumpUpvalues(const Proto* f, DumpState* D) {
    int i, n = f->sizeupvalues;
    DumpInt(n, D);
    for (i = 0; i < n; i++) DumpString(f->upvalues[i], D);
}

static void DumpFunction(const Proto* f, const TString* p, DumpState* D);

static void DumpConstants(const Proto* f, DumpState* D) {
    int i, n;
    DumpInt(n = f->sizek, D);
    for (i = 0; i < n; i++) {
        const TObject* o = &f->k[i];
        DumpByte(ttype(o), D);
        switch (ttype(o)) {
            case MRP_TNUMBER:
                DumpNumber(nvalue(o), D);
                break;
            case MRP_TSTRING:
                DumpString(tsvalue(o), D);
                break;
            case MRP_TNIL:
                break;
            default:
                mrp_assert(0); /* cannot happen */
                break;
        }
    }
    DumpInt(n = f->sizep, D);
    for (i = 0; i < n; i++) DumpFunction(f->p[i], f->source, D);
}

static void DumpFunction(const Proto* f, const TString* p, DumpState* D) {
    DumpString((f->source == p) ? NULL : f->source, D);
    DumpInt(f->lineDefined, D);
    DumpByte(f->nups, D);
    DumpByte(f->numparams, D);
    DumpByte(f->is_vararg, D);
    DumpByte(f->maxstacksize, D);
    DumpLines(f, D);
    DumpLocals(f, D);
    DumpUpvalues(f, D);
    DumpConstants(f, D);
    DumpCode(f, D);
}

// static void DumpHeader(DumpState* D)
// {
//  DumpLiteral(LUA_SIGNATURE,D);
//  DumpByte(VERSION,D); // VERSION=50
//  DumpByte(luaU_endianness(),D);
//  DumpByte(sizeof(int),D);
//  DumpByte(sizeof(size_t),D);
//  DumpByte(sizeof(Instruction),D);
//  DumpByte(SIZE_OP,D);
//  DumpByte(SIZE_A,D);
//  DumpByte(SIZE_B,D);
//  DumpByte(SIZE_C,D);
//  DumpByte(sizeof(lua_Number),D);
//  DumpNumber(TEST_NUMBER,D);
// }
static void DumpHeader(DumpState* D) {
    DumpLiteral(MRP_SIGNATURE, D);
    DumpByte(D->ver, D);
    DumpByte(mr_U_endianness(), D);
    if ((D->ver) > VERSION_50) {
    } else {
        DumpByte(sizeof(int), D);
        DumpByte(sizeof(size_t), D);
        DumpByte(sizeof(Instruction), D);
        DumpByte(SIZE_OP, D);
        DumpByte(SIZE_A, D);
        DumpByte(SIZE_B, D);
        DumpByte(SIZE_C, D);
        DumpByte(sizeof(mrp_Number), D);
        DumpNumber(TEST_NUMBER, D);
    }
}

/*
** dump function as precompiled chunk
*/
void mr_U_dump(mrp_State* L, const Proto* Main, mrp_Chunkwriter w, void* data) {
    DumpState D;
    D.L = L;
    D.write = w;
    D.data = data;
    D.ver = 0x80; // ++ 原lua没有
    DumpHeader(&D);
    DumpFunction(Main, NULL, &D);
}
