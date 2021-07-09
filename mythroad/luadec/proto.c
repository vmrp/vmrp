
#include "proto.h"



// PrintString from luac is not 8-bit clean
char *DecompileString(const Proto * f, int n)
{
    int i;
    const unsigned char *s = (void*)svalue(&f->k[n]);
    int len = tsvalue(&f->k[n])->tsv.len;
    char *ret = mr_mallocExt0(strlen2((void*)s) * 4 + 3);
    int p = 0;
    ret[p++] = '"';
    for (i = 0; i < len; i++, s++) {
        switch (*s) {
        case '"':
            ret[p++] = '\\';
            ret[p++] = '"';
            break;
        case '\a':
            ret[p++] = '\\';
            ret[p++] = 'a';
            break;
        case '\b':
            ret[p++] = '\\';
            ret[p++] = 'b';
            break;
        case '\f':
            ret[p++] = '\\';
            ret[p++] = 'f';
            break;
        case '\n':
            ret[p++] = '\\';
            ret[p++] = 'n';
            break;
        case '\r':
            ret[p++] = '\\';
            ret[p++] = 'r';
            break;
        case '\t':
            ret[p++] = '\\';
            ret[p++] = 't';
            break;
        case '\v':
            ret[p++] = '\\';
            ret[p++] = 'v';
            break;
        case '\\':
            ret[p++] = '\\';
            ret[p++] = '\\';
            break;
        default:
            if (*s < 32 || *s > 127) {
               char* pos = &(ret[p]);
               sprintf_(pos, "\\%d", *s);
               p += strlen2(pos);
            } else {
               ret[p++] = *s;
            }
            break;
        }
    }
    ret[p++] = '"';
    ret[p] = '\0';
    return ret;
}

char *DecompileConstant(const Proto * f, int i)
{
    const TObject *o = &f->k[i];
    switch (ttype(o)) {
    case MRP_TNUMBER:
        {
            char *ret = mr_mallocExt0(100);
            sprintf_(ret, MRP_NUMBER_FMT, nvalue(o));
            return ret;
        }
    case MRP_TSTRING:
        return DecompileString(f, i);
    case MRP_TNIL:
        {
            char *ret = mr_mallocExt0(4);
            strcpy2(ret, "nil");
            return ret;
        }
    default:                   /* cannot happen */
        {
            char *ret = mr_mallocExt0(4);
            strcpy2(ret, "nil");
            return ret;
        }
    }
}
