/*
** $Id: lzio.c,v 1.24 2003/03/20 16:00:56 roberto Exp $
** a generic input stream interface
** See Copyright Notice in lua.h
*/



//#define lzio_c


#include "./h/mr_limits.h"
#include "./h/mr_mem.h"
#include "./h/mr_zio.h"


int mr_Z_fill (ZIO *z) {
  size_t size;
  const char *buff = z->reader(NULL, z->data, &size);
  if (buff == NULL || size == 0) return EOZ;
  z->n = size - 1;
  z->p = buff;
  return char2int(*(z->p++));
}


int mr_Z_lookahead (ZIO *z) {
  if (z->n == 0) {
    int c = mr_Z_fill(z);
    if (c == EOZ) return c;
    z->n++;
    z->p--;
  }
  return char2int(*z->p);
}


void mr_Z_init (ZIO *z, mrp_Chunkreader reader, void *data, const char *name) {
  z->reader = reader;
  z->data = data;
  z->name = name;
  z->n = 0;
  z->p = NULL;
}


/* --------------------------------------------------------------- read --- */
size_t mr_Z_read (ZIO *z, void *b, size_t n) {
  while (n) {
    size_t m;
    if (z->n == 0) {
      if (mr_Z_fill(z) == EOZ)
        return n;  /* return number of missing bytes */
      else {
        ++z->n;  /* filbuf removed first byte; put back it */
        --z->p;
      }
    }
    m = (n <= z->n) ? n : z->n;  /* min. between n and z->n */
    MEMCPY(b, z->p, m);//ouli brew
    z->n -= m;
    z->p += m;
    b = (char *)b + m;
    n -= m;
  }
  return 0;
}

/* ------------------------------------------------------------------------ */
char *mr_Z_openspace (mrp_State *L, Mbuffer *buff, size_t n) {
  if (n > buff->buffsize) {
    if (n < MRP_MINBUFFER) n = MRP_MINBUFFER;
    mr_M_reallocvector(L, buff->buffer, buff->buffsize, n, char);
    buff->buffsize = n;
  }
  return buff->buffer;
}


