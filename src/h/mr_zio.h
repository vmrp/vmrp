
#ifndef mr_zio_h
#define mr_zio_h

#include "../../include/mr.h"


#define EOZ	(-1)			/* end of stream */

typedef struct Zio ZIO;


#define char2int(c)	cast(int, cast(unsigned char, (c)))

#define zgetc(z)  (((z)->n--)>0 ?  char2int(*(z)->p++) : mr_Z_fill(z))

#define zname(z)	((z)->name)

void mr_Z_init (ZIO *z, mrp_Chunkreader reader, void *data, const char *name);
size_t mr_Z_read (ZIO* z, void* b, size_t n);	/* read next n bytes */
int mr_Z_lookahead (ZIO *z);



typedef struct Mbuffer {
  char *buffer;
  size_t buffsize;
} Mbuffer;


char *mr_Z_openspace (mrp_State *L, Mbuffer *buff, size_t n);

#define mr_Z_initbuffer(L, buff) ((buff)->buffer = NULL, (buff)->buffsize = 0)

#define mr_Z_sizebuffer(buff)	((buff)->buffsize)
#define mr_Z_buffer(buff)	((buff)->buffer)

#define mr_Z_resizebuffer(L, buff, size) \
	(mr_M_reallocvector(L, (buff)->buffer, (buff)->buffsize, size, char), \
	(buff)->buffsize = size)

#define mr_Z_freebuffer(L, buff)	mr_Z_resizebuffer(L, buff, 0)


/* --------- Private Part ------------------ */

struct Zio {
  size_t n;			/* bytes still unread */
  const char *p;		/* current position in buffer */
  mrp_Chunkreader reader;
  void* data;			/* additional data */
  const char *name;
};


int mr_Z_fill (ZIO *z);

#endif
