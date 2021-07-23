
#ifndef mr_undump_h
#define mr_undump_h

#include "mr_object.h"
#include "mr_zio.h"

/* load one chunk; from lundump.c */
Proto* mr_U_undump (mrp_State* L, ZIO* Z, Mbuffer* buff);

/* find byte order; from lundump.c */
int mr_U_endianness (void);

/* dump one chunk; from ldump.c */
void mr_U_dump (mrp_State* L, const Proto* Main, mrp_Chunkwriter w, void* data);

/* print one chunk; from print.c */
void mr_U_print (const Proto* Main);

/* definitions for headers of binary files */
#define	MRP_SIGNATURE	"\033MRP"	/* binary files start with "<esc>MRP" */
//#define	MRP_SIGNATURE	"\033Lua"	/* binary files start with "<esc>Lua" */
#define	VERSION		0x80		/* biggest */
#define	VERSION_50	0x50		/* little */

/* a multiple of PI for testing native format */
/* multiplying by 1E7 gives non-trivial integer values */
#define	TEST_NUMBER	((mrp_Number)3.14159265358979323846E7)

#endif
