#ifndef _MR_GZIP_H_
#define _MR_GZIP_H_

#include "mr.h"
#include "other.h"
#include "string.h"

#define memzero(s, n) memset2((void *)(s), 0, (n))

#define local static

typedef unsigned char uch;
typedef unsigned short ush;
typedef unsigned long ulg;

/* PKZIP header definitions */
#define LOCSIG 0x04034b50L /* four-byte lead-in (lsb first) */
#define LOCFLG 6           /* offset of bit flag */
#define CRPFLG 1           /*  bit for encrypted entry */
#define EXTFLG 8           /*  bit for extended local header */
#define LOCHOW 8           /* offset of compression method */
#define LOCTIM 10          /* file mod time (for decryption) */
#define LOCCRC 14          /* offset of crc */
#define LOCSIZ 18          /* offset of compressed size */
#define LOCLEN 22          /* offset of uncompressed length */
#define LOCFIL 26          /* offset of file name field length */
#define LOCEXT 28          /* offset of extra field length */
#define LOCHDR 30          /* size of local header, including sig */
#define EXTHDR 16          /* size of extended local header, inc sig */

/* Return codes from gzip */
//#define OK      0
//#define ERROR   1
//#define WARNING 2

/* Compression methods (see algorithm.doc) */
//#define STORED      0
//#define COMPRESSED  1
#define PACKED 2
//#define LZHED       3
/* methods 4 to 7 reserved */
#define DEFLATED 8
//#define MAX_METHODS 9
//extern int method;         /* compression method */

/* To save memory for 16 bit systems, some arrays are overlaid between
 * the various modules:
 * deflate:  prev+head   window      d_buf  l_buf  outbuf
 * unlzw:    tab_prefix  tab_suffix  stack  inbuf  outbuf
 * inflate:              window             inbuf
 * unpack:               window             inbuf  prefix_len
 * unlzh:    left+right  window      c_table inbuf c_len
 * For compression, input is done in window[]. For decompression, output
 * is done in window except for unlzw.
 */
/*
#ifdef DYN_ALLOC
#  define EXTERN(type, array)  extern type * near array
#  define DECLARE(type, array, size)  type * near array
#  define ALLOC(type, array, size) { \
      array = (type*)fcalloc((size_t)(((size)+1L)/2), 2*sizeof(type)); \
      if (array == NULL) error("insufficient memory"); \
   }
#  define FREE(array) {if (array != NULL) fcfree(array), array=NULL;}
#else
#  define EXTERN(type, array)  extern type array[]
#  define DECLARE(type, array, size)  type array[size]
#  define ALLOC(type, array, size)
#  define FREE(array)
#endif
*/
extern uch *mr_gzInBuf;
extern uch *mr_gzOutBuf;

extern unsigned LG_gzinptr;  /* index of next byte to be processed in inbuf */
extern unsigned LG_gzoutcnt; /* bytes in output buffer */

//#//define isize bytes_in
/* for compatibility with old zip sources (to be cleaned) */

//typedef int file_t;     /* Do not use stdio */
//#define NO_FILE  (-1)   /* in memory compression */

#define PACK_MAGIC "\037\036"          /* Magic header for packed files */
#define GZIP_MAGIC "\037\213"          /* Magic header for gzip files, 1F 8B */
#define OLD_GZIP_MAGIC "\037\236"      /* Magic header for gzip 0.5 = freeze 1.x */
#define LZH_MAGIC "\037\240"           /* Magic header for SCO LZH Compress files*/
#define PKZIP_MAGIC "\120\113\003\004" /* Magic header for pkzip files */

/* gzip flag byte */
#define ASCII_FLAG 0x01   /* bit 0 set: file probably ascii text */
#define CONTINUATION 0x02 /* bit 1 set: continuation of multi-part gzip file */
#define EXTRA_FIELD 0x04  /* bit 2 set: extra field present */
#define ORIG_NAME 0x08    /* bit 3 set: original file name present */
#define COMMENT 0x10      /* bit 4 set: file comment present */
#define ENCRYPTED 0x20    /* bit 5 set: file is encrypted */
#define RESERVED 0xC0     /* bit 6,7:   reserved */

/* internal file attribute */
#define UNKNOWN 0xffff
#define BINARY 0
#define ASCII 1

#define WSIZE 0x200000 /* window size--must be a power of two, and */

#define MIN_MATCH 3
#define MAX_MATCH 258
/* The minimum and maximum match lengths */

#define MIN_LOOKAHEAD (MAX_MATCH + MIN_MATCH + 1)
/* Minimum amount of lookahead, except at the end of the input file.
 * See deflate.c for comments about the MIN_MATCH+1.
 */

#define MAX_DIST (WSIZE - MIN_LOOKAHEAD)
/* In order to simplify the code, particularly on 16 bit machines, match
 * distances are limited to MAX_DIST instead of WSIZE.
 */

//extern int mr_decrypt;        /* flag to turn on decryption */
//extern int exit_code;      /* program exit code */
//extern int verbose;        /* be verbose (-v) */
//extern int quiet;          /* be quiet (-q) */
//extern int level;          /* compression level */
//extern int test;           /* check .z file integrity */
//extern int to_stdout;      /* output to stdout (-c) */
//extern int save_orig_name; /* set if original name must be saved */

#define get_byte() mr_gzInBuf[LG_gzinptr++]
#define try_byte() mr_gzInBuf[LG_gzinptr++]

/* put_byte is used for the compressed output, put_ubyte for the
 * uncompressed output. However unlzw() uses window for its
 * suffix table instead of its output buffer, so it does not use put_ubyte
 * (to be cleaned up).
 */
#define put_ubyte(c) mr_gzOutBuf[LG_gzoutcnt++] = (uch)(c)

/* Output a 16 bit value, lsb first */

/* Output a 32 bit value to the bit stream, lsb first */

#define seekable() 0    /* force sequential output */
#define translate_eol 0 /* no option -a yet */

#define tolow(c) (mr_isupper(c) ? (c) - 'A' + 'a' : (c)) /* force to lower case */

/* Macros for getting two-byte and four-byte header values */
#define SH(p) ((ush)(uch)((p)[0]) | ((ush)(uch)((p)[1]) << 8))
#define LG(p) ((ulg)(SH(p)) | ((ulg)(SH((p) + 2)) << 16))

/* Diagnostic functions */
#ifdef DEBUG
//#  define Assert(cond,msg) {if(!(cond)) error(msg);}
//#  define Trace(x) fprintf x
//#  define Tracev(x) {if (verbose) fprintf x ;}
//#  define Tracevv(x) {if (verbose>1) fprintf x ;}
//#  define Tracec(c,x) {if (verbose && (c)) fprintf x ;}
//#  define Tracecv(c,x) {if (verbose>1 && (c)) fprintf x ;}
#define Assert(cond, msg)
#define Trace(x)
#define Tracev(x)
#define Tracevv(x)
#define Tracec(c, x)
#define Tracecv(c, x)
#else
#define Assert(cond, msg)
#define Trace(x)
#define Tracev(x)
#define Tracevv(x)
#define Tracec(c, x)
#define Tracecv(c, x)
#endif

extern int mr_unzip(void);
extern int mr_get_method(int32 buf_len);
extern int mr_inflate(void);

#endif
