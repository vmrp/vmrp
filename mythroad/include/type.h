#ifndef _M_TYPE__
#define _M_TYPE__

#include <stdint.h>

typedef uint64_t uint64; /* Unsigned 64 bit value */
typedef int64_t int64;   /* signed 64 bit value */

typedef uint32_t uint32; /* Unsigned 32 bit value */
typedef int32_t int32;   /* signed 32 bit value */
typedef uint8_t uint8;   /*Unsigned  Signed 8  bit value */
typedef int8_t int8;     /* Signed 8  bit value */
typedef uint16_t uint16; /* Unsigned 16 bit value */
typedef int16_t int16;   /* Signed 16 bit value */

typedef char* PSTR;
typedef const char* PCSTR;

typedef uint8 U8;
typedef unsigned int uint;
typedef unsigned int UINT;

typedef int ptrdiff_t;

typedef unsigned int size_t;     // uint32
typedef unsigned int uintptr_t;  // uint32

typedef int BOOL;

#define FALSE 0
#define TRUE 1

#ifndef NULL
#define NULL (void*)0
#endif

// typedef char* PSTR;
// typedef const char* PCSTR;
// typedef uint8 U8;
// typedef uint64 U64;

// typedef unsigned int UINT;
// typedef unsigned long DWORD;
// typedef unsigned char BYTE;
// typedef DWORD* DWORD_PTR;

#ifndef offsetof
#define offsetof(type, field) ((size_t)&((type*)0)->field)
#endif
#ifndef countof
#define countof(x) (sizeof(x) / sizeof((x)[0]))
#endif

#endif
