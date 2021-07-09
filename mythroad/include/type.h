#ifndef _M_TYPE__
#define _M_TYPE__

typedef char int8;
typedef unsigned char uint8;
typedef short int16;
typedef unsigned short uint16;
typedef int int32;
// typedef long int32; // long也是4字节
typedef unsigned int uint32;
typedef long long int64;
typedef unsigned long long uint64;


typedef int ptrdiff_t;

typedef unsigned int  size_t; // uint32
typedef unsigned int  uintptr_t; // uint32
typedef long long  intmax_t; // int64

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
#define offsetof(type, field) ((size_t) & ((type *)0)->field)
#endif
#ifndef countof
#define countof(x) (sizeof(x) / sizeof((x)[0]))
#endif



#endif
