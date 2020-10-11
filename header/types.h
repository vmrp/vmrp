#ifndef _TYPES_H
#define _TYPES_H

#include <stdint.h>
#include <stdio.h>
#define LOG(format, ...) printf(">> " format "\n", ##__VA_ARGS__)

typedef uint64_t uint64; /* Unsigned 64 bit value */
typedef int64_t int64;   /* signed 64 bit value */

typedef uint32_t uint32; /* Unsigned 32 bit value */
typedef int32_t int32;   /* signed 32 bit value */
typedef uint8_t uint8;   /*Unsigned  Signed 8  bit value */
typedef int8_t int8;     /* Signed 8  bit value */
typedef uint16_t uint16; /* Unsigned 16 bit value */
typedef int16_t int16;   /* Signed 16 bit value */
typedef unsigned int uint;

typedef char* PSTR;
typedef const char* PCSTR;

typedef int BOOL;

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef NULL
#define NULL (void*)0
#endif

//typedef long int size_t;
typedef uint8 U8;
typedef unsigned int UINT;

#define MR_SUCCESS 0  //成功
#define MR_FAILED -1  //失败
#define MR_IGNORE 1   //不关心
#define MR_WAITING 2  //异步(非阻塞)模式

#endif