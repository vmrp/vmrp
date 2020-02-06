#ifndef _M_STRING__
#define _M_STRING__

#include "type.h"

void *memcpy2(void *dest, const void *src, size_tt count);
void *memmove2(void *dest, const void *src, size_tt count);
char *strcpy2(char *dest, const char *src);
char *strncpy2(char *dest, const char *src, size_tt count);
char *strcat2(char *dest, const char *src);
char *strncat2(char *dest, const char *src, size_tt count);
int memcmp2(const void *cs, const void *ct, size_tt count);
int strcmp2(const char *cs, const char *ct);
int strncmp2(const char *cs, const char *ct, size_tt count);
void *memchr2(const void *s, int c, size_tt n);
void *memset2(void *s, int c, size_tt count);
size_tt strlen2(const char *s);
char *strstr2(const char *s1, const char *s2);

#endif
