#ifndef _M_STRING__
#define _M_STRING__

#include "type.h"

void *memcpy2(void *dest, const void *src, size_t count);
void *memmove2(void *dest, const void *src, size_t count);
char *strcpy2(char *dest, const char *src);
char *strncpy2(char *dest, const char *src, size_t count);
char *strcat2(char *dest, const char *src);
char *strncat2(char *dest, const char *src, size_t count);
int memcmp2(const void *cs, const void *ct, size_t count);
int strcmp2(const char *cs, const char *ct);
int strncmp2(const char *cs, const char *ct, size_t count);
void *memchr2(const void *s, int c, size_t n);
void *memset2(void *s, int c, size_t count);
size_t strlen2(const char *s);
char *strstr2(const char *s1, const char *s2);
char *strchr2(const char *s, int c);
size_t strcspn2(const char *s, const char *reject);
char *strpbrk2(const char *cs, const char *ct);
char *strrchr2(const char *s, int c);
char *strdup2(const char *s);







#endif
