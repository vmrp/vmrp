#ifndef _OTHER_H_
#define _OTHER_H_

#include <setjmp.h>
#include <stdarg.h>

#include "type.h"

#define atoi2 atol2
#define mr_wstrlen wstrlen

uint32 mr_updcrc(uint8 *s, unsigned n);
int wstrlen(char *txt);
long atol2(const char *s);
long strtol2(const char *nptr, char **endptr, register int base);
unsigned long strtoul2(const char *nptr, char **endptr, register int base);
void writeFile(char *filename, void *p, uint32 l);

#endif
