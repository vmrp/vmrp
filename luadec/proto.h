#ifndef PROTO_H
#define PROTO_H


#include "../src/h/mr_debug.h"
#include "../src/h/mr_object.h"
#include "../src/h/mr_opcodes.h"
#include "../src/h/mr_undump.h"
#include "../include/mrporting.h"
#include "../include/mem.h"
#include "../include/string.h"

char *DecompileString(const Proto * f, int n);

char *DecompileConstant(const Proto * f, int i);

#endif
