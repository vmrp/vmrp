#ifndef _FILELIB_H
#define _FILELIB_H

#include "mr_types.h"


int32 getMrpFileInfo(const char *path, const char *name, int32 *offset, int32 *length);

int32 readMrpFileEx(const char *path, const char *name, int32 *offset, int32 *length, uint8 **data);

int ungzipdata(uint8 *dest, uint32 *destLen, const uint8 *source, uint32 sourceLen);

void listMrpFiles(const char *path);

#endif
