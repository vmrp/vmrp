#ifndef _ENGINE_H
#define _ENGINE_H

#include "mr_helper.h"

#define SCNW 240
#define SCNH 320
#define SCNBIT 16

#define SCNBUF_COUNT 2

#define BITMAPMAX 30
#define SPRITEMAX 10
#define TILEMAX 3
#define SOUNDMAX 5

#define DSM_MEM_SIZE (2 * 1024 * 1024)  // DSM内存大小20M
#define DSM_MEM_SIZE_MIN (650 * 1024)   // DSM内存大小20M

#define START_FILE_NAME "cfunction.ext"

extern const mr_table mr_sys_table;
extern const mr_internal_table mr_sys_internal_tabl;
extern const mr_c_port_table mr_sys_c_port_table;

void mr_getScreenSize(int32 *w, int32 *h);
uint16 *w_getScreenBuffer(void);
void *mr_readFileFromMrp(const char *filename, int32 *filelen, int32 lookfor);

#endif