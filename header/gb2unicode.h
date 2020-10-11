#ifndef __GB2UNICODE_H__
#define __GB2UNICODE_H__

#include <stdint.h>

char *gbToUCS2BE(uint8_t *gbCode, uint32_t *outSize);


#endif
