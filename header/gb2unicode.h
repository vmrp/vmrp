#ifndef __GB2UNICODE_H__
#define __GB2UNICODE_H__

#include <stdint.h>

char *gbToUCS2BE(uint8_t *gbCode, uint32_t *outSize);
//判断utf编码，0为成功，-1失败
int IsUTF8(void *pBuffer, long size);
// 万能转换函数 需要释放内存
char *en_coding( char *text, int len, const char *coding, const char *tocoding);


#endif
