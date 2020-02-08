#ifndef _DSM_H
#define _DSM_H

#include "mr_types.h"
#include "mr_helper.h"

void *mr_malloc(uint32 len);
void mr_free(void *p, uint32 len);
void *mr_realloc(void *p, uint32 oldlen, uint32 newlen);
void *mr_memcpy(void *dst, const void *src, int len);
void *mr_memcpy(void *dst, const void *src, int len);
void *mr_memmove(void *dst, const void *src, int len);
char *mr_strcpy(char *dst, const char *src);
char *mr_strncpy(char *dst, const char *src, int len);
char *mr_strcat(char *dst, const char *src);
char *mr_strncat(char *dst, const char *src, int len);
int mr_memcmp(const void *dst, const void *src, int len);
int mr_strcmp(const char *dst, const char *src);
int mr_strncmp(const char *dst, const char *src, int len);
int mr_strcoll(const char *dst, const char *src);
void *mr_memchr(const void *s, int c, int len);
void *mr_memset(void *s, int c, int len);
int mr_strlen(const char *s);
char *mr_strstr(const char *s1, const char *s2);
int mr_sprintf(char *buf, const char *fmt, ...);
int mr_atoi(const char *s);
unsigned long mr_strtoul(const char *nptr, char **endptr, int base);
void mr_sand(uint32 seed);
int mr_rand(void);

void mr_md5_init(md5_state_t *pms);
void mr_md5_append(md5_state_t *pms, const md5_byte_t *data, int nbytes);
void mr_md5_finish(md5_state_t *pms, md5_byte_t digest[16]);
int32 mr_load_sms_cfg(void);
int32 mr_save_sms_cfg(int32 f);
int32 mr_DispUpEx(int16 x, int16 y, uint16 w, uint16 h);
void mr_DrawPoint(int16 x, int16 y, uint16 nativecolor);
void mr_DrawBitmap(uint16 *p, int16 x, int16 y, uint16 w, uint16 h, uint16 rop, uint16 transcoler, int16 sx, int16 sy, int16 mw);
void mr_DrawBitmapEx(mr_bitmapDrawSt *srcbmp, mr_bitmapDrawSt *dstbmp, uint16 w, uint16 h, mr_transMatrixSt *pTrans, uint16 transcoler);
void mr_DrawRect(int16 x, int16 y, int16 w, int16 h, uint8 r, uint8 g, uint8 b);
int32 mr_DrawText(char *pcText, int16 x, int16 y, uint8 r, uint8 g, uint8 b, int is_unicode, uint16 font);
int mr_BitmapCheck(uint16 *p, int16 x, int16 y, uint16 w, uint16 h, uint16 transcoler, uint16 color_check);
int mr_wstrlen(char *str);
int32 mr_DrawTextEx(char *pcText, int16 x, int16 y, mr_screenRectSt rect, mr_colourSt colorst, int flag, uint16 font);
int32 mr_EffSetCon(int16 x, int16 y, int16 w, int16 h, int16 perr, int16 perg, int16 perb);
int32 mr_TestCom(int32 L, int input0, int input1);
int32 mr_TestCom1(int32 L, int input0, char *input1, int32 len);
uint16 *mr_c2u(char *cp, int32 *err, int32 *size);
int32 mr_div(int32 a, int32 b);
int32 mr_mod(int32 a, int32 b);
int32 mr_unzip(uint8 *inputbuf, int32 inputlen, uint8 **outputbuf, int32 *outputlen);
uint32 mrc_updcrc(uint8 *s, uint32 n);
void *mr_readFile(const char *filename, int *filelen, int lookfor);

#endif
