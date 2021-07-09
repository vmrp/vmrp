#ifndef _mr_encode_h_
#define _mr_encode_h_

#include "type.h"
#include "mrporting.h"

/*
返回:
MR_FAILED  -1  表示失败
其他值       表示编码字符串长度，不包括字符串结束符\0
*/
extern int32 _mr_encode(uint8  *in, uint32 len,uint8 *out);

/*
返回:
MR_FAILED  -1  表示失败
其他值       表示解码后的数据长度
*/
extern int32 _mr_decode(uint8 *in, uint32 len, uint8 *out);

#endif
