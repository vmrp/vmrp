

#include "./include/mr_base64.h"

/*
 * "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
 *
 * 返回0xFF表示失败
 */
static unsigned char _mr_decode_table(unsigned char in) {
    unsigned char out = 0xFF;

    if (in == 'D')  //14
    {
        out = 7;
    } else if (in == 'h')  //7
    {
        out = 14;
    } else if (in == 'x')  //59
    {
        out = 63;
    } else if (in >= 'A' && in <= 'Z') {
        out = in - 'A' + 11;
    } else if (in >= 'a' && in <= 'k') {
        out = in - 'a';
    } else if (in >= 'l' && in <= 'z') {
        out = in - 'l' + 47;
    } else if (in >= '0' && in <= '9') {
        out = in - '0' + 37;
    } else if ('+' == in) {
        out = 62;
    } else if ('/' == in) {
        out = 59;
    } else if ('=' == in) {
        out = 64;
    }
    return (out);
} /* end of base64decodetable */

/*
 * BASE64解码算法的本质是char 转byte
return byte的个数
 * 返回-1表示失败
 */
int32 _mr_decode(uint8 *in, uint32 len, uint8 *out) {
    unsigned int x, y, z;
    int i, j;
    unsigned char bufa[4];
    unsigned char bufb[3];

    if (len == 0) {
        return 0;
    }
    /*
     * 由主调函数确保形参有效性
     */
    x = (len - 4) / 4;
    i =
        j = 0;
    for (z = 0; z < x; z++) {
        for (y = 0; y < 4; y++) {
            if ((bufa[y] = _mr_decode_table(in[j + y])) == 0xff)
                return MR_FAILED;
        } /* end of for */
        out[i] = bufa[0] << 2 | (bufa[1] & 0x30) >> 4;
        out[i + 1] = (bufa[1] & 0x0F) << 4 | (bufa[2] & 0x3C) >> 2;
        out[i + 2] = (bufa[2] & 0x03) << 6 | (bufa[3] & 0x3F);
        i += 3;
        j += 4;
    } /* end of for */
    for (z = 0; z < 4; z++) {
        if ((bufa[z] = _mr_decode_table(in[j + z])) == 0xff)
            return MR_FAILED;
    } /* end of for */
    /*
     * 编码算法确保了结尾最多有两个'='
     */
    if ('=' == in[len - 2]) {
        y = 2;
    } else if ('=' == in[len - 1]) {
        y = 1;
    } else {
        y = 0;
    }
    /*
     * BASE64算法所需填充字节个数是自识别的
     */
    for (z = 0; z < y; z++) {
        bufa[4 - z - 1] = 0x00;
    } /* end of for */
    bufb[0] = bufa[0] << 2 | (bufa[1] & 0x30) >> 4;
    bufb[1] = (bufa[1] & 0x0F) << 4 | (bufa[2] & 0x3C) >> 2;
    bufb[2] = (bufa[2] & 0x03) << 6 | (bufa[3] & 0x3F);
    /*
     * y必然小于3
     */
    for (z = 0; z < 3 - y; z++) {
        out[i + z] = bufb[z];
    } /* end of for */
    /*
     * 离开for循环的时候已经z++了
     */
    i += z;
    return (i);
} /* end of base64decode */

/*
 *
 * "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
 *
 * 返回0xFF表示失败
 */
static unsigned char _mr_encode_table(unsigned char in) {
    unsigned char out = 0xFF;

    if (in == 7)  //14
    {
        out = 'D';
    } else if (in == 14)  //7
    {
        out = 'h';
    } else if (59 == in) {
        out = '/';
    } else if (in >= 11 && in <= 36) {
        out = in + 'A' - 11;
    } else if (in >= 47 && in <= 61) {
        out = in + 'l' - 47;
    } else if (in <= 10) {
        out = in + 'a';
    } else if (in >= 37 && in <= 46) {
        out = in + '0' - 37;
    } else if (62 == in) {
        out = '+';
    } else if (in == 63)  //59
    {
        out = 'x';
    }
    return (out);
} /* end of base64encodetable */

/*
 * BASE64编码算法的本质是byte -> char
return char的个数
 * 返回-1表示失败
 */
int32 _mr_encode(uint8 *in, uint32 len, uint8 *out) {
    unsigned int x, y, z;
    int i, j;
    unsigned char buf[3];

    x = len / 3;
    y = len % 3;
    i =
        j = 0;
    for (z = 0; z < x; z++) {
        out[i] = _mr_encode_table((uint8)(in[j] >> 2));
        out[i + 1] = _mr_encode_table((uint8)((in[j] & 0x03) << 4 | in[j + 1] >> 4));
        out[i + 2] = _mr_encode_table((uint8)((in[j + 1] & 0x0F) << 2 | in[j + 2] >> 6));
        out[i + 3] = _mr_encode_table((uint8)(in[j + 2] & 0x3F));
        if ((out[i] | out[i + 1] | out[i + 2] | out[i + 3]) == 0xff)
            return MR_FAILED;
        i += 4;
        j += 3;
    } /* end of for */
    if (0 != y) {
        buf[0] =
            buf[1] =
                buf[2] = 0x00;
        for (z = 0; z < y; z++) {
            buf[z] = in[j + z];
        } /* end of for */
        out[i] = _mr_encode_table((uint8)(buf[0] >> 2));
        out[i + 1] = _mr_encode_table((uint8)((buf[0] & 0x03) << 4 | buf[1] >> 4));
        out[i + 2] = _mr_encode_table((uint8)((buf[1] & 0x0F) << 2 | buf[2] >> 6));
        out[i + 3] = _mr_encode_table((uint8)(buf[2] & 0x3F));
        if ((out[i] | out[i + 1] | out[i + 2] | out[i + 3]) == 0xff)
            return MR_FAILED;
        i += 4;
        /*
         * BASE64算法所需填充字节个数是自识别的
         */
        for (z = 0; z < 3 - y; z++) {
            out[i - z - 1] = '=';
        } /* end of for */
    }
    out[i] = 0;
    return (i);
} /* end of base64encode */
