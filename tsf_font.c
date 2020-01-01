#include <string.h>

// TSF点阵字库模块 [4/30/2012 JianbinZhu]
#include "./header/engine.h"
#include "./header/mr_helper.h"
#include "./header/mrporting.h"
#include "./header/tsf_font.h"

#define TSF_LOG LOGI

//字体信息结构体
typedef struct fontPoint {
    int32 uIndexOff;  // unicode字库索引表在字库文件中的偏移
    int32 uIndexLen;  // unicode字库索引表长度
    uint8
        *uIndexBuf;  // unicode字库索引表缓冲区地址，字库索引表是会加载到内存的

    int32 PointOff;   //字库点阵在字库文件中的偏移
    int32 PointLen;   //字库点阵长度
    uint8 *PointBuf;  //字库点阵缓冲区（内存加载方式）

    int32 GBWidth;     // GB单个字符宽度
    int32 AsciiWidth;  // ascii单个字符宽度
    int32 fontHeight;  //单个字符高度
} T_FONT_INFO, *PT_FONT_INFO;

#define FONT_DES 128

//特殊字符定义
#define CHR_SPACE ' '      //空格
#define CHR_TAB '	'  //制表符

static T_FONT_INFO g_nowUse;  //当前使用的字库
static uint8 Buf[FONT_DES];   //字体点阵信息缓存
static uint8 enable;          //是否可用标志
static uint8 gMemLoad;        //内存加载标志

static uint16 *pscn;      //屏幕缓冲区地址
static int32 scnw, scnh;  //屏幕尺寸


static const unsigned char masks[] = {
    0x80,  // 1000 0000
    0x40,  // 0100 0000
    0x20,  // 0010 0000
    0x10,  // 0001 0000
    0x08,  // 0000 1000
    0x04,  // 0000 0100
    0x02,  // 0000 0010
    0x01   // 0000 0001
};

//获取一个字符在字库点阵中的索引
static int32 GetOffSet(uint16 chr) {
    uint16 iM = 0;  //(一个索引项含16位UNICODE值16位偏移量)
    uint16 iB = 1;
    uint16 iE = 0;
    int32 UValue = 0;
    int32 indexLen = 0;
    uint8 *buf = NULL;

    indexLen = g_nowUse.uIndexLen;
    buf = g_nowUse.uIndexBuf;

    // 2012、5、9 修正 iE = (uint16)indexLen /5;
    iE = indexLen / 5;
    while (iB <= iE) {
        iM = (iB + iE) / 2;
        UValue = buf[(iM - 1) * 5];
        UValue = UValue << 8;
        UValue += buf[(iM - 1) * 5 + 1];

        if (chr == UValue) {
            UValue = buf[(iM - 1) * 5 + 2];
            UValue = UValue << 8;
            UValue += buf[(iM - 1) * 5 + 3];
            UValue = UValue << 8;
            UValue += buf[(iM - 1) * 5 + 4];

            return UValue;
        } else if (chr > UValue) {
            iB = iM + 1;
        } else {
            iE = iM - 1;
        }
    }

    return 0;
}

//获取字符点阵位图
//第一个字节 字宽 第二个字节 字字节数
uint8 *tsf_getCharBitmap(uint16 ch) {
    int32 offset = GetOffSet(ch);

    memset(Buf, 0, FONT_DES);

    if (offset == 0) {
        offset = GetOffSet(0x53e3);  //返回 □
        if (!offset) return (uint8 *)Buf;
    }

    //第一个字节 字宽 第二个字节 字字节数
    if (gMemLoad) {
        memcpy(Buf, g_nowUse.PointBuf + offset, FONT_DES);
    }

    return (uint8 *)Buf;
}

//单行绘制
int32 tsf_drawText(uint8 *chr, int16 x, int16 y, mr_colourSt colorst) {
    if (!enable || !chr) {
        return -1;
    }

    {
        int totalPoint, totalIndex, index_I, index_J;
        uint16 *tempBuf = (uint16 *)chr;
        uint16 ch = 0;
        int32 temp_mr_screen_w;
        int32 X1, Y1, chx, chy;
        const uint8 *current_bitmap;
        uint8 *p = (uint8 *)tempBuf;
        uint8 temp = 0;
        uint16 color = MAKERGB(colorst.r, colorst.g, colorst.b);
        int32 fw, fh = g_nowUse.fontHeight, flen;
        int32 tx, ty;

        mr_getScreenSize((int32 *)&scnw, (int32 *)&scnh);
        pscn = w_getScreenBuffer();

        temp_mr_screen_w = scnw;

        ch = (uint16)((*p << 8) + *(p + 1));

        chx = x;
        chy = y;
        while (ch) {
            X1 = Y1 = 0;
            totalIndex = totalPoint = 0;

            if ((ch == 0x0a) || (ch == 0x0d))  //换行直接返回
            {
                return 1;
            } else if (ch == CHR_SPACE)  //空格则空格
            {
                chx += g_nowUse.AsciiWidth;
                //超出屏幕范围检查
                if ((chx) > temp_mr_screen_w) return 1;
                goto next;
            } else if (ch == CHR_TAB) {
                chx += 4 * g_nowUse.AsciiWidth;
                //超出屏幕范围检查
                if ((chx) > temp_mr_screen_w) return 1;
                goto next;
            } else {
                current_bitmap = tsf_getCharBitmap(ch);

                fw = *current_bitmap;
                flen = *(current_bitmap + 1);
                current_bitmap += 2;
                if (fw == 0) fw = g_nowUse.GBWidth;
            }

            //超出屏幕范围检查
            if ((chx + fw) > temp_mr_screen_w) return 1;

            //绘制点阵
            totalPoint = fh * fw;
            totalIndex = 0;
            for (index_I = 0; index_I < flen; index_I++) {
                temp = current_bitmap[index_I];

                for (index_J = 0; index_J < 8; index_J++) {
                    tx = chx + X1, ty = chy + Y1;
                    totalIndex++;

                    if (tx < 0 || ty < 0 || tx > scnw - 1 || ty > scnh - 1) {
                    } else if (temp & masks[index_J]) {
                        *(pscn + (chy + Y1) * scnw + (chx + X1)) = color;
                    }
                    X1++;
                    if ((totalIndex % fw) == 0) {
                        Y1++;
                        X1 = 0;
                    }
                    if (totalIndex >= totalPoint) break;
                }
            }

            chx = chx + fw + TS_FONT_HMARGIN;  //字间距为 4
        next:
            p += 2;
            ch = (uint16)((*p << 8) + *(p + 1));
        }
    }

    return 1;
}

//从走往右换行绘制
int32 tsf_drawTextLeft(uint8 *pcText, int16 x, int16 y, mr_screenRectSt rect,
                       mr_colourSt colorst, uint16 flag) {
    if (!enable || !pcText || rect.w == 0 || rect.h == 0) {
        return -1;
    }

    {
        uint16 ch;
        const char *current_bitmap;
        uint8 *p = (uint8 *)pcText;
        int16 chx = x, chy = y;
        int32 totalIndex, totalPoint, X1, Y1, index_I, index_J;
        uint8 temp = 0;
        uint16 color = MAKERGB(colorst.r, colorst.g, colorst.b);
        int32 right = rect.x + rect.w, btm = rect.y + rect.h;
        int32 fw, fh = g_nowUse.fontHeight, flen;
        int32 lines = 0;
        int32 tx, ty;

        mr_getScreenSize((int32 *)&scnw, (int32 *)&scnh);
        pscn = w_getScreenBuffer();

        //生成unicode/GB编码值
        ch = (uint16)((*p << 8) + *(p + 1));
        while (ch) {
            if ((ch == 0x0a) || (ch == 0x0d)) {  //换行处理
                if (ch == 0x0d)                  //移除第二个换行符
                    p += 2;

                if (flag & TSF_CRLFNEWLINE) {
                    chy += (fh + TS_FONT_VMARGIN);
                    chx = x;
                    lines++;
                } else {
                    goto end;
                }

                goto next;
            } else if (ch == CHR_SPACE || ch == CHR_TAB) {  //空格、制表符 处理
                chx += (ch == CHR_SPACE ? g_nowUse.AsciiWidth
                                        : 4 * g_nowUse.AsciiWidth);

                if ((chx > right)) {  //自动换行属性
                    if ((TSF_AUTONEWLINE & flag)) {
                        chy += (fh + TS_FONT_VMARGIN);
                        chx = x;
                        lines++;
                    } else
                        goto end;
                }

                goto next;
            } else {  //其他字符
                current_bitmap = (char *)tsf_getCharBitmap(ch);

                fw = *current_bitmap;          //字符宽
                flen = *(current_bitmap + 1);  //点阵字节数
                current_bitmap += 2;
            }

            // if(chx > right && chy > btm)	//超出了绘制区域
            //	goto end;

            //测量换行
            if (((chx + fw) > right)) {
                if (flag & TSF_AUTONEWLINE) {
                    chy += (fh + TS_FONT_VMARGIN);
                    chx = x;
                    lines++;
                } else
                    goto end;
            }

            //填充点阵
            // if( ((chx + fw) <= right)
            //	&& (chx >= rect.x)
            //	&& ((chy + fh) <= btm)
            //	&& (chy >= rect.y)
            //	&& chx >= 0
            //	&& chy >= 0)
            {
                totalPoint = fh * fw;
                X1 = Y1 = 0;
                totalIndex = 0;

                for (index_I = 0; index_I < flen; index_I++)  //点阵占字节数
                {
                    temp = current_bitmap[index_I];

                    for (index_J = 0; index_J < 8; index_J++) {
                        tx = chx + X1, ty = chy + Y1;
                        totalIndex++;

                        if (tx < rect.x || ty < rect.y || tx > right ||
                            ty > btm) {
                            //
                        } else if (temp & masks[index_J]) {  //屏幕绘点
                            *(pscn + ty * scnw + tx) = color;
                        }
                        X1++;
                        if ((totalIndex % fw) == 0) {  //点阵换行
                            Y1++;
                            X1 = 0;
                        }
                        if (totalIndex >= totalPoint) break;
                    }
                }
            }

            //累计宽度
            chx = chx + fw + TS_FONT_HMARGIN;
        next:
            p += 2;  //下一个字符
            ch = (uint16)((*p << 8) + *(p + 1));
        }

    end:
        return (((lines << 20) & 0xFFF00000) | (p - pcText));
    }

    return 0;
}

//获取多行文本宽高
int32 tsf_textWidthHeightLines(uint8 *pcText, uint16 showWidth, int32 *width,
                               int32 *height, int32 *lines) {
    uint16 chU;
    int32 tempAdd = 0, tempWidth = 0;
    uint8 *tempChr = (uint8 *)pcText;
    uint8 *bmpPoint = NULL;
    int32 linewidth = showWidth;

    *width = *height = *lines = 0;

    if (!enable || !tempChr || showWidth == 0) {
        return -1;
    }

    chU = (uint16)((*tempChr << 8) + *(tempChr + 1));

    while (chU) {
        if (chU == CHR_SPACE)  //空格
        {
            tempAdd = g_nowUse.AsciiWidth;

            goto LineCheck;
        } else if (chU == CHR_TAB) {
            tempAdd = 4 * g_nowUse.AsciiWidth;

            goto LineCheck;
        } else if (chU == 0x0a || chU == 0x0d) {
            if (chU == 0x0d)  //移除第二个换行符
                tempChr += 2;
            goto NewLine;
        } else {
            bmpPoint = (uint8 *)tsf_getCharBitmap(chU);
            tempAdd = (*bmpPoint + TS_FONT_HMARGIN);
        }

    LineCheck:
        if (tempWidth + tempAdd > linewidth) {
        NewLine:
            *width = (tempWidth > *width) ? tempWidth : *width;
            *height += g_nowUse.fontHeight + TS_FONT_VMARGIN;

            (*lines)++;
            tempWidth = 0;
        } else {
            tempWidth += tempAdd;
        }

        //下一个字符
        tempChr += 2;
        chU = (uint16)((*tempChr << 8) + *(tempChr + 1));
    }

    *height += g_nowUse.fontHeight + TS_FONT_VMARGIN;
    *width = (tempWidth > *width) ? tempWidth : *width;
    (*lines)++;

    return 0;
}

int32 tsf_charWidthHeight(uint16 chU, int32 *width, int32 *height) {
    if (height) *height = g_nowUse.fontHeight;
    if (width) *width = *tsf_getCharBitmap(chU);
    return 0;
}

//获取单行文本宽高
int32 tsf_textWidthHeight(uint8 *pcText, int32 *width, int32 *height) {
    uint16 chU;
    uint8 *p = (uint8 *)pcText;
    uint8 *bmpPoint = NULL;
    int32 w = 0;

    if (!enable || !p) {
        return -1;
    }

    chU = (uint16)((*p << 8) + *(p + 1));
    while (chU) {
        if (chU == CHR_SPACE)  //空格	//|| (chU == 0x0a) || (chU == 0x0d)
        {
            w += g_nowUse.AsciiWidth;
        } else if (chU == CHR_TAB) {  //制表符 4空格代替
            w += 4 * g_nowUse.AsciiWidth;
        } else {
            bmpPoint = (uint8 *)tsf_getCharBitmap(chU);
            w += *bmpPoint + TS_FONT_HMARGIN;
        }

        p += 2;
        chU = (uint16)((*p << 8) + *(p + 1));
    }

    if (height)
        *height = g_nowUse.fontHeight;  // + TS_FONT_VMARGIN;	//包括间距
    if (width) *width = w;

    return MR_SUCCESS;
}

extern unsigned char font16_st[399063];

//初始化字库
int32 tsf_init(void) {
    uint8 *head = font16_st;

    enable = 0;  //可用标志为0
    memset(&g_nowUse, 0, sizeof(T_FONT_INFO));

    //读取unicode索引表信息
    g_nowUse.uIndexOff = *(int32 *)(head + 12);
    g_nowUse.uIndexLen = *(int32 *)(head + 16);
    g_nowUse.uIndexBuf = head + g_nowUse.uIndexOff;

    //读取点阵表信息
    g_nowUse.PointOff = *(int32 *)(head + 20);
    g_nowUse.PointLen = *(int32 *)(head + 24);
    g_nowUse.PointBuf = head + g_nowUse.PointOff;
    gMemLoad = TRUE;

    //字体尺寸信息
    g_nowUse.GBWidth = head[28];
    g_nowUse.AsciiWidth = head[29];
    g_nowUse.fontHeight = head[30];

    enable = 1;  //加载成功，可用

    return MR_SUCCESS;
}