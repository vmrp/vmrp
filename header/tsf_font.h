// TSF点阵字库模块 [4/30/2012 JianbinZhu]
// 等宽字库 且ASCII为GB 宽度的一半

#ifndef _TS_FONT_H_
#define _TS_FONT_H_

#include "mr_types.h"

//字体绘制样式
#define TS_FT_NORMAL 0x0000   //常规（倘若用户填0就代表普通绘制）
#if 0                         //未实现
#define TS_FT_BLOD 0x0002     //粗体
#define TS_FT_ELASTIC 0x0004  //斜体
#endif
#define TSF_AUTONEWLINE 0x0008  //绘制区域内自动换行
#define TSF_CRLFNEWLINE 0x0010  //识别 \r \n 自动换行

//字符间距定义
#define TS_FONT_HMARGIN 0  //两字符间水平间距
#define TS_FONT_VMARGIN 2  //两字符间垂直间距

//计算返回值中的行数
#define TS_FONT_GET_LINE(i) (((unsigned int)((i)&0xFFF00000)) >> 20)

//计算返回值中的off值
#define TS_FONT_GET_OFF(i) ((unsigned int)((i)&0x000FFFFF))

/**
 * 从左往右画字符串,只支持Unicode编码
 * 
 * 输入:
 * pText:   必须是Unicode编码的字符串
 * x,y:       显示文本的左上角x,y坐标
 * r:      定义可视区域(位于可视区域外的部分将不被显示)
 * c:   定义画笔颜色
 * flag: 取值见定义:(可以用或操作符'|'来表示多种样式)
 *
 * 返回:
 * a) 一个32位的int值:
 *					  TS_FONT_GET_LINE(i) - 占用行数(未被忽略的字符均计算在内,半行算作一行)
 *					  TS_FONT_GET_OFF(i) - 第一个被忽略的字符的off值,若off==len,则说明全部字符都参与了运算
 *											   被忽略的字符是指: 此字符开始的之后的所有字符,均不可能在可视区域内.
 * b) -1 失败
 */
int32 tsf_drawTextLeft(uint8 *pcText, int16 x, int16 y, mr_screenRectSt rect, uint16 color, uint16 flag, void *userData);

/**
 * 绘制单行文本
 *
 * 遇到换行符立即返回
 *
 * flag 无效
 */
int32 tsf_drawText(uint8 *chr, int16 x, int16 y, uint16 color, void *userData);

/**
 * 获取多行文本宽高
 * 
 * 输入：
 *		showWidth：待显示文本区域的宽度，将根据该宽度对文本断行
 *
 * 输出：
 *		width：多行文本最宽的一行
 *		height：所有行总高度（包括行间距 TS_FONT_VMARGIN）
 *		lines：总行数
 *
 * 返回：-1 失败，0 成功
 */
int32 tsf_textWidthHeightLines(uint8 *pcText, uint16 showWidth,
                               int32 *width, int32 *height, int32 *lines);

/**
 * 获取单行文本宽高
 * 
 * 输出：
 *		width：多行文本最宽的一行
 *		height：所有行总高度（注意：不包括行间距 TS_FONT_VMARGIN）
 */
int32 tsf_textWidthHeight(uint8 *pcText, int32 *width, int32 *height);

int32 tsf_charWidthHeight(uint16 chU, int32 *width, int32 *height);

uint8 *tsf_getCharBitmap(uint16 ch);

typedef void (*setPixelFunc_t)(int32 x, int32 y, uint16 color, void *userData);
int32 tsf_init(uint32 scrW, uint32 scrH, setPixelFunc_t fn);

#endif