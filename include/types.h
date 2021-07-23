#ifndef _TYPES_H
#define _TYPES_H

#include <stdint.h>
#include <stdio.h>
#define LOG(format, ...) printf(">> " format "\n", ##__VA_ARGS__)

typedef uint64_t uint64; /* Unsigned 64 bit value */
typedef int64_t int64;   /* signed 64 bit value */

typedef uint32_t uint32; /* Unsigned 32 bit value */
typedef int32_t int32;   /* signed 32 bit value */
typedef uint8_t uint8;   /*Unsigned  Signed 8  bit value */
typedef int8_t int8;     /* Signed 8  bit value */
typedef uint16_t uint16; /* Unsigned 16 bit value */
typedef int16_t int16;   /* Signed 16 bit value */
typedef unsigned int uint;

typedef char* PSTR;
typedef const char* PCSTR;

typedef int BOOL;

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef NULL
#define NULL (void*)0
#endif

//typedef long int size_t;
typedef uint8 U8;
typedef unsigned int UINT;

#define MR_SUCCESS 0  //成功
#define MR_FAILED -1  //失败
#define MR_IGNORE 1   //不关心
#define MR_WAITING 2  //异步(非阻塞)模式

enum {
    MR_KEY_0,            //按键 0
    MR_KEY_1,            //按键 1
    MR_KEY_2,            //按键 2
    MR_KEY_3,            //按键 3
    MR_KEY_4,            //按键 4
    MR_KEY_5,            //按键 5
    MR_KEY_6,            //按键 6
    MR_KEY_7,            //按键 7
    MR_KEY_8,            //按键 8
    MR_KEY_9,            //按键 9
    MR_KEY_STAR,         //按键 *
    MR_KEY_POUND,        //按键 #
    MR_KEY_UP,           //按键 上
    MR_KEY_DOWN,         //按键 下
    MR_KEY_LEFT,         //按键 左
    MR_KEY_RIGHT,        //按键 右
    MR_KEY_POWER,        //按键 挂机键
    MR_KEY_SOFTLEFT,     //按键 左软键
    MR_KEY_SOFTRIGHT,    //按键 右软键
    MR_KEY_SEND,         //按键 接听键
    MR_KEY_SELECT,       //按键 确认/选择（若方向键中间有确认键，建议设为该键）
    MR_KEY_VOLUME_UP,    //按键 侧键上
    MR_KEY_VOLUME_DOWN,  //按键 侧键下
    MR_KEY_CLEAR,
    MR_KEY_A,        //游戏模拟器A键
    MR_KEY_B,        //游戏模拟器B键
    MR_KEY_CAPTURE,  //拍照键
    MR_KEY_NONE      //按键 保留
};

enum {
    MR_KEY_PRESS,      /*0*/
    MR_KEY_RELEASE,    /*1*/
    MR_MOUSE_DOWN,     /*2*/
    MR_MOUSE_UP,       /*3*/
    MR_MENU_SELECT,    /*4*/
    MR_MENU_RETURN,    /*5*/
    MR_DIALOG_EVENT,   /*6*/
    MR_SMS_INDICATION, /*7*/
    MR_EVENT_EXIT,     /*8*/
    MR_EXIT_EVENT = 8, /*8*/
    MR_SMS_RESULT,     /*9*/
    MR_LOCALUI_EVENT,  /*10*/
    MR_OSD_EVENT,      /*11*/
    MR_MOUSE_MOVE,     /*12*/
    MR_ERROR_EVENT,    /*13执行异常通过这个事件来通知*/
    MR_PHB_EVENT,
    MR_SMS_OP_EVENT,
    MR_SMS_GET_SC,
    MR_DATA_ACCOUNT_EVENT,
    MR_MOTION_EVENT
};

typedef struct {
    uint16 year;   //年
    uint8 month;   //月
    uint8 day;     //日
    uint8 hour;    //时，24小时制
    uint8 minute;  //分
    uint8 second;  //秒
} mr_datetime;

typedef int32 (*MR_INIT_NETWORK_CB)(int32 result);
typedef int32 (*MR_GET_HOST_CB)(int32 ip);

#endif