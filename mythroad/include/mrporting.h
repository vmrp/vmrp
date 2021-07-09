
#ifndef _MRPORTING_H
#define _MRPORTING_H

#include "type.h"

#define MAKERGB565(r, g, b) (uint16_t)(((uint32_t)(r >> 3) << 11) | ((uint32_t)(g >> 2) << 5) | ((uint32_t)(b >> 3)))
#define PIXEL565R(v) ((((uint32_t)v >> 11) << 3) & 0xff)
#define PIXEL565G(v) ((((uint32_t)v >> 5) << 2) & 0xff)
#define PIXEL565B(v) (((uint32_t)v << 3) & 0xff)

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
    MR_NET_ID_MOBILE,  //移动
    MR_NET_ID_CN,      // 联通gsm
    MR_NET_ID_CDMA,    //联通CDMA
    MR_NET_ID_NONE,    //未插卡
    MR_NET_ID_OTHER    /*其他网络*/
};

enum {
    MR_EDIT_ANY,       //任何字符
    MR_EDIT_NUMERIC,   // 数字
    MR_EDIT_PASSWORD,  //密码，用"*"显示
    MR_EDIT_ALPHA
};

enum {
    MR_SIM_NEW,     //新手机第一次插入SIM卡
    MR_SIM_CHANGE,  //用户更换SIM卡
    MR_SIM_SAME     //未进行换卡操作
};

enum {
    MR_DIALOG_OK,  //对话框有"确定"键。
    MR_DIALOG_OK_CANCEL,
    MR_DIALOG_CANCEL,
    MR_DIALOG_NONE = 100
};

enum {
    MR_DIALOG_KEY_OK,
    MR_DIALOG_KEY_CANCEL
};

enum {
    MR_LOCALUI_KEY_OK,
    MR_LOCALUI_KEY_CANCEL,
    MR_LOCALUI_ACTIVE
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

enum {
    MR_DATA_ACCOUNT_OP_GET,
    MR_DATA_ACCOUNT_OP_SET
};

enum {
    DSM_ERROR_NO_ERROR = 0,
    DSM_ERROR_UNKNOW,
    DSM_ERROR_NO_SPACE,
    DSM_ERROR_TERMINATED
};

enum {
    MR_SMS_OP_GET_ME_SIZE,
    MR_SMS_OP_GET_SIM_SIZE,
    MR_SMS_OP_DELETE,
    MR_SMS_OP_GET_MSG_CONTENT
};

typedef enum {
    MR_SOUND_MIDI,
    MR_SOUND_WAV,
    MR_SOUND_MP3,
    MR_SOUND_PCM,  //8K
    MR_SOUND_M4A,
    MR_SOUND_AMR,
    MR_SOUND_AMR_WB
} MR_SOUND_TYPE;

typedef enum {
    MR_FONT_SMALL,
    MR_FONT_MEDIUM,
    MR_FONT_BIG
} MR_FONT_TYPE;

enum {
    MR_SEEK_SET,
    MR_SEEK_CUR,
    MR_SEEK_END
};

enum {
    MR_SOCK_STREAM,
    MR_SOCK_DGRAM
};

enum {
    MR_IPPROTO_TCP,
    MR_IPPROTO_UDP
};

enum {
    MR_ENCODE_ASCII,
    MR_ENCODE_UNICODE
};

typedef enum {
    IMG_BMP,  //BMP 图片
    IMG_JPG,  //jpg 图片
    IMG_PNG,  //png 图片
    IMG_GIF   //gif 图片
} IMG_TYPE;

typedef enum {
    SRC_NAME,   //传到移植接口是文件名
    SRC_STREAM  //传到移植接口的是图片数据流
} SRC_TYPE;

typedef enum {
    MR_CALL_RING,
    MR_SMS_RING,
    MR_ALARM_RING
} DSM_RING_TYPE;

typedef enum {
    MR_SCENE_NORMAL,
    MR_SCENE_MEETING,
    MR_SCENE_INDOOR,
    MR_SCENE_OUTDOOR,
    MR_SCENE_MUTE
} T_DSM_SCENE;

typedef struct
{
    int32 scene;
    int32 type;
    char* path;  //gb
} T_DSM_RING_SET;

#define DSM_ARTIST_LEN 100

typedef struct
{
    char artist[DSM_ARTIST_LEN + 2];  //big endian usc2
    int32 totaltime;                  //单位为s
} T_DSM_AUDIO_INFO;

typedef struct
{
    uint32 total;    //总的大小
    uint32 tunit;    //总大小的单位
    uint32 account;  //剩余空间的大小
    uint32 unit;     //剩余大小的单位
} T_DSM_FREE_SAPCE;

#define MR_SMS_ENCODE_FLAG 7
#define MR_SMS_REPORT_FLAG 8
#define MR_SMS_RESULT_FLAG 16

enum {
    MR_SOCKET_BLOCK,    //阻塞方式（同步方式）
    MR_SOCKET_NONBLOCK  //非阻塞方式（异步方式）
};

typedef struct
{
    uint16 year;   //年
    uint8 month;   //月
    uint8 day;     //日
    uint8 hour;    //时，24小时制
    uint8 minute;  //分
    uint8 second;  //秒
} mr_datetime;

typedef struct
{
    uint32 width;   //屏幕宽
    uint32 height;  //屏幕高
    uint32 bit;     //屏幕象素深度，单位bit
} mr_screeninfo;

typedef struct
{
    uint8 IMEI[16];       //IMEI len eq 15
    uint8 IMSI[16];       //IMSI len not more then 15
    char manufactory[8];  //厂商名，最大7个字符，空字节填\0
    char type[8];         //mobile type，最大7个字符，空字节填\0
    uint32 ver;           //SW ver
    uint8 spare[12];      //备用
} mr_userinfo;

typedef struct
{
    int32 socket;
    int32 port;
    int32 ip;
} mr_bind_st;


#define MR_GIF_SUPPORT_NO 3

typedef struct
{
    int32 width;   //图片的宽度
    int32 height;  //图片的高
    int32 img_type;
} T_DSM_IMG_INFO;

typedef struct
{
    char* src;       //文件名，或是数据流的buf的地址，如果是文件名，是GB格式
    int32 len;       //src所指的buf的大小
    int32 src_type;  //指明src中存放的是文件名，还是数据流
} T_DSM_GET_IMG_INFO;

typedef struct
{
    char* src;       //文件名，或是数据流的buf的地址，如果是文件名，是GB格式
    int32 len;       //src所指的buf的大小
    int32 width;     //用户图片显示的区域的宽度
    int32 height;    //用于图片显示的区域的高度
    int32 src_type;  //指明src中存放的是文件名，还是数据流
    char* dest;      //解码后的图片数据存放的buf
} T_DSM_IMG_DECODE;

typedef struct T_DSM_FRAME_INFO {
    int32 fwidth;                   //本帧的宽度
    int32 fheight;                  //本帧的高度
    int32 ox;                       //本帧左上角的x坐标(相对逻辑屏幕)
    int32 oy;                       //本帧左上角的y坐标(相对逻辑屏幕)
    int32 transparent_flag;         //是否需要透明显示
    int32 transparent_color;        //透明显示的颜色
    int32 delay_time;               //本帧显示的时间
    char* pdata;                    //解压好的图片数据
    struct T_DSM_FRAME_INFO* next;  //指向下一帧的数据结构
} T_DSM_FRAME_INFO;

typedef struct
{
    int32 id;
    int32 width;     //gif的宽度
    int32 height;    //gif的高度
    int32 bg_color;  //gif的背景色
    int32 frame_count;
    T_DSM_FRAME_INFO* first;  //指向gif的第一帧的数据结构
} T_DSM_GIF_HEADER;

typedef struct
{
    int32 width;   //gif的宽度
    int32 height;  //gif的高度
    int bg_color;  //gif的背景色
    char* pdata;   //解压好的图片数据
} T_DSM_PNG_HEADER;

typedef struct
{
    int32 id;
} T_DSM_GIF_ID;

#if 0  //取消
typedef struct
{
    uint32 mr_head; //Mythroad文件标签
    uint32 mri_len; //应用信息头长度
    uint32 app_len; //应用长度
    uint32 appid; //应用ID
    char filename[12]; //应用文件名
    uint16 appname[20]; //应用名，Unicode
    uint16 appversion[10]; //应用版本，Unicode
    uint16 vendor[20]; //开发商信息，Unicode
    uint16 description[40]; //应用描述，Unicode
    char mrdata[32]; //应用数据
}mr_appSt;
#endif

#define MR_FILE_RDONLY 1  //以只读的方式打开文件。
#define MR_FILE_WRONLY 2  //以只写的方式打开文件。
#define MR_FILE_RDWR 4    //以读写的方式打开文件。
#define MR_FILE_CREATE 8  //如果文件不存在，创建该文件。
#define MR_FILE_SHARD 16
#define MR_FILE_RECREATE 16  //无论文件存不存在，都重新创建该文件。
#define MR_FILE_COMMITTED 32

#define MR_IS_FILE 1     //文件
#define MR_IS_DIR 2      //目录
#define MR_IS_INVALID 8  //无效(非文件、非目录)


#define MR_SUCCESS 0  //成功
#define MR_FAILED -1  //失败
#define MR_IGNORE 1   //不关心
#define MR_WAITING 2  //异步(非阻塞)模式
//#define MR_NO_SUPPORT -2 //不支持

#define MR_PLAT_VALUE_BASE 1000  //用于某些返回值的基础值

/*定时器到期时调用定时器事件，Mythroad平台将对之进行处理。
p是启动定时器时传入的Mythroad定时器数据*/
extern int32 mr_timer(void);

/*在Mythroad平台中对按键事件进行处理，press = MR_KEY_PRESS按键按下，
= MR_KEY_RELEASE按键释放，key 对应的按键编码*/
extern int32 mr_event(int16 type, int32 param1, int32 param2);

/*退出Mythroad并释放相关资源*/
extern int32 mr_stop(void);

/****************外部接口定义*********************/

#if 0  //已取消
/*当启动Mythroad应用的时候，应该调用Mythroad的初始化函数，
用以对Mythroad平台进行初始化，并用在Mythroad平台上运行指
定的应用，app指向将要运行的游戏或应用的启动数据*/
extern int32 mr_start(mr_appSt* app);
#endif

int32 mr_start_dsm(char* filename, char* ext, char* entry);

/*注册固化应用*/
extern int32 mr_registerAPP(uint8* p, int32 len, int32 index);

#if 0  //已取消
/*取得应用列表
appList:指向已经安装未安装应用列表的第一个元素
appLen:应用的个数
注意:appList所指向的内存空间必须由调用此函数的程序员
释放
*/
extern int32 mr_getAppList(mr_appSt** appList, uint32* appLen);

/*取得应用说明*/
void mr_getAppInfo(char* info, mr_appSt *app);

/*删除指定的应用
app:该应用的数据指针
*/
extern int32 mr_uninstall(mr_appSt *app);
#endif

/*暂停应用*/
extern int32 mr_pauseApp(void);

/*恢复应用*/
extern int32 mr_resumeApp(void);

/*当手机收到短消息时调用该函数*/
extern int32 mr_smsIndiaction(uint8* pContent, int32 nLen, uint8* pNum, int32 type);

/*用户SIM卡变更*/
extern int32 mr_newSIMInd(int16 type, uint8* old_IMSI);

/*函数mr_initNetwork使用的回调函数定义*/
typedef int32 (*MR_INIT_NETWORK_CB)(int32 result);

/*函数mr_getHostByName使用的回调函数定义*/
typedef int32 (*MR_GET_HOST_CB)(int32 ip);

/*********************以下是抽象接口定义******************************/

/*调试打印*/
extern void mr_printf(const char* format, ...);

extern int32 mr_mem_get(char** mem_base, uint32* mem_len);
extern int32 mr_mem_free(char* mem, uint32 mem_len);

/*当使用本地屏幕缓冲时使用的接口*/
/*在屏幕上绘BMP*/
extern void mr_drawBitmap(uint16* bmp, int16 x, int16 y, uint16 w, uint16 h);

/*取得获取unicode码ch指向的字体的点阵信息，并告之
该字体的宽和高，获取到的点阵信息每一个bit表示
字体的一个象素，字体每行的象素必须按字节对其，
也就是说如果一个字体宽为12，则需要用两个字节
来表示该信息，第二个字节的后四个bit为0，从第三
个字节开始才表示下一行的点阵数据*/
extern const char* mr_getCharBitmap(uint16 ch, uint16 fontSize, int* width, int* height);


/*显示字符于屏幕，绘制左上角为x,y。color是565的RGB颜色 ch为字符unicode码*/
extern void mr_platDrawChar(uint16 ch, int32 x, int32 y, uint32 color);

/*启动定时器*/
extern int32 mr_timerStart(uint16 t);
/*停止定时器。*/
extern int32 mr_timerStop(void);
/*取得时间，单位ms*/
extern uint32 mr_getTime(void);
/*获取系统日期时间。*/
extern int32 mr_getDatetime(mr_datetime* datetime);
/*取得手机相关信息。*/
extern int32 mr_getUserInfo(mr_userinfo* info);
/*任务睡眠，单位ms*/
extern int32 mr_sleep(uint32 ms);
/*平台扩展接口*/
extern int32 mr_plat(int32 code, int32 param);
/*增强的平台扩展接口*/
typedef void (*MR_PLAT_EX_CB)(uint8* output, int32 output_len);
extern int32 mr_platEx(int32 code, uint8* input, int32 input_len, uint8** output, int32* output_len, MR_PLAT_EX_CB* cb);

/*文件和目录操作*/
extern int32 mr_ferrno(void);
extern int32 mr_open(const char* filename, uint32 mode);
extern int32 mr_close(int32 f);
extern int32 mr_info(const char* filename);
extern int32 mr_write(int32 f, void* p, uint32 l);
extern int32 mr_read(int32 f, void* p, uint32 l);
extern int32 mr_seek(int32 f, int32 pos, int method);
extern int32 mr_getLen(const char* filename);
extern int32 mr_remove(const char* filename);
extern int32 mr_rename(const char* oldname, const char* newname);
extern int32 mr_mkDir(const char* name);
extern int32 mr_rmDir(const char* name);

/*目录搜索开始*/
extern int32 mr_findStart(const char* name, char* buffer, uint32 len);
/*取得一个目录搜索结果*/
extern int32 mr_findGetNext(int32 search_handle, char* buffer, uint32 len);
/*目录搜索结束*/
extern int32 mr_findStop(int32 search_handle);

/*退出平台*/
extern int32 mr_exit(void);

extern void mr_panic(char* msg);
void dsm_prepare(void);

/*开始手机震动*/
extern int32 mr_startShake(int32 ms);
/*结束手机震动*/
extern int32 mr_stopShake(void);

/*播放音频数据*/
extern int32 mr_playSound(int type, const void* data, uint32 dataLen, int32 loop);
/*停止播放音频*/
extern int32 mr_stopSound(int type);

/*发送一条短消息*/
extern int32 mr_sendSms(char* pNumber, char* pContent, int32 flags);
/*拨打电话*/
extern void mr_call(char* number);
/*取得网络ID，0 移动，1 联通*/
extern int32 mr_getNetworkID(void);
/*连接WAP*/
extern void mr_connectWAP(char* wap);

extern int32 mr_sleep(uint32 ms);
extern int32 mr_getScreenInfo(mr_screeninfo* screeninfo);

/*GUI 接口*/
extern int32 mr_menuCreate(const char* title, int16 num);
extern int32 mr_menuSetItem(int32 menu, const char* text, int32 index);
extern int32 mr_menuShow(int32 menu);
/*设置选中项目，保留*/
extern int32 mr_menuSetFocus(int32 menu, int32 index);
extern int32 mr_menuRelease(int32 menu);
extern int32 mr_menuRefresh(int32 menu);

extern int32 mr_dialogCreate(const char* title, const char* text, int32 type);
extern int32 mr_dialogRelease(int32 dialog);
extern int32 mr_dialogRefresh(int32 dialog, const char* title, const char* text, int32 type);

extern int32 mr_textCreate(const char* title, const char* text, int32 type);
extern int32 mr_textRelease(int32 text);
extern int32 mr_textRefresh(int32 handle, const char* title, const char* text);

extern int32 mr_editCreate(const char* title, const char* text, int32 type, int32 max_size);
extern int32 mr_editRelease(int32 edit);
extern const char* mr_editGetText(int32 edit);

extern int32 mr_winCreate(void);
extern int32 mr_winRelease(int32 win);

/*Socket接口*/
extern int32 mythroad_initNetwork(MR_INIT_NETWORK_CB cb, const char* mode);
extern int32 mr_initNetwork(MR_INIT_NETWORK_CB cb, const char* mode);
extern int32 mythroad_getHostByName(const char* name, MR_GET_HOST_CB cb);
extern int32 mr_getHostByName(const char* name, MR_GET_HOST_CB cb);
extern int32 mr_closeNetwork(void);
extern int32 mr_socket(int32 type, int32 protocol);
extern int32 mr_connect(int32 s, int32 ip, uint16 port, int32 type);
extern int32 mr_closeSocket(int32 s);
extern int32 mr_recv(int32 s, char* buf, int len);
extern int32 mr_recvfrom(int32 s, char* buf, int len, int32* ip, uint16* port);
extern int32 mr_send(int32 s, const char* buf, int len);
extern int32 mr_sendto(int32 s, const char* buf, int len, int32 ip, uint16 port);
extern int32 mr_getSocketState(int s);

typedef struct
{
    int32 index;
    int8 type;
} T_DSM_GET_SMS_INFO_REQ;

typedef struct
{
    int32 index;
    int8 type;
} T_DSM_DELETE_SMS_REQ;
typedef enum {
    MR_SMS_NOBOX,
    MR_SMS_UNREAD,
    MR_SMS_INBOX,
    MR_SMS_OUTBOX,
    MR_SMS_DRAFTS,
    MR_SMS_AWAITS,
    MR_SMS_DATA,
    MR_SMS_UNSENT,
    MR_SMS_READED,
    MR_SMS_SENT
} MR_MSG_STATUS;

typedef enum {
    MR_SMS_STORAGE_SIM,
    MR_SMS_STORAGE_ME
} MR_SMS_STORAGE;

typedef enum {
    MR_SMS_NOT_READY = MR_PLAT_VALUE_BASE,
    MR_SMS_READY
} MR_SMS_STATUS;
typedef enum {
    MR_NORMAL_SCREEN = MR_PLAT_VALUE_BASE,
    MR_TOUCH_SCREEN,
    MR_ONLY_TOUCH_SCREEN
} MR_SCREEN_TYPE;

typedef enum {
    MR_CHINESE = MR_PLAT_VALUE_BASE,
    MR_ENGLISH,
    MR_TCHINESE,    //繁体
    MR_SPANISH,     //西班牙
    MR_DANISH,      //丹麦语
    MR_POLISH,      //波兰
    MR_FRENCH,      //法国
    MR_GERMAN,      //德国
    MR_ITALIAN,     //意大利
    MR_THAI,        //泰语
    MR_RUSSIAN,     // 俄罗斯
    MR_BULGARIAN,   //保加利亚
    MR_UKRAINIAN,   //乌克兰
    MR_PORTUGUESE,  //葡萄牙
    MR_TURKISH,     //土耳其
    MR_VIETNAMESE,  //越南
    MR_INDONESIAN,  //印度尼西亚
    MR_CZECH,       //捷克
    MR_MALAY,       //马来西亚
    MR_FINNISH,     //芬兰的
    MR_HUNGARIAN,   //匈牙利
    MR_SLOVAK,      //斯洛伐克
    MR_DUTCH,       //荷兰
    MR_NORWEGIAN,   //挪威
    MR_SWEDISH,     //瑞典
    MR_CROATIAN,    //克罗地亚
    MR_ROMANIAN,    //罗马尼亚
    MR_SLOVENIAN,   //斯洛文尼亚
    MR_GREEK,       //希腊语
    MR_HEBREW,      //希伯来
    MR_ARABIC,      //阿拉伯
    MR_PERSIAN,     //波斯
    MR_URDU,        //乌尔都语
    MR_HINDI,       //北印度
    MR_MARATHI,     //马拉地语(属印欧语系印度语族)
    MR_TAMIL,       //泰米尔语
    MR_BENGALI,     //孟加拉人(语
    MR_PUNJABI,     //印度西北部的一地方
    MR_TELUGU       //泰卢固语(印度东部德拉维拉语言)
} MR_LANGUAGE;

typedef enum {
    MR_IDLE_BG_PAPER,   /*背景*/
    MR_IDLE_SAVER_PAPER /*屏保*/
} MR_IDLE_PAPER_TYPE;

typedef enum {
    MR_SMS_ACTION_SAVE = MR_PLAT_VALUE_BASE + 1,
    MR_SMS_ACTION_DELETE
} MR_SMS_ACTION_TYPE;

enum {
    MR_MSDC_NOT_EXIST = MR_PLAT_VALUE_BASE,
    MR_MSDC_OK,
    MR_MSDC_NOT_USEFULL /*可能在usb模式导致无法操作t卡*/
};

// mr_plat枚举
#define MR_NES_SET_WRITE_ADDR 102
#define MR_NES_GET_READ_ADDR 103
#define MR_GOTO_BASE_WIN 104
#define MR_LIST_CREATE 1
#define MR_LIST_SET_ITEM 2
#define MR_SET_ACTIVE_SIM 1004
#define MR_SET_VOL 1302
#define MR_CONNECT 1001
#define MR_SET_SOCTIME 1002
#define MR_BIND_PORT 1003
#define MR_ACTIVE_APP 1003
#define MR_CHARACTER_HEIGHT 1201

// mr_platEx枚举
#define MR_MALLOC_EX 1001
#define MR_MFREE_EX 1002
#define MR_BACKSTAGE 1004
#define MR_SHOW_PIC 1005
#define MR_STOP_SHOW_PIC 1006
#define MR_APPEND_SMS 1007
#define MR_MALLOC_SCRRAM 1014
#define MR_FREE_SCRRAM 1015

#define MR_GET_CHARACTOR_INFO 1201
#define MR_SET_EVENT_FLAG 1202
#define MR_SEND_MMS 1203
#define MR_SWITCHPATH 1204
#define MR_CHECK_TOUCH 1205
#define MR_GET_HANDSET_LG 1206
#define MR_UCS2GB 1207
#define MR_SET_RING 1208
#define MR_GET_AUDIO_INFO 1209
#define MR_GET_KEYPAD_MAP 1210
#define MR_GET_RAND 1211
#define MR_GET_SCENE 1213
#define MR_SET_KEY_END 1214
#define MR_GET_CELL_ID_START 1215
#define MR_GET_CELL_ID_STOP 1216
#define MR_WEATHER_EXIT 1217
#define MR_GET_NES_DEFAULT_DIR 1220
#define MR_GET_APPLIST_TITLE 1221
#define MR_TURONBACKLIGHT 1222
#define MR_TUROFFBACKLIGHT 1223
#define MR_GET_CELL_INFO 1224
#define MR_GET_FILE_POS 1231
#define MR_GET_FREE_SPACE 1305
#define MR_GET_SIM_INFO 1307

#define MR_MEDIA_INIT 201
#define MR_MEDIA_BUF_LOAD 203
#define MR_MEDIA_FILE_LOAD 202
#define MR_MEDIA_PLAY_CUR_REQ 204
#define MR_MEDIA_PAUSE_REQ 205
#define MR_MEDIA_RESUME_REQ 206
#define MR_MEDIA_STOP_REQ 207
#define MR_MEDIA_CLOSE 208
#define MR_MEDIA_GET_STATUS 209
#define MR_MEDIA_SETPOS 210
#define MR_MEDIA_GETTIME 211
#define MR_MEDIA_GET_TOTAL_TIME 212
#define MR_MEDIA_GET_CURTIME 213
#define MR_MEDIA_GET_CURTIME_MSEC 215
#define MR_MEDIA_FREE 216
#define MR_MEDIA_ALLOC_INRAM 220
#define MR_MEDIA_FREE_INRAM 221

#define MR_MEDIA_OPEN_MUTICHANNEL 222
#define MR_MEDIA_PLAY_MUTICHANNEL 223
#define MR_MEDIA_STOP_MUTICHANNEL 224
#define MR_MEDIA_CLOSE_MUTICHANNEL 225

#define MR_GET_IMG_INFO 3001
#define MR_DECODE_IMG 3002
#define MR_DECODE_STATUS 3003
#define MR_GIF_DECODE 3004
#define MR_GIF_RELEASE 3005
#define MR_DRAW_BUFFER 3007
#define MR_GET_ACT_LAYER 3008
#define MR_DISPLAY_LCD 3009

#define ACI_MIDI_DEVICE 1
#define ACI_WAVE_DEVICE 2
#define ACI_MP3_DEVICE 3
#define ACI_AMR_DEVICE 4
#define ACI_PCM_DEVICE 5
#define ACI_M4A_DEVICE 6
#define ACI_AMR_WB_DEVICE 7

#define MR_MEDIA_IDLE 1
#define MR_MEDIA_INITED 2
#define MR_MEDIA_LOADED 3
#define MR_MEDIA_PLAYING 4
#define MR_MEDIA_PAUSED 5
#define MR_MEDIA_SUSPENDED 6
#define MR_MEDIA_SUSPENDING 7

#define MR_GET_FRAME_BUFFER 1001
#define MR_SEND_MMS 1203

#define MR_PHB_OPERATION_BASE 4000

#define MR_PHB_NONE 0
#define MR_PHB_SIM 1 /*对sim 卡操作*/
#define MR_PHB_NVM 2 /* 对nvm操作 */
#define MR_PHB_BOTH 3

#define MR_PHB_BY_NAME 1
#define MR_PHB_BY_NUMBER 2

#define MR_PHB_SEARCH_ENTRY (MR_PHB_OPERATION_BASE + 11)      //获得 记录通过 电话本排列的顺序index
#define MR_PHB_SET_ENTRY (MR_PHB_OPERATION_BASE + 12)         //SET 一条记录
#define MR_PHB_GET_ENTRY (MR_PHB_OPERATION_BASE + 16)         //get 一条记录
#define MR_PHB_COPY_ENTRY (MR_PHB_OPERATION_BASE + 17)        //拷贝一条记录
#define MR_PHB_SET_OWNER_ENTRY (MR_PHB_OPERATION_BASE + 21)   // 添加本机号码记录.指的是 电话本的 MSISDN 区
#define MR_PHB_GET_OWNER_ENTYR (MR_PHB_OPERATION_BASE + 22)   // 获得本机号码.
#define MR_PHB_DELETE_ENTRY_ALL (MR_PHB_OPERATION_BASE + 31)  // 删除所有记录
#define MR_PHB_GET_COUNT (MR_PHB_OPERATION_BASE + 32)         //得到记录数
#define MR_PHB_GET_STATUS (MR_PHB_OPERATION_BASE + 33)
#define MR_PHB_USE_LOCAL (MR_PHB_OPERATION_BASE + 41)
#define MR_PHB_USE_LOCAL_GET_ENTRY (MR_PHB_OPERATION_BASE + 42)
#define MR_PHB_USE_LOCAL_DESTORY (MR_PHB_OPERATION_BASE + 43)

//电话本操作返回值
#define MR_PHB_ERROR -1
#define MR_PHB_IDLE 0
#define MR_PHB_SUCCESS 0
#define MR_PHB_NOT_SUPPORT 1
#define MR_PHB_NOT_READY 2
#define MR_PHB_NOT_FOUND 3
#define MR_PHB_STORAGE_FULL 4
#define MR_PHB_NUMBER_TOO_LONG 5
#define MR_PHB_OUT_OF_INDEX 6

#define MR_PHB_MAX_NAME (36 * 2)    //暂时定位24个字节,12个汉字.
#define MR_PHB_MAX_NUMBER (48 * 2)  //暂时定位可输入40个字节.40个数字
#define MR_PHB_MAX_SEARCH_PATTERN (60 * 2)

#define MR_SET_OPERATION_BASE (5000)
#define MR_SET_GETDATETIME (MR_SET_OPERATION_BASE + 1)
#define MR_SET_SETDATETIME (MR_SET_OPERATION_BASE + 2)

#define MR_SET_SETALARMMRP (MR_SET_OPERATION_BASE + 14)
#define MR_SET_GETWEATHER (MR_SET_OPERATION_BASE + 15)
#define MR_SET_CREATWEATHER (MR_SET_OPERATION_BASE + 16)
#define MR_SET_DESTORYWEATHER (MR_SET_OPERATION_BASE + 17)
#define MR_GETWEATHERNOTIFY (MR_SET_OPERATION_BASE + 18)
#define MR_SET_GETWEATHERDESTOP (MR_SET_OPERATION_BASE + 19)

#define MR_LCD_ROTATE_NORMAL 0
#define MR_LCD_ROTATE_90 1
#define MR_LCD_ROTATE_180 2
#define MR_LCD_ROTATE_270 3
#define MR_LCD_MIRROR 4
#define MR_LCD_MIRROR_ROTATE_90 5
#define MR_LCD_MIRROR_ROTATE_180 6
#define MR_LCD_MIRROR_ROTATE_270 7

#define MR_FMGR_OPERATION_BASE 1400
#define MR_BROWSE_FMGR_FILTER_INIT (MR_FMGR_OPERATION_BASE + 1)
#define MR_BROWSE_FMGR_FILTER_SET (MR_FMGR_OPERATION_BASE + 2)
#define MR_BROWSE_FMGR_FILTER_CLEAR (MR_FMGR_OPERATION_BASE + 3)
#define MR_BROWSE_FMGR (MR_FMGR_OPERATION_BASE + 4)
#define MR_BROWSE_FMGR_GET_PATH (MR_FMGR_OPERATION_BASE + 5)
#define MR_BROWSE_FMGR_EXIT (MR_FMGR_OPERATION_BASE + 6)

#define MR_FMGR_TYPE_ALL 1
#define MR_FMGR_TYPE_FOLDER 2
#define MR_FMGR_TYPE_FOLDER_DOT 3
#define MR_FMGR_TYPE_UNKNOW 4
/* image */
#define MR_FMGR_TYPE_BMP 5
#define MR_FMGR_TYPE_JPG 6
#define MR_FMGR_TYPE_JPEG 7
#define MR_FMGR_TYPE_GIF 8
#define MR_FMGR_TYPE_PNG 9
#define MR_FMGR_TYPE_EMS 10
#define MR_FMGR_TYPE_ANM 11
#define MR_FMGR_TYPE_WBMP 12
#define MR_FMGR_TYPE_WBM 13
/* audio */
#define MR_FMGR_TYPE_IMY 14
#define MR_FMGR_TYPE_MID 15
#define MR_FMGR_TYPE_MIDI 16
#define MR_FMGR_TYPE_WAV 17
#define MR_FMGR_TYPE_AMR 18
#define MR_FMGR_TYPE_AAC 19
#define MR_FMGR_TYPE_DAF 20
#define MR_FMGR_TYPE_VM 21
#define MR_FMGR_TYPE_AWB 22
#define MR_FMGR_TYPE_AIF 23
#define MR_FMGR_TYPE_AIFF 24
#define MR_FMGR_TYPE_AIFC 25
#define MR_FMGR_TYPE_AU 26
#define MR_FMGR_TYPE_SND 27
#define MR_FMGR_TYPE_M4A 28
#define MR_FMGR_TYPE_MMF 29
#define MR_FMGR_TYPE_WMA 30
/* video */
#define MR_FMGR_TYPE_3GP 31
#define MR_FMGR_TYPE_MP4 32
#define MR_FMGR_TYPE_AVI 33
/* others */
#define MR_FMGR_TYPE_JAD 34
#define MR_FMGR_TYPE_JAR 35
#define MR_FMGR_TYPE_VCF 36
#define MR_FMGR_TYPE_VCS 37
#define MR_FMGR_TYPE_THEME 38
#define MR_FMGR_TYPE_MRP 39
#define MR_FMGR_TYPE_NES 40
#define MR_FMGR_TYPE_ZIP 41
#define MR_FMGR_TYPE_ZPK 42

typedef struct
{
    uint8* src;
    uint8* dest;
    uint16 src_width;
    uint16 src_height;
    uint16 src_pitch;
    uint16 dest_width;
    uint16 dest_height;
    uint16 output_clip_x1;
    uint16 output_clip_y1;
    uint16 output_clip_x2;
    uint16 output_clip_y2;
} mr_img_resize_struct;

typedef struct
{
    int32 appid;         //app id
    uint8 describe[20];  //应用标志符 - "ipqq"
    uint8* param;        //预留扩展用
} mr_backstage_st;

typedef enum {
    DSM_PIC_DESTID_IDLE_ICON,
    DSM_PIC_DESTID_IDLE_BG
} mr_pic_destId;

typedef struct
{
    int32 appid;
    int32 time;
    int32 img_type;
    int32 img_size;
    int32 width;
    int32 height;
    uint16 color;
    uint8* buff;
    uint8 destId;
} mr_pic_req;

typedef struct
{
    int socketId;       //socket 句柄
    int realSocketId;   //真实 socket 句柄（代理有效）
    int isProxy;        //代理标志
    int realConnected;  //真实连接上标志

    int socStat;
    int readStat;
    int writeStat;
} T_DSM_SOC_STAT;

typedef struct
{
    void* callBack;
} mr_socket_struct;

typedef struct
{
    int32 pos;  //单位,秒s.
} T_SET_PLAY_POS;

typedef struct
{
    int32 pos;
} T_MEDIA_TIME;

/*回调有两种可能的返回值：
ACI_PLAY_COMPLETE   0  //播放结束
ACI_PLAY_ERROR       1  //播放时遇到错误
Loop ：1，循环播放；0，不循环播放；2，PCM循环播放模式
Block：1，阻塞播放；0，不阻塞播放*/
typedef void (*ACI_PLAY_CB)(int32 result);

typedef struct
{
    ACI_PLAY_CB cb;  //回调函数
    int32 loop;
    int32 block;
} T_DSM_MEDIA_PLAY;

typedef struct
{
    char* src;
    int32 len;
    int32 src_type;  // MRAPP_SRC_TYPE
} MRAPP_IMAGE_ORIGIN_T;

typedef struct
{
    int32 width;   //图片的宽度
    int32 height;  //图片的高度
} MRAPP_IMAGE_SIZE_T;

typedef struct
{
    char* src;
    int32 src_len;
    int32 src_type;
    int32 ox;
    int32 oy;
    int32 w;
    int32 h;
} T_DRAW_DIRECT_REQ;

typedef struct
{
    uint8 level;
    uint8 current_band;
    uint8 rat;
    uint8 flag;
} T_RX;

typedef struct
{
    uint16 lac;
    uint16 cell_id;
    uint8 mnc[2];
    uint8 mcc[3];
    uint8 mnc3[4];
} T_DSM_CELL_INFO;

typedef struct
{
    uint32 total;
    uint32 tUnit;
    uint32 account;
    uint32 unit;
} T_DSM_DISK_INFO;

////---------------------------------
typedef enum {
    NETTYPE_WIFI = 0,
    NETTYPE_CMWAP = 1,
    NETTYPE_CMNET = 2,
    NETTYPE_UNKNOW = 3
} AND_NETTYPE;

typedef enum {
    DSM_SOC_CLOSE,
    DSM_SOC_OPEN,
    DSM_SOC_CONNECTING,
    DSM_SOC_CONNECTED,
    DSM_SOC_ERR
} T_DSM_SOC_STAT_ENUM;

typedef enum {
    DSM_SOC_NOREAD,
    DSM_SOC_READABLE
} T_DSM_SOC_READ_STAT;

typedef enum {
    DSM_SOC_NOWRITE,
    DSM_SOC_WRITEABLE
} T_DSM_SOC_WRITE_STAT;

typedef struct
{
    uint8 mod_id;
    uint8 identifier;
    int event_id;
    int result;
} mr_socket_event_struct;

typedef int32 (*startSkyLapp)(uint8* param);
void mr_registerLappEntry(void* entry);

int32 mr_cacheSync(void* addr, int32 len);

void mr_tm_init(void);
void mr_baselib_init(void);
void mr_tablib_init(void);
void mr_pluto_init(void);
void mythroad_init(void);
void mr_strlib_init(void);
void mr_iolib_target_init(void);
void mr_tcp_target_init(void);
void mr_socket_target_init(void);

extern int32 mr_rand(void);

#endif
