#ifndef MRC_BASE_H
#define MRC_BASE_H

/*
本头文件中包括了mythroad直接支持的各种函数调用，
以及入口函数。
*/
#ifndef SIM_MOD
	typedef  unsigned long long  uint64;      /* Unsigned 64 bit value */
	typedef  long long                int64;      /* signed 64 bit value */
#else
	typedef	unsigned _int64	uint64;
	typedef	 _int64	int64;
#endif
typedef  unsigned short     uint16;      //有符号16bit整型
typedef  unsigned long int  uint32;      //无符号32bit整型
typedef  long int                int32;      //有符号32bit整型
typedef  unsigned char      uint8;        //无符号8bit整型
typedef  signed char          int8;        //有符号8bit整型
typedef  signed short         int16;       //有符号16bit整型

#define MR_SUCCESS  0    //成功
#define MR_FAILED   -1    //失败
#define MR_IGNORE   1     //不关心
#define MR_WAITING   2     //异步(非阻塞)模式

#ifndef NULL
#define NULL (void*)0
#endif
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#ifdef MR_SPREADTRUM_MOD
#pragma no_check_stack
#endif

enum {
   MR_KEY_0,               //按键 0
   MR_KEY_1,               //按键 1
   MR_KEY_2,               //按键 2
   MR_KEY_3,               //按键 3
   MR_KEY_4,               //按键 4
   MR_KEY_5,               //按键 5
   MR_KEY_6,               //按键 6
   MR_KEY_7,               //按键 7
   MR_KEY_8,               //按键 8
   MR_KEY_9,               //按键 9
   MR_KEY_STAR,            //按键 *
   MR_KEY_POUND,           //按键 #
   MR_KEY_UP,              //按键 上
   MR_KEY_DOWN,            //按键 下
   MR_KEY_LEFT,            //按键 左
   MR_KEY_RIGHT,           //按键 右
   MR_KEY_POWER,           //按键 挂机键
   MR_KEY_SOFTLEFT,        //按键 左软键
   MR_KEY_SOFTRIGHT,       //按键 右软键
   MR_KEY_SEND,            //按键 接听键
   MR_KEY_SELECT,          //按键 确认/选择（若方向键中间有确认键，建议设为该键）
   MR_KEY_VOLUME_UP,          //按键 侧键上
   MR_KEY_VOLUME_DOWN,          //按键 侧键下
   MR_KEY_NONE             //按键 保留
};

enum {
   MR_NET_ID_MOBILE,                  //移动
   MR_NET_ID_CN,          // 联通gsm
   MR_NET_ID_CDMA,       //联通CDMA
   MR_NET_ID_NONE       //未插卡
};

enum {
   MR_EDIT_ANY,                  //任何字符
   MR_EDIT_NUMERIC,          // 数字
   MR_EDIT_PASSWORD       //密码，用"*"显示
};

enum {
   MR_SIM_NEW,     //新手机第一次插入SIM卡
   MR_SIM_CHANGE, //用户更换SIM卡
   MR_SIM_SAME    //未进行换卡操作
};

enum {
   MR_DIALOG_OK,                   //对话框有"确定"键。
   MR_DIALOG_OK_CANCEL,    //对话框有"确定" "取消"键。
   MR_DIALOG_CANCEL           //对话框有"返回"键。
};

enum {
   MR_DIALOG_KEY_OK,         //对话框/文本框等的"确定"键被点击(选择)
   MR_DIALOG_KEY_CANCEL  //对话框/文本框等的"取消"("返回")键被点击(选择)
};

enum {
   MR_LOCALUI_KEY_OK,       //本地控件的"确定"键被点击(选择)
   MR_LOCALUI_KEY_CANCEL//本地控件的"取消"("返回")键被点击(选择)
};


enum {
	MR_KEY_PRESS, 	//按键按下
	MR_KEY_RELEASE, //按键释放
	MR_MOUSE_DOWN, 	//鼠标按下
	MR_MOUSE_UP, 	//鼠标释放
	MR_MENU_SELECT, //
	MR_MENU_RETURN, //
	MR_DIALOG_EVENT, //
	MR_EVENT01, //
	MR_EXIT_EVENT, //
	MR_EVENT02, //
	MR_LOCALUI_EVENT, //
	MR_OSD_EVENT, //
	MR_MOUSE_MOVE, //
	MR_ERROR_EVENT, //*13执行异常通过这个事件来通知*/
	MR_PHB_EVENT,//
	MR_SMS_OP_EVENT,//
	MR_SMS_GET_SC,//
	MR_DATA_ACCOUNT_EVENT,//
	MR_MOTION_EVENT,//

	MR_TIMER_EVENT = 1001,
    MR_NET_EVENT
};

typedef enum 
{
   MR_SOUND_MIDI,
   MR_SOUND_WAV,
   MR_SOUND_MP3,
   MR_SOUND_PCM, //8K 16bit
   MR_SOUND_M4A,
   MR_SOUND_AMR,
   MR_SOUND_AMR_WB
}MR_SOUND_TYPE;

typedef enum 
{
   MR_FONT_SMALL,
   MR_FONT_MEDIUM,
   MR_FONT_BIG
}MR_FONT_TYPE;

enum
{
   MR_SEEK_SET,             //从文件起始开始
   MR_SEEK_CUR,             //从当前位置开始
   MR_SEEK_END             //从文件末尾开始
};

enum
{
   MR_SOCK_STREAM,
   MR_SOCK_DGRAM
};

enum
{
   MR_IPPROTO_TCP,
   MR_IPPROTO_UDP
};

enum
{
   MR_ENCODE_ASCII,
   MR_ENCODE_UNICODE
};

enum {
   MR_SOCKET_BLOCK,          //阻塞方式（同步方式）
   MR_SOCKET_NONBLOCK       //非阻塞方式（异步方式）
};

enum {
   BM_OR,         //SRC .OR. DST*   半透明效果
   BM_XOR,        //SRC .XOR. DST*
   BM_COPY,       //DST = SRC*      覆盖
   BM_NOT,        //DST = (!SRC)*
   BM_MERGENOT,   //DST .OR. (!SRC)
   BM_ANDNOT,     //DST .AND. (!SRC)
   BM_TRANSPARENT, //透明色不显示，图片的第一个象素（左上角的象素）是透明色
   BM_AND,
   BM_GRAY,
   BM_REVERSE
};

#define MR_IS_FILE     1      //文件
#define MR_IS_DIR      2      //目录
#define MR_IS_INVALID  8  //无效(非文件、非目录)

#define MR_FILE_RDONLY         1//以只读的方式打开文件。
#define MR_FILE_WRONLY        2//以只写的方式打开文件。
#define MR_FILE_RDWR             4//以读写的方式打开文件。
#define MR_FILE_CREATE          8//如果文件不存在，创建该文件。

/*
 *  zefang_wang 2010.12.21 :
 *    这个值之前定义有错误， 16 在底层的实现为 SHARE_OPEN，
 *    但是之前被定义成了   RECREATE.
 */

#define MR_FILE_SHARE_OPEN      16// 一边写， 一边读。

#define DRAW_TEXT_EX_IS_UNICODE          1 //是否使用UNICODE码, 网络字节序
#define DRAW_TEXT_EX_IS_AUTO_NEWLINE    2 //是否自动换行

#define MR_PLAT_VALUE_BASE 1000    //用于某些返回值的基础值


typedef struct
{
   int32 socket;
   int32 port;
}mr_bind_st;

typedef struct
{
   uint16 year;                 //年
   uint8  month;                //月
   uint8  day;                  //日
   uint8  hour;                 //时，24小时制
   uint8  minute;               //分
   uint8  second;               //秒
}mr_datetime;

typedef struct
{
   uint32 width;                  //屏幕宽
   uint32 height;                 //屏幕高
   uint32 bit;                    //屏幕象素深度，单位bit
}mr_screeninfo;


typedef struct {
   uint16            w;           //图片宽
   uint16            h;           //图片高
   uint32            buflen;  //图片缓冲长度
   uint32            type;     //图片缓冲类型
   uint16*            p;        //图片缓冲指针
}mr_bitmapSt;

typedef struct {
   uint16*            p;        //图片缓冲指针
   uint16            w;           //图片宽
   uint16            h;           //图片高
   uint16            x;
   uint16            y;
}mr_bitmapDrawSt;

typedef struct {
   uint16            x;
   uint16            y;
   uint16            w;
   uint16            h;
}mr_screenRectSt;

typedef struct {
   uint8            r;
   uint8            g;
   uint8            b;
}mr_colourSt;

typedef struct {
   uint16            h;
}mr_spriteSt;

typedef struct  {
   int16            x;
   int16            y;
   uint16            w;
   uint16            h;
   int16            x1;
   int16            y1;
   int16            x2;
   int16            y2;
   uint16            tilew;
   uint16            tileh;
}mr_tileSt;


/********************************C库函数********************************/
/*
一般不推荐在mythroad代码中使用C标准的库函数，
一些C标准的库函数会导致mythroad代码的链接失
败。虽然使用C标准库函数是不推荐的，但在许
多情况下使用C标准库函数的应用也是可以运行
的，但使用未经验证的C标准库函数，可能会由
于不被手机支持而引发死机等问题。mythroad平台
提供一些最为常用的C库函数，请尽量使用这些
函数。
*/

/*该函数功能与printf函数相似，区别是本函数的输出
信息将打印在手机的trace上*/
extern void (*mrc_printf)(const char *format,...);

/*
这段宏可以将源代码中的C标准的库函数替换为
mythroad平台支持的对应函数。
*/

//#define MEM_LEAK_DEBUG
#if defined SDK_MOD &&  defined MEM_LEAK_DEBUG
void *mrc_mallocEx(int size, char* file, int line);
#define malloc(size) mrc_mallocEx(size, __FILE__, __LINE__)
#define free(p) {\
	mrc_free(p);\
	mrc_printf("free,%lu,FILE:%s,LINE:%d", p, __FILE__, __LINE__);\
}
#else	

#define malloc   mrc_malloc   
#define free     mrc_free     
#endif /* defined SDK_MOD &&  defined MEM_LEAK_DEBUG */


#define strchr   mrc_strchr   
#define memcpy   mrc_memcpy   
#define memmove  mrc_memmove  
#define strcpy   mrc_strcpy   
#define strncpy  mrc_strncpy  
#define strcat   mrc_strcat   
#define strncat  mrc_strncat  
#define memcmp   mrc_memcmp   
#define strcmp   mrc_strcmp   
#define strncmp  mrc_strncmp  
#define strcoll  mrc_strcoll  
#define memchr   mrc_memchr   
#define memset   mrc_memset   
#define strlen   mrc_strlen   
#define strstr   mrc_strstr   
#define sprintf  mrc_sprintf             
#define atoi     mrc_atoi     
#define strtoul  mrc_strtoul  

extern void *(*MR_MEMCPY)(void * s1, const void * s2, int n);
extern void *(*MR_MEMMOVE)(void * s1, const void * s2, int n);
extern char *(*MR_STRCPY)(char * s1, const char * s2);
extern char *(*MR_STRNCPY)(char * s1, const char * s2, int n);
extern char *(*MR_STRCAT)(char * s1, const char * s2);
extern char *(*MR_STRNCAT)(char * s1, const char * s2, int n);
extern int (*MR_MEMCMP)(const void * s1, const void * s2, int n);
extern int (*MR_STRCMP)(const char * s1, const char * s2);
extern int (*MR_STRNCMP)(const char * s1, const char * s2, int n);
extern int (*MR_STRCOLL)(const char * s1, const char * s2);
extern void *(*MR_MEMCHR)(const void * s, int c, int n);
extern void *(*MR_MEMSET)(void * s, int c, int n);
extern int (*MR_STRLEN)(const char * s);
extern char *(*MR_STRSTR)(const char * s1, const char * s2);
extern int (*MR_SPRINTF)(char * s, const char * format, ...);
extern int (*MR_ATOI)(const char * nptr);
extern unsigned long int (*MR_STRTOUL)(const char * nptr, char ** endptr, int base);

extern void* mrc_malloc(int size);
extern void mrc_free(void *address);
extern void mrc_freeEx(void *address);//专给调试使用的函数，不做memset
extern const char *mrc_strchr(const char *src,int c);
extern int32 mrc_wstrlen(char * txt);

#define mrc_memcpy(s1, s2, n)       MR_MEMCPY(s1, s2, n)
#define mrc_memmove(s1, s2, n)   MR_MEMMOVE(s1, s2, n)
#define mrc_strcpy(s1, s2)              MR_STRCPY(s1, s2)
#define mrc_strncpy(s1, s2, n)        MR_STRNCPY(s1, s2, n)
#define mrc_strcat(s1, s2)               MR_STRCAT(s1, s2)
#define mrc_strncat(s1, s2, n)         MR_STRNCAT(s1, s2, n)
#define mrc_memcmp(s1, s2, n)      MR_MEMCMP(s1, s2, n)
#define mrc_strcmp(s1, s2)              MR_STRCMP(s1, s2)
#define mrc_strncmp(s1, s2, n)         MR_STRNCMP(s1, s2, n)
#define mrc_strcoll(s1, s2)               MR_STRCOLL(s1, s2)

#define mrc_memchr(s1, c, n)          MR_MEMCHR(s1, c, n)
#define mrc_memset(s1, c, n)          MR_MEMSET(s1, c, n)
#define mrc_strlen(s)                       MR_STRLEN(s)
#define mrc_strstr(s1, s2)               MR_STRSTR(s1, s2)
#define mrc_sprintf                         MR_SPRINTF
#define mrc_atoi(s1)                       MR_ATOI(s1)
#define mrc_strtoul(s1, s2, n)         MR_STRTOUL(s1, s2, n)

#define MR_MALLOC(size) mrc_malloc(size)
#define MR_FREE(p, size) mrc_free(p)
/********************************C库函数结束********************************/

/*取得获取unicode码ch指向的字体的点阵信息，并告之
该字体的宽和高，获取到的点阵信息每一个bit表示
字体的一个象素，字体每行的象素必须按字节对其，
也就是说如果一个字体宽为12，则需要用两个字节
来表示该信息，第二个字节的后四个bit为0，从第三
个字节开始才表示下一行的点阵数据*/
char *mrc_getCharBitmap(uint16 ch, uint16 fontSize, int *width, int *height);

/********************************文件接口********************************/
/*
该函数用于调试使用，返回的是最后一次操作文件
失败的错误信息，返回的错误信息具体含义与平台
上使用的文件系统有关。
该函数可能被实现为总是返回MR_SUCCESS。
返回:
      最后一次操作文件失败的错误信息
*/
int32 mrc_ferrno(void);

/*
以mode方式打开文件，如果文件不存在，根据mode值
判断是否创建之。
输入参数
参数	说明
返回说明
返回状态	说明 
非 NULL	文件句柄
NULL	失败（注意，这里与其他接口不一样）

输入:
filename	文件名
mode	文件打开方式
         mode取值
                MR_FILE_RDONLY   //以只读的方式打开文件。
                MR_FILE_WRONLY   //以只写的方式打开文件。
                                    （这个方式可能被实现为与
                                    MR_FILE_RDWR相同的操作）
                MR_FILE_RDWR      //以读写的方式打开文件。
                MR_FILE_CREATE     //如果文件不存在，创建
                                    该文件，该参数不会单独出现
                                    ，只能与其他值一同出现（使
                                    用"或"运算）
               mode可能的取值：
               a、	前三个参数的其中一个
               b、	前三个参数的其中一个和MR_FILE_CREATE的"或"值
返回:
非 NULL	       文件句柄
NULL	            失败（注意，这里与其他接口不一样）
*/
int32 mrc_open(const char* filename,  uint32 mode);

/*
关闭文件。
输入:
f	文件句柄
返回:
MR_SUCCESS	成功
MR_FAILED	失败
*/
int32 mrc_close(int32 f);

/*
取得文件类型信息。
输入:
filename	文件名
返回:
      MR_IS_FILE     1//是文件
      MR_IS_DIR      2//是目录
      MR_IS_INVALID  8//文件不存在，或既不是文件也不是目录
*/
int32 mrc_fileState(const char* filename);

/*
写文件
输入:
f	文件句柄
p	待写入数据存放地址
l	待写入数据长度
返回:
      >0                   确切写入的字节数
      MR_FAILED      失败
*/
int32 mrc_write(int32 f,void *p,uint32 l);

/*
读取文件的内容到指定的缓冲。
输入:
f	文件句柄
p	文件缓存地址
l	缓冲长度
返回:
      >=0                确切读取的字节数
      MR_FAILED      失败
*/
int32 mrc_read(int32 f,void *p,uint32 l);

/*
读取文件的所有内容到申请的内存中。
输入:
filename	文件名
输出:
len           读取到的内容长度
返回:
      非NULL         指向读取到的内容的指针，该内存需要
                              调用者释放
      NULL              失败
*/
void* mrc_readAll(const char* filename, uint32 *len);


/*
设置文件指针。
输入:
f	文件句柄
pos	文件指针位置
method	可能的取值为：
   MR_SEEK_SET, 
   MR_SEEK_CUR, 
   MR_SEEK_END
返回:
      MR_SUCCESS  成功
      MR_FAILED   失败
*/
int32 mrc_seek(int32 f, int32 pos, int method);

/*
取得文件长度。
输入:
filename	文件名 
返回:
      >=0   文件长度
      MR_FAILED   失败/文件不存在
*/
int32 mrc_getLen(const char* filename);

/*
删除文件。
输入:
filename	文件名
返回:
      MR_SUCCESS  成功
      MR_FAILED   失败
*/
int32 mrc_remove(const char* filename);

/*
文件重命名。
输入:
oldname	旧文件名
newname	新文件名
返回:
      MR_SUCCESS  成功
      MR_FAILED   失败
*/
int32 mrc_rename(const char* oldname, const char* newname);

/*
创建目录。
输入:
name	目录名
返回:
      MR_SUCCESS  成功
      MR_FAILED   失败
*/
int32 mrc_mkDir(const char* name);

/*
删除目录以及目录下面的文件和子目录。
输入:
name	目录名
返回:
      MR_SUCCESS  成功
      MR_FAILED   失败
*/
int32 mrc_rmDir(const char* name);

/*
准备搜索name指定的目录，当dsm调用该函数后，系统
初始化一个目录搜索，并返回第一个目录搜索的结果
，每当dsm调用一次mr_c_findGetNext函数，系统返回下一个
该目录下的文件或一级子目录名。该函数只返回查找
句柄。当name为空字符串""时（注意name指向空串，但
name不是NULL），搜索Mythroad平台引擎的文件当前目录。
如：若手机以"/dsmdata/"作为Mythroad平台引擎的文件当前
目录，当name为空字符串时，搜索目录"/dsmdata"。
例：一个目录下有文件："a.bmp"、"b.mrp"；目录"data"，则
mr_c_findStart返回查找句柄和"a.bmp"/handle，紧接着的mr_c_findGetNext
返回"b.mrp"/MR_SUCCESS、"data"/MR_SUCCESS和XX(无效)/MR_FAILED。
输入:
name	目录名
len	缓冲区大小
输出:
buffer  缓冲区，用于存放查找成功时第一个文件名或一级
            子目录名
返回:
      >0                  查找句柄，供mr_c_findGetNext、mr_c_findStop函数使用
      MR_FAILED      失败
*/
int32 mrc_findStart(const char* name, char* buffer, uint32 len);

/*
取得一个目录搜索的结果。将结果放置于buffer中。当
目录中的结果都遍历过后，返回MR_FAILED。
这里需要注意的是，使用mr_c_findGetNext获得的子目录不
能是"."和".."。
输入:
   search_handle	调用mr_c_findStart时返回的查找句柄
   len	缓冲区大小
输出:
   buffer  缓冲区，用于存放查找成功时文件名或一级子目录名
返回:
      MR_SUCCESS  搜索成功
      MR_FAILED   搜索结束或搜索失败
*/
int32 mrc_findGetNext(int32 search_handle, char* buffer, uint32 len);

/*
目录搜索结束。中止一个mr_c_findStart开启的目录搜索。
输入:
search_handle        调用mr_findStart时返回的查找句柄
返回:
      MR_SUCCESS  成功
      MR_FAILED   失败
*/
int32 mrc_findStop(int32 search_handle);


/********************************绘图接口********************************/


/*
将指定字符（仅支持unicode）绘制于屏幕指定区域，区域
外的部分不显示；
输入:
chr:            待显示的字符unicode指针(大端)
x, y:             待显示的字符左上角x, y
rect:             显示的字符限制范围
colorst:          字体颜色
font:              字体大小，可能的值是   
                        MR_FONT_SMALL
                        MR_FONT_MEDIUM
                        MR_FONT_BIG
返回值:
   MR_SUCCESS  操作成功，字符为\00\00时也返回成功，但没有
                         实质显示操作；
   MR_FAILED      操作失败，字符在字库中未找到会返回该值；
*/
int32 mrc_drawChar(uint8* chr, int16 x, int16 y, mr_screenRectSt rect, mr_colourSt colorst, uint16 font);


/*
将指定文本绘制于屏幕指定位置。
输入:
pcText:         待显示的字符串
x, y:             待显示的文本左上角x, y
r, g, b:          字体颜色r,g,b，r,g,b的取值范围：0~255，下同。
is_unicode:    是否是unicode，TRUE(1)表示使用unicode编码，FALSE(0)表
                     示使用GB2312编码。
font:              字体大小，可能的值是   
                        MR_FONT_SMALL
                        MR_FONT_MEDIUM
                        MR_FONT_BIG
返回值:
   MR_SUCCESS  操作成功
   MR_FAILED      操作失败
*/
int32 mrc_drawText(char* pcText, int16 x, int16 y, uint8 r, uint8 g, uint8 b, int is_unicode, uint16 font);

/*
与函数mrc_drawText功能相似，不同点在于mrc_drawText将
显示的字符限制在左上角为（x, y），宽高为（w, h）
的矩形范围之内。
由于早期mythroad版本，应用使用该函数时需要附带
编码转换表，使用该函数将使目标代码增大约16K。
1936及其之后版本中:不自动换行时可以显示半个字
符。
1935版本无法显示半个字符。
输入:
pcText:         待显示的字符串
x, y:             待显示的文本左上角x, y
rect:             显示的字符限制范围
colorst:          字体颜色
font:              字体大小，可能的值是   
                        MR_FONT_SMALL
                        MR_FONT_MEDIUM
                        MR_FONT_BIG
flag：可以取如下的值，也可以是这些值的相加：
          DRAW_TEXT_EX_IS_UNICODE          1 //是否使用UNICODE码, 网络字节序
          DRAW_TEXT_EX_IS_AUTO_NEWLINE    2 //是否自动换行
返回值:
    指示出在屏幕上第一个未完整显示字符的索引，
该索引是Text的unicode索引值。即使函数使用gb输入字
符串，函数返回的索引值也是根据该字符串转换为
unicode串后的索引值。若所有字符都能完整显示，则
返回该字串转换为unicode串后的长度。
*/
int32 mrc_drawTextEx(char* pcText, int16 x, int16 y, mr_screenRectSt rect, mr_colourSt colorst, int flag, uint16 font);


/*
 *  这个函数直接使用VM的函数来画图。
 */

int32 mrc_drawTextExVM(char* pcText, int16 x, int16 y, mr_screenRectSt rect, mr_colourSt colorst, int flag, uint16 font);


/*
与函数mrc_drawText功能相似，不同点在于mrc_drawTextLeft
函数不支持GB，所以比较节省内存。
输入:
pcText:         待显示的字符串
x, y:             待显示的文本左上角x, y
rect:             显示的字符限制范围
colorst:          字体颜色
font:              字体大小，可能的值是   
                        MR_FONT_SMALL
                        MR_FONT_MEDIUM
                        MR_FONT_BIG
flag：可以取如下的值，也可以是这些值的相加：
          DRAW_TEXT_EX_IS_AUTO_NEWLINE    2 //是否自动换行
返回值:
    指示出在屏幕上第一个未完整显示字符的索引(字节)，
该索引是Text的unicode索引值。若所有字符都能完整
显示，则返回该字串转换为unicode串后的长度。
*/
int32 mrc_drawTextLeft(char* pcText, int16 x, int16 y, mr_screenRectSt rect, mr_colourSt colorst, int flag, uint16 font);

/*
与函数mrc_drawTextLeft功能相似，不同点在于mrc_drawTextLeft
函数从右往左显示文本，相应的最右边显示的文本最
后一个字符；并且，该函数不支持自动换行。
输入:
pcText:         待显示的字符串
x, y:             待显示的文本右上角x, y
rect:             显示的字符限制范围
colorst:          字体颜色
font:              字体大小，可能的值是   
                        MR_FONT_SMALL
                        MR_FONT_MEDIUM
                        MR_FONT_BIG
flag：          无效；保留该参数仅为了统一
返回值:
    指示出在屏幕上第一个未完整显示字符的索引(字节)，
该索引是Text的unicode索引值。若所有字符都能完整
显示，则返回该字串转换为0。
*/
int32 mrc_drawTextRight(char* pcText, int16 x, int16 y, mr_screenRectSt rect, mr_colourSt colorst, int flag, uint16 font);

/*
将gb字符串转换为Unicode字符串，并申请一片内存保
存Unicode字符串，将Unicode字符串的指针返回。
由于早期mythroad版本，应用使用该函数时需要附带
编码转换表，使用该函数将使目标代码增大约16K。
输入:
cp: 输入的gb字符串
err：填NULL；若err为非NULL，则在转换出错时err返回出
          错字符的索引
输出:
err：若err为非NULL，则在转换出错时err返回出错字符
             的索引
size：输出的Unicode字符串长度
返回:
    NULL        转换出错
    其他    Unicode字符串指针
*/
uint16* mrc_c2u(char *cp, int32 *err, int32 *size);

/*
与mrc_c2u函数功能相同；
不同在于该函数使用VM中的码表进行变换，
可以使程序减少15K左右；
使用该函数得到的内存，需要使用mrc_freeFileData函数释放。
V1939后可以使用，V1939之前的版本会死机；
*/
uint16* mrc_c2uVM(char *cp, int32 *err, int32 *size);

/*
获取字符串的显示宽度和高度。
输入:
pcText:         待显示的字符串
is_unicode:    是否是unicode，TRUE(1)表示使用unicode编码，FALSE(0)表
                     示使用GB2312编码。
font:              字体大小，可能的值是   
                        MR_FONT_SMALL
                        MR_FONT_MEDIUM
                        MR_FONT_BIG
输出:
w：字符串的显示宽度
h：字符串的显示高度
返回:
    MR_SUCCESS  操作成功
    MR_FAILED      操作失败
*/
int32 mrc_textWidthHeight(char* pcText, int is_unicode, uint16 font, int32* w, int32* h);

/*
与mrc_textWidthHeight类似，不同点为mrc_unicodeTextWidthHeight仅处理
Unicode字符串，由于无需GB转换码表，代码空间会比
mrc_textWidthHeight节省15K左右。
输入:
pcText:         待显示的字符串
font:              字体大小，可能的值是   
                        MR_FONT_SMALL
                        MR_FONT_MEDIUM
                        MR_FONT_BIG
输出:
w：字符串的显示宽度
h：字符串的显示高度
返回:
    MR_SUCCESS  操作成功
    MR_FAILED      操作失败
*/
int32 mrc_unicodeTextWidthHeight(uint16* pcText, uint16 font, int32* w, int32* h);



/*
仅处理Unicode字符串输入
返回待显示字符串若显示在宽为w的区间里，
需要的行数；
pcText:         待显示的字符串
font:              字体大小，可能的值是   
                        MR_FONT_SMALL
                        MR_FONT_MEDIUM
                        MR_FONT_BIG
w                  待显示宽度
 返回:
    MR_FAILED      操作失败
    其他           字符串行数
*/
int32 mrc_unicodeTextRow(uint16* pcText, uint16 font, int32 w);


/*
获取屏幕宽、高、象素深度等信息。
mr_screeninfo格式如下：
typedef struct
{
   uint32 width;                  //屏幕宽
   uint32 height;                 //屏幕高
   uint32 bit;                    //屏幕象素深度，单位bit，
                                      如：6万5千色（16bit色深）应该返回16。
}mr_screeninfo;

输出:
screeninfo	屏幕信息

返回:
      MR_SUCCESS  成功
      MR_FAILED   失败
*/
int32 mrc_getScreenInfo(mr_screeninfo * screeninfo);


/*
绘制矩形于指定区域。
输入:
x,y,w,h:	位置
r,g,b	     绘制颜色
*/
void mrc_drawRect(int16 x, int16 y, int16 w, int16 h, uint8 r, uint8 g, uint8 b);

/*
绘制线段。
输入:
x1,y1,x2,y2:	起末点位置
r,g,b	          绘制颜色
*/
void mrc_drawLine(int16 x1, int16 y1, int16 x2, int16 y2, uint8 r, uint8 g, uint8 b);

/*
在屏幕的指定位置绘制点。
输入:
x, y	           绘制点的位置
nativecolor	点的颜色。（R:G:B = 5:6:5）
*/
void mrc_drawPoint(int16 x, int16 y, uint16 nativecolor);

/*
在屏幕的指定位置绘制点。
输入:
x, y	           绘制点的位置
r,g,b	          绘制颜色
*/
void mrc_drawPointEx(int16 x, int16 y, int32 r, int32 g, int32 b);

/*
使用指定的颜色清除屏幕。
输入:
r,g,b	          绘制颜色
*/
void mrc_clearScreen(int32 r, int32 g, int32 b);

/*
刷新屏幕指定的区域。该函数的功能是将mythroad屏幕
缓冲指定的区域刷新到屏幕上。
输入:
x, y, w, h	       屏幕指定的区域（左上角为（x,y），宽高
                        为（w,h））
*/
void mrc_refreshScreen(int16 x, int16 y, uint16 w, uint16 h);
void mrc_refreshScreenA(int16 x, int16 y, uint16 w, uint16 h);

/*
将屏幕的左上角x,y，宽高为w,h的矩形区域内的r,g,b分别
增强perr/256, perg/256, perb/256倍。
若perr=256, perg=0, perb=0，将只保留矩形区域内的红色；若
perr=perg= perb=128，将使矩形区域内产生一种半透明的效
果。
输入:
x,y,w,h	屏幕位置。
perr, perg, perb	r,g,b变化的数值。
*/
void mrc_EffSetCon(int16 x, int16 y, int16 w, int16 h, int16 perr, int16 perg, int16 perb);

/*
将mrp中名为filename的图片，从(x, y)开始的宽高为w, h的区域，
加载到序号为i的bmp缓冲中。max_w为名为filename的图片的图
片宽度。

mythroad中共有30个图片缓冲(序号0~29)，可以将mrp中的bmp图片
加载到缓冲中，供后继的绘图等操作

当满足(x==0)&&(y==0)&&(w==max_w)条件时，mrc_bitmapLoad将导入整幅
图片,而不是一部分。

输入:
i                  图片缓冲序号
filename      文件名，当文件名为"*"时，释放该缓存
x,y              源图片的起始位置
w,h             欲加载图片的宽高
max_w        欲加载图片的原始宽度

返回:
      MR_SUCCESS     成功
      MR_FAILED         失败
*/
int32 mrc_bitmapLoad(uint16 i, char* filename, int16 x, int16 y, uint16 w, uint16 h, uint16 max_w);

/*
	将序号为i的bmp缓冲中的图片，从缓冲中的图片的(sx, sy)
	开始的宽高为w, h的区域，绘制到(x, y)开始的屏幕缓冲中。

输入:
i                  图片缓冲序号
x,y              屏幕位置
rop              选择如下：
   BM_OR,         //SRC .OR. DST*   半透明效果
   BM_XOR,        //SRC .XOR. DST*
   BM_COPY,       //DST = SRC*      覆盖
   BM_NOT,        //DST = (!SRC)*
   BM_MERGENOT,   //DST .OR. (!SRC)
   BM_ANDNOT,     //DST .AND. (!SRC)
   BM_TRANSPARENT,//透明色不显示，图片的第一个象素（左上角
                                 的象素）是透明色
   BM_AND,        //DST AND SRC
   BM_GRAY,        //灰度绘图， 相当于BM_TRANSPARENT＋灰度绘图：
                              DST灰度 ＝ 30%R + 59%G + 11%B图片序号
   BM_REVERSE     //反向绘图，相当于BM_TRANSPARENT＋反向绘图（V1939）

sx,sy              源图片的起始位置
w,h             欲加载图片的宽高

返回:
      MR_SUCCESS     成功
      MR_FAILED         失败
*/
int32 mrc_bitmapShow(uint16 i, int16 x, int16 y, uint16 rop, int16 sx, int16 sy, int16 w, int16 h);

/*
功能同mrc_bitmapShow，唯一不同点是:源图片不是位于图片
缓冲区内，而是由参数给出。

输入:
p        源图片指针
mw     源图片的原始宽度
sx,sy  从源图片的(sx,sy)坐标开始
其余同mrc_bitmapShow

返回:
      MR_SUCCESS     成功
      MR_FAILED         失败
*/
int mrc_bitmapShowEx(uint16* p,
   int16 x,
   int16 y,
   int16 mw,
   int16 w,
   int16 h,
   uint16 rop,
   int16 sx,
   int16 sy
);


int mrc_bitmapShowExTrans(uint16* p,
   int16 x,
   int16 y,
   int16 mw,
   int16 w,
   int16 h,
   uint16 rop,
   int16 sx,
   int16 sy,
   uint16 transcolor
);

/*
兴建一个序号为i的bmp缓冲，缓冲图片的宽高为w, h。

输入:
i                  图片缓冲序号
w,h             图片的宽高

返回:
      MR_SUCCESS     成功
      MR_FAILED         失败
*/
int mrc_bitmapNew(
   uint16 i,
   uint16 w,
   uint16 h
);

/*
用增强的方式将bmp图片绘制于指定图片中。
将序号si 的bmp缓冲中的图片，从缓冲中的图片的(sx, sy)开
始的宽高为w, h的区域，绘制到序号di 的从(dx,dy)开始的bmp
缓冲中。

模式rop选择如下：
   BM_COPY,               //DST = SRC*      覆盖
   BM_TRANSPARENT,  //透明色不显示，图片的第一个象素（左上
                                  角的象素）是透明色
                                  
A、B、C、D用于图像变化，用于该变化的变换矩阵为：
x = A0*x0 + B0*y0
y = C0*x0 + D0*y0
这里为了表示小数，A, B, C, D均被乘以了256，即：
A = A0*256
B = B0*256
C = C0*256
D = D0*256
根据变换公式，可以绘出不同效果的图像，比如：
旋转图像：
A = 256 * cos（角度）
B = 256 * sin（角度）
C = 256 * -sin（角度）
D = 256 * cos（角度）
放大、缩小图像：
A = 256 * 放大倍数
B = 0
C = 0
D = 256 * 放大倍数

返回:
      MR_SUCCESS     成功
      MR_FAILED         失败
*/
int mrc_bitmapDraw(
   uint16 di,
   int16 dx,
   int16 dy,
   uint16 si,
   int16 sx,
   int16 sy,
   uint16 w,
   uint16 h,
   int16 A,
   int16 B,
   int16 C,
   int16 D,
   uint16 rop
);

/*
将屏幕缓冲载入序号为i的bmp缓冲中。

输入:
i                  图片缓冲序号

返回:
      MR_SUCCESS     成功
      MR_FAILED         失败
*/
int mrc_bitmapGetScreen(
   uint16 i
);

/*
精灵简介:
精灵是游戏运动的主体，支持碰撞检测，同时可以加载
10个序列，处理方便灵活。精灵序列图片左上角的象素
是透明色。
*/

/*
设置精灵高度

输入:
i                  图片缓冲序号
h                 精灵高度

返回:
      MR_SUCCESS     成功
      MR_FAILED         失败
*/
int32 mrc_spriteSet(
   uint16 i,
   uint16 h);

/*
绘制精灵

输入:
i                  图片缓冲序号
spriteindex   精灵编号
x,y              屏幕位置
mod              选择如下：
   BM_OR,         //SRC .OR. DST*   半透明效果
   BM_XOR,        //SRC .XOR. DST*
   BM_COPY,       //DST = SRC*      覆盖
   BM_NOT,        //DST = (!SRC)*
   BM_MERGENOT,   //DST .OR. (!SRC)
   BM_ANDNOT,     //DST .AND. (!SRC)
   BM_TRANSPARENT,//透明色不显示，图片的第一个象素（左上角
                                 的象素）是透明色
   BM_AND,        //DST AND SRC
   BM_GRAY,        //灰度绘图， 相当于BM_TRANSPARENT＋灰度绘图：
                              DST灰度 ＝ 30%R + 59%G + 11%B图片序号
   BM_REVERSE     //反向绘图，相当于BM_TRANSPARENT＋反向绘图（V1939）

返回:
      MR_SUCCESS     成功
      MR_FAILED         失败
*/
int32 mrc_spriteDraw(
   uint16 i,
   uint16 spriteindex,
   int16 x,
   int16 y,
   uint16 mod
);

/*
绘制精灵(增强)

输入:
i                  图片缓冲序号
spriteindex   精灵编号
x,y              屏幕位置
A,B,C,D       参见mrc_bitmapDraw说明

返回:
      MR_SUCCESS     成功
      MR_FAILED         失败
*/
int32 mrc_spriteDrawEx(
   uint16 i,
   uint16 spriteindex,
   int16 x,
   int16 y,
   int16 A,
   int16 B,
   int16 C,
   int16 D
);

/*
 判断碰撞的画精灵函数，返回值是画精灵时精灵所在位置
 非r,g,b的象素点数目。

输入:
i                  图片缓冲序号
spriteindex   精灵编号
x,y              屏幕位置
r,g,b           检测颜色

返回:
      >=0                   非r,g,b的象素点数目
      MR_FAILED         失败
*/
int32 mrc_spriteCheck(uint16 i, uint16 spriteindex, int16 x, int16 y,uint8 r, uint8 g, uint8 b);


/*
地砖简介:
地砖，背景和关卡设计的基石。图片序号与mrc_bitmapLoad中的
图片序号对应，同时可以有3个地砖，图片序号0～2。
*/
/*
设置地砖

输入:
i                  图片缓冲序号（地砖号）
x,y              屏幕位置
w,h              地砖列数, 地砖行数
tileh             地砖图片高

返回:
      MR_SUCCESS     成功
      MR_FAILED         失败
*/
int32 mrc_tileInit(
   uint16 i,
   int16 x,
   int16 y,
   uint16 w,
   uint16 h,
   uint16 tileh
   );

/*
设置地砖i的可视范围。

输入:
i                  图片缓冲序号（地砖号）
x1,y1,x2,y2  可视范围的左上和右下角(象素)
返回:
      MR_SUCCESS     成功
      MR_FAILED         失败
*/
int32 mrc_tileSetRect(
   uint16 i,
   int16 x1,
   int16 y1,
   int16 x2,
   int16 y2
);

/*
画地砖

输入:
i                  图片缓冲序号（地砖号）

返回:
      MR_SUCCESS     成功
      MR_FAILED         失败
*/
int32 mrc_tileDraw(
   uint16 i
);

/*
设置地砖

输入:
i                  图片缓冲序号（地砖号）
x,y              屏幕位置
w,h              地砖列数, 地砖行数
tileh             地砖图片高

返回:
      MR_SUCCESS     成功
      MR_FAILED         失败
*/
int32 mrc_tileSetEx
(  uint16 i,
   int16 x,
   int16 y,
   uint16 w,
   uint16 h,
   uint16 tileh
   );


/*
设置地砖

输入:
i                  图片缓冲序号（地砖号）
x,y              屏幕位置

返回:
      MR_SUCCESS     成功
      MR_FAILED         失败
*/
int32 mrc_tileSet
(  uint16 i,
   int16 x,
   int16 y
);


/*
地砖i卷动

输入:
i                  图片缓冲序号（地砖号）
mode:   0 up , 1 down, 2 left, 3 right

返回:
      MR_SUCCESS     成功
      MR_FAILED         失败
*/
int32 mrc_tileShift(
   uint16 i,
   uint16 mode
);

/*
从文件filename中读取地图到地砖i

输入:
i                  图片缓冲序号（地砖号）
filename      地图文件名

返回:
      MR_SUCCESS     成功
      MR_FAILED         失败
*/
int32 mrc_tileLoad(
   uint16 i,
   char* filename
);

int32 mrc_tileLoadEx(
   uint16 i,
   uint8* buf,
   int32 len
);

/*
读取地砖值

输入:
i                  图片缓冲序号（地砖号）
x,y              地砖列, 地砖行

返回:
      >=0                   地砖值
      MR_FAILED         失败
*/
int32 mrc_tileGetTile(
   uint16 i,
   uint16 x,
   uint16 y
);

/*
设置地砖值

输入:
i                  图片缓冲序号（地砖号）
x,y              地砖列, 地砖行
v                 地砖值

返回:
      MR_SUCCESS     成功
      MR_FAILED         失败
*/
int32 mrc_tileSetTile(
   uint16 i,
   uint16 x,
   uint16 y,
   uint16 v
);





/********************************本地化UI接口********************************/

/*
创建一个菜单，并返回菜单句柄，title是菜单的标题。

输入:
title	菜单的标题，unicode编码，网络字节序。
num	菜单项的数目

返回:
      正整数   菜单句柄
      MR_FAILED   失败
*/
int32 mrc_menuCreate(const char* title, int16 num);

/*
	在菜单里设置一个菜单项，参数index是该菜单项的
	序号，当用户选中某个菜单项时，把index号通过
	mrc_event函数发送到应用中。

输入:
menu  菜单的句柄
text 菜单项的名字，使用unicode编码，网络字节序。
index    菜单项的index号

返回:
      MR_SUCCESS  成功
      MR_FAILED   失败
*/
int32 mrc_menuSetItem(int32 menu, const char *text, int32 index);

/*
显示菜单。当菜单显示时，如果用户选择了菜单上
的某一项，系统将构造Mythroad应用消息，通过
mrc_event函数传送给Mythroad应用，消息类型为
MR_MENU_SELECT，参数为该菜单项的index。如果用户选择
了退出该菜单，系统将构造Mythroad应用消息，通过
mrc_event函数传送给Mythroad应用，消息类型为
MR_MENU_RETURN。

输入:
menu 菜单的句柄

返回:
      MR_SUCCESS  成功
      MR_FAILED   失败
*/
int32 mrc_menuShow(int32 menu);

/*
释放菜单。

输入:
menu 菜单的句柄

返回:
      MR_SUCCESS  成功
      MR_FAILED   失败
*/
int32 mrc_menuRelease(int32 menu);

/*
刷新菜单显示。

输入:
menu 菜单的句柄

返回:
      MR_SUCCESS  成功
      MR_FAILED   失败
*/
int32 mrc_menuRefresh(int32 menu);

/*
创建一个对话框，并返回对话框句柄。当对话框显
示时，如果用户按了对话框上的某个键，系统将构
造Mythroad应用消息，通过mrc_event函数传送给Mythroad应
用，消息类型为MR_DIALOG_EVENT，参数为该按键的ID。
"确定"键ID为：MR_DIALOG_KEY_OK；"取消"键ID为：
MR_DIALOG_KEY_CANCEL。

输入:
title	对话框的标题，unicode编码，网络字节序。
text	对话框内容，unicode编码，网络字节序。
type	对话框类型：
      MR_DIALOG_OK：对话框有"确定"键。
      MR_DIALOG_OK_CANCEL：对话框有"确定"和"取消"键。
      MR_DIALOG_CANCEL：对话框有 "返回"键。

返回:
      正整数   对话框句柄
      MR_FAILED   失败
*/
int32 mrc_dialogCreate(const char * title, const char * text, int32 type);

/*
释放对话框。

输入:
dialog  对话框的句柄

返回:
      MR_SUCCESS  成功
      MR_FAILED   失败
*/
int32 mrc_dialogRelease(int32 dialog);

/*
刷新对话框的显示。


输入:
dialog	对话框的句柄
title	对话框的标题，unicode编码，网络字节序。
text	对话框内容，unicode编码，网络字节序。
type	若type为-1，表示type不变。
对话框类型：
      MR_DIALOG_OK：对话框有"确定"键。
      MR_DIALOG_OK_CANCEL：对话框有"确定"和"取消"键。
      MR_DIALOG_CANCEL：对话框有 "返回"键。

返回:
      MR_SUCCESS  成功
      MR_FAILED   失败
*/
int32 mrc_dialogRefresh(int32 dialog, const char * title, const char * text, int32 type);

/*
创建一个文本框，并返回文本框句柄。文本框用来
显示只读的文字信息。文本框和对话框并没有本质
的区别，仅仅是显示方式上的不同，在使用上它们
的主要区别是：对话框的内容一般较短，文本框的
内容一般较长，对话框一般实现为弹出式的窗口，
文本框一般实现为全屏式的窗口。也可能在手机上
对话框和文本框使用了相同的方式实现。
文本框和对话框的消息参数是一样的。当文本框显
示时，如果用户选择了文本框上的某个键，系统将
构造Mythroad应用消息，通过mrc_event函数传送给Mythroad
平台，消息类型为MR_DIALOG_EVENT，参数为该按键的ID。
"确定"键ID为：MR_DIALOG_KEY_OK；"取消"键ID为：
MR_DIALOG_KEY_CANCEL。

输入:
title	文本框的标题，unicode编码，网络字节序。
text	文本框内容，unicode编码，网络字节序。
type	文本框类型：
      MR_DIALOG_OK：文本框有"确定"键。
      MR_DIALOG_OK_CANCEL：文本框有"确定"和"取消"键。
      MR_DIALOG_CANCEL：文本框有 "取消/返回"键。

返回:
      正整数   文本框句柄
      MR_FAILED   失败
*/
int32 mrc_textCreate(const char * title, const char * text, int32 type);

/*
释放文本框。

输入:
text 文本框的句柄

返回:
      MR_SUCCESS  成功
      MR_FAILED   失败
*/
int32 mrc_textRelease(int32 text);

/*
刷新文本框显示。

输入:
handle	文本框的句柄
title	文本框的标题，unicode编码，网络字节序。
text	文本框内容，unicode编码，网络字节序。

返回:
      MR_SUCCESS  成功
      MR_FAILED   失败
*/
int32 mrc_textRefresh(int32 handle, const char * title, const char * text);

/*
创建一个编辑框，并返回编辑框句柄。编辑框用来
显示并提供用户编辑文字信息。text是编辑框显示的
初始内容。
当编辑框显示时，如果用户选择了编辑框上的某个
键，系统将构造Mythroad应用消息，通过mrc_event函数
传送给Mythroad应用，消息类型为MR_DIALOG_EVENT，参数
为该按键的ID。"确定"键ID为：MR_DIALOG_KEY_OK；"取消
"键ID为：MR_DIALOG_KEY_CANCEL。

输入:
title	编辑框的标题，unicode编码，网络字节序。
text	编辑框的初始内容，unicode编码，网络字节序。
type	输入法类型：
      MR_EDIT_ANY：     任何字符
      MR_EDIT_NUMERIC： 数字
      MR_EDIT_PASSWORD： 密码，用"*"显示
max_size	最多可以输入的字符（unicode）个数，这里每一
                个中文、字母、数字、符号都算一个字符。
返回:
      正整数   编辑框句柄
      MR_FAILED   失败
*/
int32 mrc_editCreate(const char * title, const char * text, int32 type, int32 max_size);

/*
释放编辑框。

输入:
edit 编辑框的句柄

返回:
      MR_SUCCESS  成功
      MR_FAILED   失败
*/
int32 mrc_editRelease(int32 edit);

/*
获取编辑框内容，unicode编码。调用者若需在编辑框
释放后仍然使用编辑框的内容，需要自行保存该内
容。该函数需要在编辑框释放之前调用。

输入:
edit 编辑框的句柄

返回:
      非NULL       编辑框的内容指针，unicode编码。
      NULL            失败
*/
const char* mrc_editGetText(int32 edit);

/*
创建一个可扩展窗体，并返回可扩展窗体句柄。
可扩展窗体创建之后，用户的按键和触摸屏事件
会被构造成Mythroad应用消息，通过mrc_event函数传送
给Mythroad应用，按键事件的消息类型为MR_KEY_PRESS、
MR_KEY_RELEASE，触摸屏事件的消息类型为
MR_MOUSE_DOWN、MR_MOUSE_UP。
因为在对话框、菜单等窗体状态下，应用仅能接
收到菜单、对话框等事件，当需要创建一个由应
用自行绘制并处理按键事件的窗体时，就需要创
建可扩展窗体。

返回:
      正整数   可扩展窗体句柄
      MR_FAILED   失败
*/
int32 mrc_winCreate(void);

/*
释放可扩展窗体。

输入:
win  对话框的句柄

返回:
      MR_SUCCESS  成功
      MR_FAILED   失败
*/
int32 mrc_winRelease(int32 win);




/********************************网络接口********************************/

/*
取得网络ID。

返回:
      MR_NET_ID_MOBILE  移动GSM
      MR_NET_ID_CN   联通GSM
      MR_NET_ID_CDMA 联通CDMA
      MR_NET_ID_NONE 未插卡或网络错误
*/
int32 mrc_getNetworkID(void);

/*
网络初始化回调函数
输入:
result:
   MR_SUCCESS  初始化成功
   MR_FAILED      初始化失败
返回值:
   MR_SUCCESS  操作成功
   MR_FAILED      操作失败
函数的返回值仅作为将来升级版本保留，目前mythroad
不关心函数的返回值。
*/
typedef int32 (*MR_INIT_NETWORK_CB)(int32 result);

/*
网络初始化，如果没有拨号，进行拨号操作。
这里需要注意的是，本文档描述的所有网络接口函
数在实现时建议优先考虑采用非阻塞方式。
若网络初始化使用异步模式，使用回调函数通知引
擎初始化结果。

输入:
cb	当网络初始化使用异步模式时，使用该回调函数
通知应用初始化结果
mode	拨号方式，"CMNET"或" CMWAP"的拨号方式。

返回:
      MR_SUCCESS  同步模式，初始化成功，不再调用cb
      MR_FAILED   （立即感知的）失败，不再调用cb
      MR_WAITING  使用回调函数通知引擎初始化结果
*/
int32 mrc_initNetwork(MR_INIT_NETWORK_CB cb, const char *mode);

/*
断开拨号连接。

输入:

返回:
      MR_SUCCESS  成功
      MR_FAILED   失败
*/
int32 mrc_closeNetwork(void);

/*
获取主机IP回调函数
输入:
ip: 
   MR_FAILED       获取IP失败
   其他值      IP地址
返回值:
   MR_SUCCESS  操作成功
   MR_FAILED      操作失败
函数的返回值仅作为将来升级版本保留，目前mythroad
不关心函数的返回值。
*/
typedef int32 (*MR_GET_HOST_CB)(int32 ip);

/*
	通过主机名获得该主机的IP地址值，如果一个主机
	的IP地址为218.18.95.203，则值为218<<24 + 18<<16 + 95<<8 + 203
	= 0xda125fcb。
      若获取主机IP使用异步模式，使用回调函数通知引
      擎获取IP的结果。

输入:
name  主机名
cb      回调函数


返回:
      MR_FAILED   （立即感知的）失败，不再调用cb
      MR_WAITING  使用回调函数通知引擎获取IP的结果
      其他值   同步模式，立即返回的IP地址，不再调用cb
*/
int32 mrc_getHostByName(const char *name, MR_GET_HOST_CB cb);

/*
	创建一个socket。

输入:
 type	 Socket类型：
      MR_SOCK_STREAM
      MR_SOCK_DGRAM
 protocol	具体协议类型:
      MR_IPPROTO_TCP，
      MR_IPPROTO_UDP

返回:
      >=0              返回的Socket句柄
      MR_FAILED    失败
*/
int32 mrc_socket(int32 type, int32 protocol);

/*
	建立TCP连接。

输入:
 s       打开的socket句柄。
 ip      IP地址
 port    端口号
 type:
            MR_SOCKET_BLOCK          //阻塞方式（同步方式）
            MR_SOCKET_NONBLOCK       //非阻塞方式（异步方式）

返回:
      MR_SUCCESS  成功
      MR_FAILED      失败
      MR_WAITING   使用异步方式进行连接，应用需要轮询
                            该socket的状态以获知连接状况
*/
int32 mrc_connect(int32 s, int32 ip, uint16 port, int32 type);


/*
获取socket connect 状态（主要用于TCP的异步连接）
返回：

输入:
Socket句柄

返回:
      MR_SUCCESS ：  连接成功
      MR_FAILED  ：连接失败
      MR_WAITING ：连接中
      MR_IGNORE  ：不支持该功能
*/
int32 mrc_getSocketState(int32 s);

/*
 	关闭一个socket连接。

输入:
s  打开的socket句柄

返回:
      MR_SUCCESS  成功
      MR_FAILED   失败
*/
int32 mrc_closeSocket(int32 s);

/*
 	从网络接收数据。

输入:
s  打开的socket句柄。
len   缓冲区大小。

输出:
buf   缓冲区，存放接收到的数据。

返回:
      >=0的整数   实际接收的数据字节个数
      MR_FAILED          Socket已经被关闭或遇到了无法修复的错误。
*/
int32 mrc_recv(int32 s, char *buf, int len);

/*
 	从指定地址接收数据。

输入:
s  打开的socket句柄。
len   缓冲区大小。
ip   对端IP地址
port 对端端口号

输出:
buf   缓冲区，存放接收到的数据。


返回:
      >=0的整数   实际接收的数据字节个数
      MR_FAILED   Socket已经被关闭或遇到了无法修复的错误。
*/
int32 mrc_recvfrom(int32 s, char *buf, int len, int32 *ip, uint16 *port);

/*
 	发送数据。

输入:
s  打开的socket句柄
len   缓冲区大小

输出:
buf   要发送数据的缓冲区

返回:
      >=0             实际发送的数据字节个数
      MR_FAILED   Socket已经被关闭或遇到了无法修复的错误。
*/
int32 mrc_send(int32 s, const char *buf, int len);

/*
 	向指定地址发送数据。

输入:
s  打开的socket句柄
len   缓冲区大小
ip   对端IP地址
port 对端端口号

输出:
buf   要发送数据的缓冲区

返回:
      >=0               实际发送的数据字节个数
      MR_FAILED     Socket已经被关闭或遇到了无法修复的错误。
*/
int32 mrc_sendto(int32 s, const char *buf, int len, int32 ip, uint16 port);



/********************************声音接口********************************/

/*
Mythroad中最多同时支持 5个声音缓冲， index = 0~4。需要注
意的是虽然Mythroad中最多同时支持5个Sound文件，但 
Mythroad 中这五个文件并不能同时播放，当且仅当播放的
声音类型不同并且宿主平台支持同时播放类型不同的
声音时，可以同时播放不同的声音。 
*/
/*
设置声音缓冲

输入:
i                 声音缓存序号
filename     声音文件名
type的取值如下： 
        MR_SOUND_MIDI       0 
        MR_SOUND_WAV       1 
        MR_SOUND_MP3       2 
返回:
      MR_SUCCESS     成功
      MR_FAILED         失败
*/
int32 mrc_soundSet(uint16 i, char * filename, int32 type);

/*
播放声音缓冲

输入:
i                 声音缓存序号
loop            0:单次播放, 1:循环播放

返回:
      MR_SUCCESS     成功
      MR_FAILED         失败
*/
int32 mrc_soundPlay(
   uint16 i,
   int32 loop
);

/*
停止播放声音缓冲

输入:
i                 声音缓存序号

返回:
      MR_SUCCESS     成功
      MR_FAILED         失败
*/
int32 mrc_soundStop(
   uint16 i
);

/*
播放声音数据

输入:
type       声音数据类型:
        MR_SOUND_MIDI       0 
        MR_SOUND_WAV       1 
        MR_SOUND_MP3       2 
data        声音数据指针
dataLen   声音数据长度
loop            0:单次播放, 1:循环播放

返回:
      MR_SUCCESS     成功
      MR_FAILED         失败
*/
int32 mr_playSoundEx(int type, const void* data, uint32 dataLen, int32 loop);


/*
停止播放声音数据

输入:
type       声音数据类型:
        MR_SOUND_MIDI       0 
        MR_SOUND_WAV       1 
        MR_SOUND_MP3       2 

返回:
      MR_SUCCESS     成功
      MR_FAILED         失败
*/
int32 mr_stopSoundEx(int type);


/********************************定时器接口********************************/

/*
创建定时器

返回:
      非NULL     定时器句柄
      NULL          失败
*/
int32 mrc_timerCreate (void);

/*
删除定时器

输入:
t           定时器句柄
*/
void mrc_timerDelete (int32 t);

/*
停止定时器

输入:
t           定时器句柄
*/
void mrc_timerStop (int32 t);

/*
定时器回调函数
输入:
data:
   启动定时器时传入的data参数。
*/
typedef void (*mrc_timerCB)(int32 data);

/*
启动定时器

输入:
t           定时器句柄
time      定时器时长，单位毫秒
data      定时器数据
f           定时器回调函数
loop      是否循环；0:不循环，1:循环

返回:
      MR_SUCCESS     成功
      MR_FAILED         失败
*/
int32 mrc_timerStart (int32 t, int32 time, int32 data, mrc_timerCB f, int32 loop);


/*
更改定时器时长。

输入:
t           定时器句柄
time      定时器时长，单位毫秒

返回:
      MR_SUCCESS     成功
      MR_FAILED         失败
*/
int32 mrc_timerSetTimeEx (int32 t, int32 time);



/********************************其他接口********************************/
/*
退出应用，应用调用该函数通知mythroad，应用将要退
出。
*/
void mrc_exit(void);

/*
获取系统时间，单位毫秒。系统时间可以以Mythroad平
台引擎启动之前的任意时刻为起始时间，返回从起
始时间到目前经过的毫秒数。例如这个函数可能返
回的是系统启动后经过的毫秒数。
返回:
     单位毫秒的系统时间
*/
int32 mrc_getUptime(void);


/*
获取系统日期时间。
mr_datetime格式如下：
typedef struct
{
   uint16 year;                 //年
   uint8  month;                //月
   uint8  day;                  //日
   uint8  hour;                 //时，24小时制
   uint8  minute;               //分
   uint8  second;               //秒
}mr_datetime;

输出:
datetime	日期时间

返回:
      MR_SUCCESS  成功
      MR_FAILED   失败
*/
int32 mrc_getDatetime(mr_datetime* datetime);

/*
获取系统所剩余的内存数

返回:
      系统所剩余的内存数，单位字节
*/
uint32 mrc_getMemoryRemain(void);

/*
启动手机震动。

输入:
ms             震动持续的时间，单位毫秒

返回:
      MR_SUCCESS     成功
      MR_FAILED         失败
*/
int32 mrc_startShake(int32 ms);

/*
取得mythroad平台版本号

返回:
      mythroad平台版本号
*/
int32 mrc_getVersion(void);

/*
获取当前正在运行的mrp的文件名称
mythroad中支持的最大文件长度为127字节

返回:
      当前正在运行的mrp的文件名称
*/
char* mrc_getPackName(void);

/*
将name设置为当前mrp
mythroad中支持的最大文件长度为127字节

输入:
name         mrp文件名

返回:
      MR_SUCCESS     成功
      MR_FAILED         失败
*/
int32 mrc_setPackName(char * name);

/*
取得系统的总共内存大小
*/
int32 mrc_getSysMem(void);

/*******************************入口函数**********************************/
/*
应用初始化函数
该函数在应用初始化期间被mythroad平台调用，可以在这个
函数中进行全局变量的初始化等工作。
返回值:
MR_SUCCESS  应用初始化成功
MR_FAILED      应用初始化失败
*/
extern int32 mrc_init(void);

/*
应用事件函数
该函数在应用运行期间，每当mythroad平台收到事件时
被调用
输入:
code:
      code的可能取值如下:
enum {
   MR_KEY_PRESS,           //按键按下事件
   MR_KEY_RELEASE,        //按键释放事件
   MR_MOUSE_DOWN,       //触摸屏（鼠标）按下事件
   MR_MOUSE_UP,            //触摸屏（鼠标）抬起/释放事件
   MR_MENU_SELECT,       //菜单选中事件
   MR_MENU_RETURN,       //菜单返回事件
   MR_DIALOG_EVENT,      // 对话框/编辑框/文本框事件
   MR_EVENT01,                //VM保留，请不要使用
   MR_EXIT_EVENT,           //应用退出事件
   MR_EVENT02,                 //VM保留，请不要使用
   MR_LOCALUI_EVENT         //本地化接口事件
};
code：
移植层code取值范围为：0～999（已经使用的除外），其余
保留给VM和应用。
（    0～999： 移植层使用（VM已经使用的除外）；
    1000～1999：VM使用；
    10000~99999:应用使用；
其余均保留；）2007-11-20添加规范。

param0:
   当code为MR_KEY_PRESS或MR_KEY_RELEASE时，param0的可能取值如下:
enum {
   MR_KEY_0,               //按键 0
   MR_KEY_1,               //按键 1
   MR_KEY_2,               //按键 2
   MR_KEY_3,               //按键 3
   MR_KEY_4,               //按键 4
   MR_KEY_5,               //按键 5
   MR_KEY_6,               //按键 6
   MR_KEY_7,               //按键 7
   MR_KEY_8,               //按键 8
   MR_KEY_9,               //按键 9
   MR_KEY_STAR,            //按键 *
   MR_KEY_POUND,           //按键 #
   MR_KEY_UP,              //按键 上
   MR_KEY_DOWN,            //按键 下
   MR_KEY_LEFT,            //按键 左
   MR_KEY_RIGHT,           //按键 右
   MR_KEY_POWER,           //按键 挂机键
   MR_KEY_SOFTLEFT,        //按键 左软键
   MR_KEY_SOFTRIGHT,       //按键 右软键
   MR_KEY_SEND,            //按键 接听键
   MR_KEY_SELECT,          //按键 确认/选择（若方向键中间有确认键，建议设为该键）
   MR_KEY_VOLUME_UP,          //按键 侧键上
   MR_KEY_VOLUME_DOWN,          //按键 侧键下
   MR_KEY_NONE             //按键 保留
};
当code为MR_MOUSE_DOWN或MR_MOUSE_UP时，param0为屏幕的x坐标；
当code为MR_MENU_SELECT时，param0为菜单index；
当code为MR_DIALOG_EVENT时，param0的可能取值如下:
enum {
   MR_DIALOG_KEY_OK,         //对话框/文本框等的"确定"键被点击(选择)
   MR_DIALOG_KEY_CANCEL  //对话框/文本框等的"取消"("返回")键被点击(选择)
};
当code为MR_LOCALUI_EVENT时，param0的可能取值如下:
enum {
   MR_LOCALUI_KEY_OK,       //本地控件的"确定"键被点击(选择)
   MR_LOCALUI_KEY_CANCEL//本地控件的"取消"("返回")键被点击(选择)
};

param1:
当code为MR_MOUSE_DOWN或MR_MOUSE_UP时，param1为屏幕的y坐标；

返回值:
MR_SUCCESS  操作成功
MR_FAILED      操作失败
*/
extern int32 mrc_event(int32 code, int32 param0, int32 param1);

/*
应用暂停函数
该函数在应用被暂停时（有电话等事件暂停应用）
被mythroad平台调用。

注:在MTK的一些移植版本中，suspend (pause)和 resume 中不能
创建本地UI窗口。

返回值:
MR_SUCCESS  操作成功
MR_FAILED      操作失败
*/
extern int32 mrc_pause(void);

/*
该函数在应用恢复运行时被mythroad平台调用。

注:在MTK的一些移植版本中，suspend (pause)和 resume 中不能
创建本地UI窗口。

返回值:
MR_SUCCESS  操作成功
MR_FAILED      操作失败
*/
extern int32 mrc_resume(void);

/*
该函数在应用退出时被mythroad平台调用。
返回值:
MR_SUCCESS  操作成功
MR_FAILED      操作失败
*/
extern int32 mrc_exitApp(void);  



/*
该函数在收到短信事件时(仅编译参数sms_indication==1时有效)
被调用
输入:
code:
      code的值为MR_SMS_INDICATION == 7

param0:
      消息内容指针
      
param1:
      为号码指针
      
param2:
      为消息格式：
   MR_ENCODE_ASCII,
   MR_ENCODE_UNICODE
   
param3:
      消息内容长度

      
返回值:
MR_SUCCESS  操作成功
MR_FAILED      操作失败
*/
extern int32 mrc_eventEx(int32 code, int32 param0, int32 param1, int32 param2, int32 param3);



/*
从指定的mrp文件中读取指定的文件。该函数与mrc_readFileFromMrp
的区别除了输入有所不同外，还有另外一个不同:
mrc_readFileFromMrp函数尽量读取出mrp中的文件，仅对文件以及读取
过程做若检查；mrc_readFileFromMrpEx对读取过程做强检查，若文件
以压缩形式存放，还会对文件进行内容的强检查。该函数适合
使用在加载代码等需要较高正确性保证的环境。
输入:
packname     mrp文件名
filename        欲读取文件的文件名
*filebuf          读取文件的输出缓冲
                    当文件以压缩形式存放时，若:
                    *filebuf==NULL，则函数申请一片空间存放返回的文件
                    *filebuf!=NULL，这时函数使用*filebuf指向的空间存放
                           返回的文件内容
*filelen          当*filebuf!=NULL、文件以压缩形式存放时，指出
                    *filebuf指向的空间大小，若该空间大小不足以
                    存放解压以后的文件，则函数返回失败
lookfor          指出函数的操作形式:
                    0:    读取mrp中文件的内容，并通过*filebuf和*filelen
                               返回该内容；当*filebuf==NULL时，返回的内存
                               需要调用者释放；
                    1:    仅仅查找mrp中是否存在该文件，并不读取
                               文件内容
                    2:    当mrp文件位于ROM或RAM中时，读取欲读取文
                                件的原始内容，即使文件进行了压缩也
                                不进行解压，返回的内存不需要释放；
                                当mrp文件位于文件系统中时，等同于
                                lookfor==0
                    3:    以强检查的方式读取mrp中文件的内容，由于
                               lookfor==0的方式读取文件时，文件是否压缩
                               的判断是自适应的，所以不能完全保证文件
                               的正确性；lookfor==3时会强制约定文件进行了
                               压缩，并进行强检查。当*filebuf==NULL时，返回
                               的内存需要调用者释放；
                     4:与3相同，不同在于使用mrc_malloc8分配内存；
                     5:仅通过filelen返回文件长度；

输出:
*filebuf         当lookfor==0、2、3时返回文件内容指针
*filelen         当lookfor==0、2、3时返回文件内容长度

返回:
      MR_SUCCESS   成功，当lookfor==1时表示文件存在
      MR_FAILED       失败

(      
近日发现有部分代码在使用mrc_readFileFromMrpEx函数时，
对结果的判断仅使用了filebuf（判断是否为NULL），而忽略
了函数的返回值。
      在这里提醒：mrc_readFileFromMrpEx函数在操作失败时，返回
      值是失败，但filebuf的值是未定义（也就是说，可能是
      NULL，也可能不是NULL），这里必须使用函数返回值进
      行结果判断，使用filebuf进行判断是不保险的。
)
*/
int32 mrc_readFileFromMrpEx(char* packname, const char* filename, 
               uint8 ** filebuf, int32 *filelen, int32 lookfor);

/*
该函数与mrc_readFileFromMrpEx函数类似，区别在于:
1、lookfor参数无效，在此保留仅为兼容；
2、不支持在内存中或固化的mrp；
3、mrp中的文件解压时，不会被缓冲到内存中，占用内存较少；
*/
int32 mrc_readFileFromMrpExA(char* packname, const char* filename, 
               uint8** filebuf, int32 *filelen, int32 lookfor);


/*
该函数与mrc_readFileFromMrpEx函数类似，区别在于:
1、没有lookfor参数，mrc_readFileFromMrpExPart函数仅处理文件读取；
2、mrc_readFileFromMrpExPart函数仅读取原始数据，不对压缩文件进行
解压；
3、参数offset:从文件offset开始读取数据；
4、参数read_len:读取的数据长度；
*/
int32 mrc_readFileFromMrpExPart(char* packname, const char* filename, 
               uint8 ** filebuf, int32 *filelen, int32 offset, int32 read_len);

/*
从mrp中读取文件的所有内容到申请的内存中。
使用该函数得到的内存，需要使用mrc_freeFileData函数释放。

输入:
filename     mrp文件名
lookfor          指出函数的操作形式:
                    0:    读取mrp中文件的内容
                    1:    仅仅查找mrp中是否存在该文件，并不读取
                               文件内容

输出:
*filelen         当lookfor==0时返回文件内容长度
                   当lookfor==1时未知

返回:
   当lookfor==0时
      非NULL         指向读取到的内容的指针，该内存需要
                              调用者释放
      NULL         失败
   当lookfor==1时
      1         mrp中存在该文件
      NULL         mrp中不存在该文件
*/
void * mrc_readFileFromMrp(const char* filename, int32 *filelen, int32 lookfor);

/*
释放由mrc_readFileFromMrp函数读取的文件内容空间。
输入:
data     文件内容指针
filelen          文件内容长度
*/
void mrc_freeFileData(void* data, int32 filelen);

/*
释放由原始内存申请方式申请的空间。
输入:
add     指针
size   长度
*/
void mrc_freeOrigin(void* add, int32 size);

/*
输入:
s     输入内容指针，若为NULL，则进行初始化；
n    输入内容长度，若s为非NULL，n为0，返回计算结果；
使用方法:
   mrc_updcrc(NULL, 0);          
   mrc_updcrc(s, n);
   return mrc_updcrc(s, 0);

*/
uint32 mrc_updcrc(uint8 *s, uint32 n);


void mrc_refreshScreenTrigger(int16 x, int16 y, uint16 w, uint16 h);
void mrc_refreshScreenTriggerA(int16 x, int16 y, uint16 w, uint16 h);
void mrc_refreshScreenUnTrigger(void);


typedef unsigned char md5_byte_t; /* 8-bit byte */
typedef unsigned int md5_word_t; /* 32-bit word */

typedef struct md5_state_s {
    md5_word_t count[2];	/* message length in bits, lsw first */
    md5_word_t abcd[4];		/* digest buffer */
    md5_byte_t buf[64];		/* accumulate block */
} md5_state_t;

extern void mrc_md5_init(md5_state_t *pms);

extern void mrc_md5_append(md5_state_t *pms, const md5_byte_t *data, int nbytes);

extern void mrc_md5_finish(md5_state_t *pms, md5_byte_t digest[16]);

extern int32 mrc_platDrawTextFlag;

extern void mrc_platDrawChar(uint16 ch, int32 x, int32 y, int32 color);



/*
 *  判断获取numBytes大小的扩展内存是否需要检测一次内存。
 *  如果使用移植接口可以成功的申请到这么多内存，则返回
 *     FALSE
 *  否则， 返回TRUE。
 *
 */

extern int32 mrc_exRamNeedDetect(int32 numBytes);



/*
 *  返回：
 *     MR_SUCCESS : 已经扫描过。
 *     else：       没有或者出错。
 */

extern int mrc_exRamDetected(void);




typedef void (*mrc_exRamDetect_progress_cb_t)(int ratio);

/*
 *  调用这个API开始内存检测，
 *  可能需要10s的时间。
 */
extern void mrc_exRamDetect(mrc_exRamDetect_progress_cb_t cb);


/*
 *  调用这个启用扩展内存。 
 *  num为需要的额外的内存数，单位为Byte。
 */
extern int32  mrc_exRamInitEx(int num);

extern int32 mrc_exRamInit(void);

/*
反初始化平台的SBASM扩展内存；
调用这个函数后，mrc_exRamMalloc将只好使用主内存，
mrc_exRamFree函数将会视释放的内存空间，若待释放的
空间位于主内存，将释放该内存，若待释放的空间
位于扩展内存，将不做任何操作；
返回:
      MR_SUCCESS   成功
      MR_FAILED       失败
*/
extern int32 mrc_exRamRelease(void);


/*
先在扩展内存中申请内存，若扩展内存不足，在主内存
中申请内存；
*/
extern void* mrc_exRamMalloc(int size);

/*
若待释放的空间位于主内存，将从主内存中释放该内存，
若待释放的空间位于扩展内存，将从扩展内存中释放该内
存；
*/
extern void mrc_exRamFree(void *address);

/*
仅申请扩展内存；
*/
extern void* mrc_exRamMallocOnly(int size);

/*
仅释放扩展内存；
*/
extern void mrc_exRamFreeOnly(void *address);

/*
将扩展内存保存到文件；
#define MRC_EXRAM_FILE "cache/exr.cac"
返回:
      MR_SUCCESS   成功
      MR_FAILED       失败
*/
extern int32 mrc_exRamStore(void);

/*
从文件加载扩展内存；
返回:
      MR_SUCCESS   成功
      MR_FAILED       失败
*/
extern int32 mrc_exRamLoad(void);



/*
 *  获取内存使用的状态。[单位 Byte]
 *     mainUsed -  如果!=NULL, 那么输出为主内存被使用的数量
 *     mainLeft -  如果 !=NULL, 那么输出为主内存剩余的数量
 *     ssbUsed  -  作废
 *     ssbLeft  -  作废
 *
 *     sbasmUsed  -  如果 !=NULL， 那么输出为sbasm使用的数量，未开启的情况下-1
 *     sbasmUsed  -  如果 !=NULL， 那么输出为sbasm剩余的数量，未开启的情况下-1
 *
 *  返回值：
 *      主内存的峰值。
 */

extern int mrc_getMemStatus(int * mainUsed, int * mainLeft, 
					 int * ssbUsed, int * ssbLeft,  
					 int * sbasmUsed, int * sbasmLeft);


/*
 *  下面两个函数主要是用来做本地存档的。
 *  存档会绑定到当前的IMSI号， 并且做了MD5校验， 防止有些玩家对存档进行破解。

 *     代码开销:   ~1K (thumb)
 *     运行时内存开销:     <2K (堆栈),    0 (堆)
 */
 

/*
 *   写入一个绑定IMSI号的存档。  
 *
 *    参数：  
 *
 *      key --  应用开发者任意指定的一个key，会用来加密。
 *      fileName --  存档的文件名， 例如   "gzzhx/1.sav",  NOTE: 不会自动创建目录; 如果文件已经存在会先删除再创建。
 *      data/len --  应用的二进制数据。
 *      isAddTail  --  是否为追加。
 *
 *   返回值：
 *      MR_SUCCESS --  成功
 *      MR_FAILED  --  失败， 原因可能包括：目录没有创建；IO错误等。如果为追加，文件不存在或者邋MD5不对。
 *      
 */
extern int32  mrc_safeStorage_write(int32 key, const char * fileName, void * data, int32 len, int32 isAddTail);


/*
 *   打开一个加密的存档文件或者返回数据的长度。
 *   
 *    参数：  
 *
 *      key --  应用开发者任意指定的一个key， 和调用mrc_safeStorage_write时一致才能打开。
 *      fileName --  存档的文件名， 例如   "gzzhx/1.sav",
 *      offset  --     数据的偏移量
 *      out_data --  输出Buffer， 如果为NULL， 会返回数据的长度。
 *      in_len   --  输出Buffer的长度。 
 *
 *   返回值：
 *          < 0       : 失败， 原因可能包括：KEY不对， IMSI不匹配， 文档被篡改, in_len<实际长度，或者其他的IO错误.
 *          > 0       :  if  out_data == NULL; 返回整个文件的长度
 *
 *                         if  out_data != NULL;  返回整个文件的长度， 并且将数据写入到out_data 中.
 *      
 */
extern int32 mrc_safeStorage_read(int32 key, const char *	fileName,  int32 offset, void * out_data, int32 in_len);

/*add new network function*/


/*
	回调中可能出现的错误类型
*/
enum
{
	NET_ERROR_INITNETWORK_FAILED = 100,
	NET_ERROR_INITNETWORK_NOSIMCARD,
	NET_ERROR_INITNETWORK_FAILED1,
	NET_ERROR_INITNETWORK_FAILED2,
	NET_ERROR_INITNETWORK_TIMEOUT,
	NET_ERROR_INITNETWORK_AUTHERROR,
	
	NET_ERROR_GETHOST_FAILED = 200,
	NET_ERROR_GETHOST_CHECK_FAILED,
	NET_ERROR_GETHOST_IP_INVALID,
	NET_ERROR_GETHOST_RES_FAILED,
	NET_ERROR_GETHOST_RES_TIMEOUT,
	
	NET_ERROR_CONNECT_FAILED = 300,
	NET_ERROR_CONNECT_RES_FAILED,
	NET_ERROR_CONNECT_TIMEOUT,
	
	NET_ERROR_NO_MEM = 800
};

typedef enum
{
	NET_EVEVT_CONNECTED,
	NET_EVEVT_ERROR
		
}NET_EVEVT;

/*
  回调函数类型NET_CB

  网络回调函数，当evt==NET_EVEVT_CONNECTED，返回相应的handle
				当evt==NET_EVEVT_ERROR，handle=(int32)NULL,
				param0和param1显示失败原因
*/
typedef void (*NET_CB)(NET_EVEVT evt,int32 handle,int32 param0,int32 param1);


/*
	函数名称：mrc_TCPconnect
	函数功能：使用CMNET方式建立一个TCP连接
	输入：ipaddr：连接地址的ip或者域名
			port：连接端口
			cb：  回调函数
	返回值：ret>0,连接的控制句柄
	        ret = (int32)NULL,创建失败，回调函数会先收到错误码

*/
int32 mrc_TCPconnect(char* ipaddr,uint16 port,NET_CB cb);



/*
	函数名称：mrc_TCPclose
	函数功能：关闭连接，销毁
	输入：连接的控制句柄
	返回值：MR_SUCCESS --  成功
	      MR_FAILED  --  失败， 原因可能是传入的handle不正确或已经close。

*/
int32 mrc_TCPclose(int32 handle);



/*
	函数名称：mrc_TCPsend
	函数功能：发送数据
	输入：handle：连接的句柄
			data：待发送数据
			len：待发送数据长度
	返回值：ret>=0,实际发送长度
			MR_FAILED  --  失败，原因可能是连接已经断开或遇到无法修复的错误。

*/
int32 mrc_TCPsend(int32 handle,uint8* data,int32 len);



/*
	函数名称：mrc_TCPrecv
	函数功能：发送数据
	输入：handle：连接的句柄
			data：接收数据缓冲区的地址
			len： 接收数据缓冲区的长度
	返回值：ret>=0,实际接收字节数
			MR_FAILED  --失败，原因可能是连接已经断开或遇到无法修复的错误。
*/
int32 mrc_TCPrecv(int32 handle,uint8* data,int32 len);


#ifdef SDK_MOD

extern int32 mrc_appInit(void);
extern int32 mrc_appExitApp(void);
#define MRC_EXT_INIT mrc_appInit
#define MRC_EXT_EXIT mrc_appExitApp
   
#else

#define MRC_EXT_INIT mrc_init
#define MRC_EXT_EXIT mrc_exitApp

#endif


#endif
