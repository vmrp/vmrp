#ifndef HELPER_H_INCLUDED
#define HELPER_H_INCLUDED

#include "md5.h"
#include "mrporting.h"

typedef void (*mrc_timerCB)(int32 data);

typedef struct mrc_timerSt /* TIMER CONTROL BLOCK      */
{
    int32 check;         /* check this value,is the timer valid?             */
    int32 time;          /* timeout time             */
    int32 left;          /* time left before timeout */
    mrc_timerCB handler; /* event handler            */
    int32 data;
    int32 loop;
    struct mrc_timerSt* next;  /* next in active chain     */
    struct mrc_timerSt* next2; /* next in timeout chain     */
} mrc_timerSt;

typedef int32 (*MR_C_FUNCTION)(void* P, int32 code, uint8* input, int32 input_len, uint8** output, int32* output_len);
typedef void (*T_mr_printf)(const char* format, ...);
typedef int32 (*T_mr_mem_get)(char** mem_base, uint32* mem_len);

typedef int32 (*T_mr_mem_free)(char* mem, uint32 mem_len);

typedef void (*T_mr_drawBitmap)(uint16* bmp, int16 x, int16 y, uint16 w, uint16 h);
typedef const char* (*T_mr_getCharBitmap)(uint16 ch, uint16 fontSize, int* width, int* height);

typedef int32 (*T_mr_timerStart)(uint16 t);
typedef int32 (*T_mr_timerStop)(void);
typedef uint32 (*T_mr_getTime)(void);
typedef int32 (*T_mr_getDatetime)(mr_datetime* datetime);
typedef int32 (*T_mr_getUserInfo)(mr_userinfo* info);
typedef int32 (*T_mr_sleep)(uint32 ms);
typedef int32 (*T_mr_plat)(int32 code, int32 param);

typedef void (*MR_PLAT_EX_CB)(uint8* output, int32 output_len);
typedef int32 (*T_mr_platEx)(int32 code, uint8* input, int32 input_len, uint8** output, int32* output_len, MR_PLAT_EX_CB* cb);

typedef int32 (*T_mr_ferrno)(void);
typedef int32 (*T_mr_open)(const char* filename, uint32 mode);
typedef int32 (*T_mr_close)(int32 f);
typedef int32 (*T_mr_info)(const char* filename);
typedef int32 (*T_mr_write)(int32 f, void* p, uint32 l);
typedef int32 (*T_mr_read)(int32 f, void* p, uint32 l);
typedef int32 (*T_mr_seek)(int32 f, int32 pos, int method);
typedef int32 (*T_mr_getLen)(const char* filename);
typedef int32 (*T_mr_remove)(const char* filename);
typedef int32 (*T_mr_rename)(const char* oldname, const char* newname);
typedef int32 (*T_mr_mkDir)(const char* name);
typedef int32 (*T_mr_rmDir)(const char* name);

typedef int32 (*T_mr_findStart)(const char* name, char* buffer, uint32 len);
typedef int32 (*T_mr_findGetNext)(int32 search_handle, char* buffer, uint32 len);
typedef int32 (*T_mr_findStop)(int32 search_handle);
typedef int32 (*T_mr_exit)(void);

typedef int32 (*T_mr_startShake)(int32 ms);
typedef int32 (*T_mr_stopShake)(void);

typedef int32 (*T_mr_playSound)(int type, const void* data, uint32 dataLen, int32 loop);
typedef int32 (*T_mr_stopSound)(int type);

typedef int32 (*T_mr_sendSms)(char* pNumber, char* pContent, int32 flags);
typedef void (*T_mr_call)(char* number);
typedef int32 (*T_mr_getNetworkID)(void);
typedef void (*T_mr_connectWAP)(char* wap);

typedef void (*T_mr_platDrawChar)(uint16 ch, int32 x, int32 y, int32 color);

typedef int32 (*T_mr_menuCreate)(const char* title, int16 num);
typedef int32 (*T_mr_menuSetItem)(int32 menu, const char* text, int32 index);
typedef int32 (*T_mr_menuShow)(int32 menu);
typedef int32 (*T_mr_menuSetFocus)(int32 menu, int32 index);
typedef int32 (*T_mr_menuRelease)(int32 menu);
typedef int32 (*T_mr_menuRefresh)(int32 menu);

typedef int32 (*T_mr_dialogCreate)(const char* title, const char* text, int32 type);
typedef int32 (*T_mr_dialogRelease)(int32 dialog);
typedef int32 (*T_mr_dialogRefresh)(int32 dialog, const char* title, const char* text, int32 type);

typedef int32 (*T_mr_textCreate)(const char* title, const char* text, int32 type);
typedef int32 (*T_mr_textRelease)(int32 text);
typedef int32 (*T_mr_textRefresh)(int32 handle, const char* title, const char* text);

typedef int32 (*T_mr_editCreate)(const char* title, const char* text, int32 type, int32 max_size);
typedef int32 (*T_mr_editRelease)(int32 edit);
typedef const char* (*T_mr_editGetText)(int32 edit);

typedef int32 (*T_mr_winCreate)(void);
typedef int32 (*T_mr_winRelease)(int32 win);

typedef int32 (*T_mr_getScreenInfo)(mr_screeninfo* screeninfo);

typedef int32 (*MR_INIT_NETWORK_CB)(int32 result);
typedef int32 (*MR_GET_HOST_CB)(int32 ip);

typedef int32 (*T_mr_initNetwork)(MR_INIT_NETWORK_CB cb, const char* mode);
typedef int32 (*T_mr_closeNetwork)(void);
typedef int32 (*T_mr_getHostByName)(const char* name, MR_GET_HOST_CB cb);
typedef int32 (*T_mr_socket)(int32 type, int32 protocol);
typedef int32 (*T_mr_connect)(int32 s, int32 ip, uint16 port, int32 type);
typedef int32 (*T_mr_closeSocket)(int32 s);
typedef int32 (*T_mr_recv)(int32 s, char* buf, int len);
typedef int32 (*T_mr_recvfrom)(int32 s, char* buf, int len, int32* ip, uint16* port);
typedef int32 (*T_mr_send)(int32 s, const char* buf, int len);
typedef int32 (*T_mr_sendto)(int32 s, const char* buf, int len, int32 ip, uint16 port);

typedef void* (*T_mr_malloc)(uint32 len);
typedef void (*T_mr_free)(void* p, uint32 len);
typedef void* (*T_mr_realloc)(void* p, uint32 oldlen, uint32 len);

typedef void* (*T_memcpy)(void* s1, const void* s2, int n);
typedef void* (*T_memmove)(void* s1, const void* s2, int n);
typedef char* (*T_strcpy)(char* s1, const char* s2);
typedef char* (*T_strncpy)(char* s1, const char* s2, int n);
typedef char* (*T_strcat)(char* s1, const char* s2);
typedef char* (*T_strncat)(char* s1, const char* s2, int n);
typedef int (*T_memcmp)(const void* s1, const void* s2, int n);
typedef int (*T_strcmp)(const char* s1, const char* s2);
typedef int (*T_strncmp)(const char* s1, const char* s2, int n);
typedef int (*T_strcoll)(const char* s1, const char* s2);
typedef void* (*T_memchr)(const void* s, int c, int n);
typedef void* (*T_memset)(void* s, int c, int n);
typedef int (*T_strlen)(const char* s);
typedef char* (*T_strstr)(const char* s1, const char* s2);

typedef int (*T_sprintf)(char* s, const char* format, ...);
typedef int (*T_atoi)(const char* nptr);
typedef unsigned long int (*T_strtoul)(const char* nptr,
                                       char** endptr, int base);
typedef int (*T_rand)(void);

typedef struct {
    uint16 w;
    uint16 h;
    uint32 buflen;
    uint32 type;
    uint16* p;
} mr_bitmapSt;

typedef struct {
    int16 x;
    int16 y;
    uint16 w;
    uint16 h;
    int16 x1;
    int16 y1;
    int16 x2;
    int16 y2;
    uint16 tilew;
    uint16 tileh;
} mr_tileSt;

typedef struct {
    void* p;
    uint32 buflen;
    int32 type;
} mr_soundSt;

typedef struct {
    uint16 h;
} mr_spriteSt;

typedef struct {
    uint16* p;
    uint16 w;
    uint16 h;
    uint16 x;
    uint16 y;
} mr_bitmapDrawSt;

typedef struct {
    int16 A;  // A, B, C, and D are fixed point values with an 8-bit integer part
    int16 B;  // and an 8-bit fractional part.
    int16 C;
    int16 D;
    uint16 rop;
} mr_transMatrixSt;

typedef struct {
    uint16 x;
    uint16 y;
    uint16 w;
    uint16 h;
} mr_screenRectSt;

typedef struct {
    uint8 r;
    uint8 g;
    uint8 b;
} mr_colourSt;

typedef struct
{
    int32 id;
    int32 ver;
    char* sidName;
} mrc_appInfoSt;

typedef void (*T_mr_md5_init)(md5_state_t* pms);
typedef void (*T_mr_md5_append)(md5_state_t* pms, const md5_byte_t* data, int nbytes);
typedef void (*T_mr_md5_finish)(md5_state_t* pms, md5_byte_t digest[16]);

typedef int32 (*T__mr_load_sms_cfg)(void);
typedef int32 (*T__mr_save_sms_cfg)(int32 f);
typedef int32 (*T__DispUpEx)(int16 x, int16 y, uint16 w, uint16 h);
typedef void (*T__DrawPoint)(int16 x, int16 y, uint16 nativecolor);
typedef void (*T__DrawBitmap)(uint16* p, int16 x, int16 y, uint16 w, uint16 h, uint16 rop, uint16 transcoler, int16 sx, int16 sy, int16 mw);
typedef void (*T__DrawBitmapEx)(mr_bitmapDrawSt* srcbmp, mr_bitmapDrawSt* dstbmp, uint16 w, uint16 h, mr_transMatrixSt* pTrans, uint16 transcoler);
typedef void (*T_DrawRect)(int16 x, int16 y, int16 w, int16 h, uint8 r, uint8 g, uint8 b);
typedef int32 (*T__DrawText)(char* pcText, int16 x, int16 y, uint8 r, uint8 g, uint8 b, int is_unicode, uint16 font);
typedef int (*T__BitmapCheck)(uint16* p, int16 x, int16 y, uint16 w, uint16 h, uint16 transcoler, uint16 color_check);
typedef void* (*T__mr_readFile)(const char* filename, int* filelen, int lookfor);
typedef int (*T_mr_wstrlen)(char* txt);
typedef int32 (*T_mr_registerAPP)(uint8* p, int32 len, int32 index);

typedef int32 (*T__mr_c_function_new)(MR_C_FUNCTION f, int32 len);

typedef int32 (*T__DrawTextEx)(char* pcText, int16 x, int16 y, mr_screenRectSt rect, mr_colourSt colorst, int flag, uint16 font);
typedef int32 (*T__mr_EffSetCon)(int16 x, int16 y, int16 w, int16 h, int16 perr, int16 perg, int16 perb);
typedef int32 (*T__mr_TestCom)(int32 L, int input0, int input1);
typedef int32 (*T__mr_TestCom1)(int32 L, int input0, char* input1, int32 len);

/*
函数功能：将gb字符串转换为Unicode字符串，并申请一片内存保存Unicode字符串，将Unicode字符串
的指针返回。
cp: 输入的gb字符串；
err：填NULL；
size：输出的Unicode字符串长度；
返回：Unicode字符串指针*/
typedef uint16* (*T_c2u)(char* cp, int32* err, int32* size);

typedef int32 (*T__mr_div)(int32 a, int32 b);
typedef int32 (*T__mr_mod)(int32 a, int32 b);

typedef int32 (*T_mrp_error)(int32 L);

typedef void (*T_mrp_settop)(int32 L, int idx);

typedef struct {
    uint8** mr_m0_files;
    uint32* vm_state;
    int32* mr_state;
    int32* _bi;

    void** mr_timer_p;
    uint32* mr_timer_state;
    void* mr_timer_run_without_pause;

    void* mr_gzInBuf;
    void* mr_gzOutBuf;
    void* LG_gzinptr;
    void* LG_gzoutcnt;

    int32* mr_sms_cfg_need_save;
    void* _mr_smsSetBytes;
    void* _mr_smsAddNum;
    void* _mr_newSIMInd;

    void* _mr_isMr;

#if 0
   void*                   mrp_gettop; //1937
   T_mrp_settop				mrp_settop;
   void*   mrp_pushvalue;
   void*   mrp_remove;
   void*   mrp_insert;
   void*   mrp_replace;
   
   void*   mrp_isnumber;
   void*   mrp_isstring;
   void*   mrp_iscfunction;
   void*   mrp_isuserdata;
   void*   mrp_type;
   void*   mrp_typename;
   void*   mrp_shorttypename;
   
   
   void*   mrp_equal;
   void*   mrp_rawequal;
   void*   mrp_lessthan;
   
   void*   mrp_tonumber;
   void*   mrp_toboolean;
   void*   mrp_tostring;
   void*   mrp_strlen;
   void*   mrp_tostring_t;
   void*   mrp_strlen_t;
   void*   mrp_tocfunction;
   void*   mrp_touserdata;
   void*   mrp_tothread;
   void*   mrp_topointer;
   
   void*   mrp_pushnil;
   void*   mrp_pushnumber;
   void*   mrp_pushlstring;
   void*   mrp_pushstring;
   void*   mrp_pushvfstring;
   void*   mrp_pushfstring;
   void*   mrp_pushboolean;
   void*   mrp_pushcclosure;
   
   
   void*   mrp_gettable;
   void*   mrp_rawget;
   void*   mrp_rawgeti;
   void*   mrp_newtable;
   void*   mrp_getmetatable;
   
   
   void*   mrp_settable;
   void*   mrp_rawset;
   void*   mrp_rawseti;
   
   
   void*   mrp_call;
   void*   mrp_pcall;
   void*   mrp_load;
   
   void*   mrp_getgcthreshold;
   void*   mrp_setgcthreshold;
   
   
   T_mrp_error   mrp_error;

   void*   mrp_checkstack;
   void*   mrp_newuserdata;
   void*   mrp_getfenv;
   void*   mrp_setfenv;
   void*   mrp_setmetatable;
   void*   mrp_cpcall;
   void*   mrp_next;
   void*   mrp_concat;
   void*   mrp_pushlightuserdata;
   void*   mrp_getgccount;
   void*   mrp_dump;
   void*   mrp_yield;
   void*   mrp_resume;
#endif
} mr_internal_table;

typedef int32 (*T_mr_c_gcfunction)(int32 code);

typedef struct {
    void* reserve0;
    void* reserve1;
    void* reserve2;
    T_mr_c_gcfunction mr_c_gcfunction;
} mr_c_port_table;

typedef struct {
    T_mr_malloc mr_malloc;
    T_mr_free mr_free;
    T_mr_realloc mr_realloc;

    T_memcpy memcpy;
    T_memmove memmove;
    T_strcpy strcpy;
    T_strncpy strncpy;
    T_strcat strcat;
    T_strncat strncat;
    T_memcmp memcmp;
    T_strcmp strcmp;
    T_strncmp strncmp;
    T_strcoll strcoll;
    T_memchr memchr;
    T_memset memset;
    T_strlen strlen;
    T_strstr strstr;
    T_sprintf sprintf;
    T_atoi atoi;
    T_strtoul strtoul;
    T_rand rand;

    void* reserve0;
    void* reserve1;
    mr_internal_table* _mr_c_internal_table;
    mr_c_port_table* _mr_c_port_table;
    T__mr_c_function_new _mr_c_function_new;

    T_mr_printf mr_printf;
    T_mr_mem_get mr_mem_get;
    T_mr_mem_free mr_mem_free;
    T_mr_drawBitmap mr_drawBitmap;
    T_mr_getCharBitmap mr_getCharBitmap;
    T_mr_timerStart g_mr_timerStart;
    T_mr_timerStop g_mr_timerStop;
    T_mr_getTime mr_getTime;
    T_mr_getDatetime mr_getDatetime;
    T_mr_getUserInfo mr_getUserInfo;
    T_mr_sleep mr_sleep;

    T_mr_plat mr_plat;
    T_mr_platEx mr_platEx;

    T_mr_ferrno mr_ferrno;
    T_mr_open mr_open;
    T_mr_close mr_close;
    T_mr_info mr_info;
    T_mr_write mr_write;
    T_mr_read mr_read;
    T_mr_seek mr_seek;
    T_mr_getLen mr_getLen;
    T_mr_remove mr_remove;
    T_mr_rename mr_rename;
    T_mr_mkDir mr_mkDir;
    T_mr_rmDir mr_rmDir;
    T_mr_findStart mr_findStart;
    T_mr_findGetNext mr_findGetNext;
    T_mr_findStop mr_findStop;

    T_mr_exit mr_exit;
    T_mr_startShake mr_startShake;
    T_mr_stopShake mr_stopShake;
    T_mr_playSound mr_playSound;
    T_mr_stopSound mr_stopSound;

    T_mr_sendSms mr_sendSms;
    T_mr_call mr_call;
    T_mr_getNetworkID mr_getNetworkID;
    T_mr_connectWAP mr_connectWAP;

    T_mr_menuCreate mr_menuCreate;
    T_mr_menuSetItem mr_menuSetItem;
    T_mr_menuShow mr_menuShow;
    void* reserve;
    T_mr_menuRelease mr_menuRelease;
    T_mr_menuRefresh mr_menuRefresh;
    T_mr_dialogCreate mr_dialogCreate;
    T_mr_dialogRelease mr_dialogRelease;
    T_mr_dialogRefresh mr_dialogRefresh;
    T_mr_textCreate mr_textCreate;
    T_mr_textRelease mr_textRelease;
    T_mr_textRefresh mr_textRefresh;
    T_mr_editCreate mr_editCreate;
    T_mr_editRelease mr_editRelease;
    T_mr_editGetText mr_editGetText;
    T_mr_winCreate mr_winCreate;
    T_mr_winRelease mr_winRelease;

    T_mr_getScreenInfo mr_getScreenInfo;

    T_mr_initNetwork mr_initNetwork;
    T_mr_closeNetwork mr_closeNetwork;
    T_mr_getHostByName mr_getHostByName;
    T_mr_socket mr_socket;
    T_mr_connect mr_connect;
    T_mr_closeSocket mr_closeSocket;
    T_mr_recv mr_recv;
    T_mr_recvfrom mr_recvfrom;
    T_mr_send mr_send;
    T_mr_sendto mr_sendto;

    uint16** mr_screenBuf;
    int32* mr_screen_w;
    int32* mr_screen_h;
    int32* mr_screen_bit;
    mr_bitmapSt* mr_bitmap;
    mr_tileSt* mr_tile;
    int16** mr_map;
    mr_soundSt* mr_sound;
    mr_spriteSt* mr_sprite;

    char* pack_filename;
    char* start_filename;
    char* old_pack_filename;
    char* old_start_filename;

    char** mr_ram_file;
    int32* mr_ram_file_len;

    int8* mr_soundOn;
    int8* mr_shakeOn;

    char** LG_mem_base;  //VM 内存基址
    int32* LG_mem_len;   //VM 内存大小
    char** LG_mem_end;   //VM 内存终止
    int32* LG_mem_left;  //VM 剩余内存

    uint8* mr_sms_cfg_buf;
    T_mr_md5_init mr_md5_init;
    T_mr_md5_append mr_md5_append;
    T_mr_md5_finish mr_md5_finish;
    T__mr_load_sms_cfg _mr_load_sms_cfg;
    T__mr_save_sms_cfg _mr_save_sms_cfg;
    T__DispUpEx _DispUpEx;

    T__DrawPoint _DrawPoint;
    T__DrawBitmap _DrawBitmap;
    T__DrawBitmapEx _DrawBitmapEx;
    T_DrawRect DrawRect;
    T__DrawText _DrawText;
    T__BitmapCheck _BitmapCheck;
    T__mr_readFile _mr_readFile;
    T_mr_wstrlen mr_wstrlen;
    T_mr_registerAPP mr_registerAPP;
    T__DrawTextEx _DrawTextEx;  //1936
    T__mr_EffSetCon _mr_EffSetCon;
    T__mr_TestCom _mr_TestCom;
    T__mr_TestCom1 _mr_TestCom1;  //1938
    T_c2u c2u;                    //1939

    T__mr_div _mr_div;  //1941
    T__mr_mod _mr_mod;

    uint32* LG_mem_min;
    uint32* LG_mem_top;  //内存峰值

    void* mr_updcrc;            //1943
    char* start_fileparameter;  //1945
    void* mr_sms_return_flag;   //1949
    void* mr_sms_return_val;
    void* mr_unzip;                     //1950
    mrc_timerCB* mr_exit_cb;            //1951
    int32* mr_exit_cb_data;             //1951
    char* mr_entry;                     //1952,V2000-V2002不支持
    T_mr_platDrawChar mr_platDrawChar;  //1961
} mr_table;

typedef struct _mr_c_event_st {
    int32 code;
    int32 param0;
    int32 param1;
    int32 param2;
    int32 param3;
} mr_c_event_st;

typedef struct _mr_c_call_st {
    int32 code;
    uint8* input;
    int32 input_len;

} mr_c_call_st;

#define MR_MINIMUM_TIMER 10
#define MR_MINIMUM_TIMER_OUT 50

#define MR_SCREEN_W mr_screen_w
#define MR_SCREEN_MAX_W MR_SCREEN_W
#define MR_SCREEN_H mr_screen_h

#define MR_SCREEN_DEEP 2

/*
 *  zefang_wang 2010.12.21 :
 *    这个值之前定义有错误， 16 在底层的实现为 SHARE_OPEN，
 *    但是之前被定义成了   RECREATE.
 */

#define MR_FILE_SHARE_OPEN 16  // 一边写， 一边读。

#define MR_IS_FILE 1     //文件
#define MR_IS_DIR 2      //目录
#define MR_IS_INVALID 8  //无效(非文件、非目录)

#define MR_SPRITE_INDEX_MASK (0x03FF)  // mask of bits used for tile index
#define MR_SPRITE_TRANSPARENT (0x0400)

#define MR_TILE_SHIFT (11)

#define MR_ROTATE_0 (0)
#define MR_ROTATE_90 (1)
#define MR_ROTATE_180 (2)
#define MR_ROTATE_270 (3)

enum {
    BM_OR,           //SRC .OR. DST*   半透明效果
    BM_XOR,          //SRC .XOR. DST*
    BM_COPY,         //DST = SRC*      覆盖
    BM_NOT,          //DST = (!SRC)*
    BM_MERGENOT,     //DST .OR. (!SRC)
    BM_ANDNOT,       //DST .AND. (!SRC)
    BM_TRANSPARENT,  //透明色不显示，图片的第一个象素（左上角的象素）是透明色
    BM_AND,
    BM_GRAY,
    BM_REVERSE
};

enum {
    MR_FILE_STATE_OPEN,
    MR_FILE_STATE_CLOSED,
    MR_FILE_STATE_NIL
};

#define DRAW_TEXT_EX_IS_UNICODE 1
#define DRAW_TEXT_EX_IS_AUTO_NEWLINE 2

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#define ABS(VAL) (((VAL) > 0) ? (VAL) : (-(VAL)))

#define MRC_TIME_START(a)                        \
    {                                            \
        mr_timerStart(a);                        \
        mr_timer_state = MR_TIMER_STATE_RUNNING; \
    }
#define MRC_TIME_STOP()                       \
    {                                         \
        mr_timerStop();                       \
        mr_timer_state = MR_TIMER_STATE_IDLE; \
    }

typedef int32 (*MR_LOAD_C_FUNCTION)(int32 code);

#ifndef MRC_PLUGIN
typedef int32 (*mrc_extMainSendAppMsg_t)(int32 extCode, int32 app, int32 code, int32 param0, int32 param1);
#else
typedef int32 (*mrc_extMainSendAppMsg_t)(int32 app, int32 code, int32 param0, int32 param1, int32 param2, int32 param3, int32 param4, int32 extCode);
typedef int32 (*mpsFpFuncType)(int32 p0, int32 p1, int32 p2, int32 p3, int32 p4, int32 p5);
typedef int32 (*MR_C_FUNCTION_EX)(int32 p0, int32 p1, int32 p2, int32 p3, int32 p4, int32 p5, void* P, mpsFpFuncType func);
typedef struct _mrcMpsFpCallParamsSt {
    mpsFpFuncType func;
    int32 p0;
    int32 p1;
    int32 p2;
    int32 p3;
    int32 p4;
    int32 p5;
} mrcMpsFpCallParamsSt;

typedef struct _mrcMpsFpEventParamsSt {
    int32 p1;
    int32 p2;
    int32 p3;
    int32 p4;
    int32 p5;
} mrcMpsFpEventParamsSt;
#endif

typedef struct _mrc_extChunk_st mrc_extChunk_st;

typedef struct _mr_c_function_st {
    uint8* start_of_ER_RW;          // RW段指针
    uint32 ER_RW_Length;            // RW长度
    int32 ext_type;                 // ext启动类型，为1时表示ext启动
    mrc_extChunk_st* mrc_extChunk;  // ext模块描述段，下面的结构体。
    int32 stack;                    //stack shell 2008-2-28
} mr_c_function_st;

typedef struct _mrc_extChunk_st {
    /* 0x00 */ int32 check;                     //0x7FD854EB 标志
    /* 0x04 */ MR_LOAD_C_FUNCTION init_func;    //mr_c_function_load 函数指针
    /* 0x08 */ MR_C_FUNCTION event;             //mr_helper 函数指针
    /* 0x0c */ uint8* code_buf;                 //ext内存地址
    /* 0x10 */ int32 code_len;                  //ext长度
    /* 0x14 */ uint8* var_buf;                  //RW段地址
    /* 0x18 */ int32 var_len;                   //RW段长度
    /* 0x1c */ mr_c_function_st* global_p_buf;  //mr_c_function_st 表地址
    /* 0x20 */ int32 global_p_len;              //mr_c_function_st 表长度
    /* 0x24 */ int32 timer;
    /* 0x28 */ mrc_extMainSendAppMsg_t sendAppEvent;
    /* 0x2c */ mr_table* extMrTable;  // mr_table函数表。

#ifdef MRC_PLUGIN
    MR_C_FUNCTION_EX eventEx;
#endif

    int32 isPause; /*1: pause 状态0:正常状态*/
#ifdef SDK_MOD
    int32 (*mrc_init_t)(void);
    int32 (*mrc_event_t)(int32 code, int32 param0, int32 param1);
    int32 (*mrc_pause_t)(void);
    int32 (*mrc_resume_t)(void);
    int32 (*mrc_exitApp_t)(void);
#endif
} mrc_extChunk_st;

enum {
    MRC_EXT_INTERNAL_EVENT,
    MRC_EXT_APP_EVENT,
    MRC_EXT_MPS_EVENT
};


#if 1
#define MRC_MALLOC(size) mrc_malloc(size)
#define MRC_FREE(p) mrc_free(p)
#else
void* mrc_mallocEx(int size, char* file, int line);
#define MRC_MALLOC(size) mrc_mallocEx(size, __FILE__, __LINE__)
#define MRC_FREE(p)                                                    \
    {                                                                  \
        mrc_free(p);                                                   \
        mrc_printf("free,%lu,FILE:%s,LINE:%d", p, __FILE__, __LINE__); \
    }
#endif

#endif
