#ifndef mythroad_h
#define mythroad_h

#include "mr.h"

/*这里是做虚拟机配置的部分*/

/*启动虚拟机Log*/
#define MYTHROAD_DEBUG

/*使用打包应用*/
#define MR_GAME_PACK

/*支持PKZIP模式的压缩文件*/
#define MR_PKZIP_MAGIC

#define MR_AUTHORIZATION

/*退出VM 时是否释放VM 占用的资源
这里如果不释放VM 占用的资源，有可能会导致
文件、网络等资源得不到释放*/
#define MR_EXIT_RELEASE_ALL

// #define MR_SECOND_BUF

/*支持短信*/
#define MR_SM_SURPORT

/*支持Socket*/
#define MR_SOCKET_SUPPORT

/*配置结束*/

#define MR_TIME_START(a)                         \
    {                                            \
        mr_timerStart(a);                        \
        mr_timer_state = MR_TIMER_STATE_RUNNING; \
    }
#define MR_TIME_STOP()                        \
    {                                         \
        mr_timerStop();                       \
        mr_timer_state = MR_TIMER_STATE_IDLE; \
    }

#define DRAW_TEXT_EX_IS_UNICODE 1
#define DRAW_TEXT_EX_IS_AUTO_NEWLINE 2

enum {
    MR_SCREEN_FIRST_BUF,
    MR_SCREEN_SECOND_BUF
};

enum {
    MR_TIMER_STATE_IDLE,
    MR_TIMER_STATE_RUNNING,
    MR_TIMER_STATE_SUSPENDED,
    MR_TIMER_STATE_ERROR
};

typedef struct {
    int16 t;
    int16 act;
} mr_cycleSt;


#define MAKERGB(r, g, b) (uint16)(((uint32)(r >> 3) << 11) + ((uint32)(g >> 2) << 5) + ((uint32)(b >> 3)))
#define MR_SCREEN_CACHE_POINT(x, y) (mr_screenBuf + y * MR_SCREEN_MAX_W + x)


#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#define MR_BMP_FILE_HEADER_LEN 54
#define MR_SET_U16(p, v)         \
    {                            \
        *(uint8*)p++ = (v)&0xff; \
        *(uint8*)p++ = (v) >> 8; \
    }
#define MR_SET_U32(p, v)                       \
    {                                          \
        *(uint8*)p++ = (v)&0xff;               \
        *(uint8*)p++ = ((v)&0xff00) >> 8;      \
        *(uint8*)p++ = ((v)&0xff0000) >> 16;   \
        *(uint8*)p++ = ((v)&0xff000000) >> 24; \
    }

#define MR_SCREEN_W mr_screen_w
#define MR_SCREEN_MAX_W MR_SCREEN_W
#define MR_SCREEN_H mr_screen_h
#define MR_SCREEN_DEEP 2

#define BITMAPMAX 30
#define SPRITEMAX 10
#define TILEMAX 3

#define SOUNDMAX 5

#define MR_SPRITE_INDEX_MASK (0x03FF)  // mask of bits used for tile index
#define MR_SPRITE_TRANSPARENT (0x0400)

#define MR_TILE_SHIFT (11)

#define MR_ROTATE_0 (0)
#define MR_ROTATE_90 (1)
#define MR_ROTATE_180 (2)
#define MR_ROTATE_270 (3)
/* 54 byte */
/*
typedef struct {
	uint16	bmType;
	uint32	bmSize;
	uint16	bmReserved1;
	uint16	bmReserved2;
	uint32	bmOffset;
   
	uint32	Size;
	uint32	Width;
	uint32	Height;
	uint16	Planes;
	uint16	BitCount;
	uint32	Compression;
	uint32	SizeImage;
	uint32	XPelsPerMeter;
	uint32	YPelsPerMeter;
	uint32	ClrUsed;
	uint32	ClrImportant;
}mr_bitmap_file_header;
*/
typedef struct SaveF {
    int32 f;
} SaveF;

typedef struct LoadF {
    int32 f;
    char buff[MRP_L_BUFFERSIZE];
} LoadF;

#define MR_FLAGS_BI 1
#define MR_FLAGS_AI 2
#define MR_FLAGS_RI 4
#define MR_FLAGS_EI 8

void* _mr_readFile(const char* filename, int* filelen, int lookfor);

extern int32 _mr_smsGetBytes(int32 pos, char* p, int32 len);
extern void _mr_showErrorInfo(const char* errstr);
extern int _mr_GetSysInfo(mrp_State* L);
extern int _mr_GetDatetime(mrp_State* L);
extern int mr_Gb2312toUnicode(mrp_State* L);
extern int32 _mr_getHost(mrp_State* L, char* host);

extern int _mr_pcall(int nargs, int nresults);

extern const char* _mr_memfind(const char* s1, size_t l1, const char* s2, size_t l2);
extern int32 _mr_u2c(char* input, int32 inlen, char* output, int32 outlen);

//extern int32 mr_read_asyn_cb(int32 result, uint32  cb_param);
extern mrp_State* vm_state;

extern int32 mr_timer_run_without_pause;

#ifdef MR_PKZIP_MAGIC
extern int32 mr_zipType;
#endif

typedef int32 (*MR_LOAD_C_FUNCTION)(int32 code);
typedef int32 (*MR_C_FUNCTION)(void* P, int32 code, uint8* input, int32 input_len, uint8** output, int32* output_len);

typedef int32 (*MR_EVENT_FUNCTION)(int16 type, int32 param1, int32 param2);
typedef int32 (*MR_TIMER_FUNCTION)(void);
typedef int32 (*MR_STOP_FUNCTION)(void);
typedef int32 (*MR_PAUSEAPP_FUNCTION)(void);
typedef int32 (*MR_RESUMEAPP_FUNCTION)(void);

typedef void (*mrc_timerCB)(int32 data);



/*下面是当不能取得屏幕缓冲指针时使用的接口 (不完全)   */
//extern void mr_drawBitmap(uint16* bmp, int16 x, int16 y, uint16 w, uint16 h, uint16 rop, uint16 transcolor);
//extern void mr_drawRect(int16 x, int16 y, uint16 w, uint16 h, uint32 color);
//extern int mr_check(uint16*p, int16 x, int16 y, uint16 w, uint16 h, uint16 transcoler, uint16 color_check);
//extern void mr_effect(int16 x, int16 y, int16 w, int16 h, int16 perr, int16 perg, int16 perb);

#endif
