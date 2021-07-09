#include "./include/fixR9.h"
#include "./include/md5.h"
#include "./include/mem.h"
#include "./include/mr.h"
#include "./include/mr_auxlib.h"
#include "./include/mr_base64.h"
#include "./include/mr_graphics.h"
#include "./include/mr_gzip.h"
#include "./include/mr_helper.h"
#include "./include/mr_lib.h"
#include "./include/mr_socket_target.h"
#include "./include/mr_tcp_target.h"
#include "./include/mrporting.h"
#include "./include/mythroad.h"
#include "./include/string.h"
#include "./include/encode.h"

typedef struct _mini_mr_c_event_st {
    int32 code;
    int32 param0;
    int32 param1;
    int32 param2;
    int32 param3;
} mini_mr_c_event_st;

mini_mr_c_event_st c_event_st;

#define MRDBGPRINTF mr_printf

mrp_State* vm_state;

static uint16* mr_screenBuf;
static mr_bitmapSt mr_bitmap[BITMAPMAX + 1];
static mr_tileSt mr_tile[TILEMAX];
static int16* mr_map[TILEMAX];
static mr_soundSt mr_sound[SOUNDMAX];
static mr_spriteSt mr_sprite[SPRITEMAX];
int32 mr_state = MR_STATE_IDLE;
static int32 bi = 0;
static char pack_filename[MR_MAX_FILENAME_SIZE];
static char start_filename[MR_MAX_FILENAME_SIZE];
static char start_fileparameter[MR_MAX_FILENAME_SIZE];
static char old_pack_filename[MR_MAX_FILENAME_SIZE];
static char old_start_filename[MR_MAX_FILENAME_SIZE];
static char mr_entry[MR_MAX_FILENAME_SIZE];
static int32 mr_screen_w;
static int32 mr_screen_h;
static int32 mr_screen_bit;
static void* mr_timer_p;
static int32 mr_timer_state = MR_TIMER_STATE_IDLE;
int32 mr_timer_run_without_pause = FALSE;

static char* mr_exception_str = NULL;

#ifdef MR_CFG_USE_A_DISK
static char temp_current_path[MR_MAX_FILENAME_SIZE];
#endif

//******************************************
//将应用加载到内存中运行
static char* mr_ram_file = NULL;
static int mr_ram_file_len;
//******************************************

//*******************************
int8 mr_soundOn = 0;
int8 mr_shakeOn = 0;
//*******************************
uint8* mr_gzInBuf;
uint8* mr_gzOutBuf;
unsigned LG_gzinptr;  /* index of next byte to be processed in inbuf */
unsigned LG_gzoutcnt; /* bytes in output buffer */

#ifdef MR_PKZIP_MAGIC
int32 mr_zipType;
#endif

//*******************************

//************************************短信
#define MR_MAX_NUM_LEN 32     //手机号码最大长度
#define MR_MAX_TRACE_BUF 100  //TRACE 大小
#define MR_CMD_NUM 10         //最大命令号码个数
#define MR_SECTION_LEN 120    //一节的长度
#define MR_MAX_SM_LEN 160     //短消息的最大长度
#define MR_SMS_CFG_BUF_LEN (MR_SECTION_LEN * 36)

#define CFG_USE_UNICODE_OFFSET 5  //统一长号码flag偏移
#define CFG_SM_FLAG_OFFSET 32     //短信更新flag偏移

#define CFG_USE_SM_UPDATE_OFFSET 4   //是否使用短信更新
#define CFG_USE_URL_UPDATE_OFFSET 6  //是否使用SMS更新的URL

#define DSM_CFG_FILE_NAME "dsm.cfg"  //短信文件名称

static uint8 mr_sms_cfg_buf[MR_SMS_CFG_BUF_LEN];
static int32 mr_sms_cfg_need_save = FALSE;

static uint8 mr_sms_return_flag;
static int32 mr_sms_return_val;

//************************************短信

MR_LOAD_C_FUNCTION mr_load_c_function;
MR_C_FUNCTION mr_c_function;
void* mr_c_function_P;
int32 mr_c_function_P_len;

MR_EVENT_FUNCTION mr_event_function = NULL;
MR_TIMER_FUNCTION mr_timer_function = NULL;
MR_STOP_FUNCTION mr_stop_function = NULL;
MR_PAUSEAPP_FUNCTION mr_pauseApp_function = NULL;
MR_RESUMEAPP_FUNCTION mr_resumeApp_function = NULL;

static mrc_timerCB mr_exit_cb = NULL;
static int32 mr_exit_cb_data;

typedef struct {
    int32 id;
    int32 ver;
    char* sidName;
    int32 ram;
} mrc_appInfoSt_st;

mrc_appInfoSt_st mrc_appInfo_st;

//int32 _mr_decode(unsigned char *in, unsigned int len, unsigned char *out);

int32 _mr_smsSetBytes(int32 pos, char* p, int32 len);
void _DrawBitmap(uint16* p, int16 x, int16 y, uint16 w, uint16 h, uint16 rop, uint16 transcoler, int16 sx, int16 sy, int16 mw);
int _mr_EffSetCon(int16 x, int16 y, int16 w, int16 h, int16 perr, int16 perg, int16 perb);
int32 _DrawTextEx(char* pcText, int16 x, int16 y, mr_screenRectSt rect, mr_colourSt colorst, int flag, uint16 font);
int _mr_TestCom(mrp_State* L, int input0, int input1);
int _mr_TestCom1(mrp_State* L, int input0, char* input1, int32 len);
int _mr_isMr(char* input);
int32 _mr_newSIMInd(int16 type, uint8* old_IMSI);
int32 _mr_load_sms_cfg(void);
int32 _mr_save_sms_cfg(int32 f);
int32 _mr_smsAddNum(int32 index, char* pNum);
void _DrawPoint(int16 x, int16 y, uint16 nativecolor);
void DrawRect(int16 x, int16 y, int16 w, int16 h, uint8 r, uint8 g, uint8 b);
int32 _DrawText(char* pcText, int16 x, int16 y, uint8 r, uint8 g, uint8 b, int is_unicode, uint16 font);
int _BitmapCheck(uint16* p, int16 x, int16 y, uint16 w, uint16 h, uint16 transcoler, uint16 color_check);
void* _mr_readFile(const char* filename, int* filelen, int lookfor);
int32 mr_registerAPP(uint8* p, int32 len, int32 index);
int32 _mr_c_function_new(MR_C_FUNCTION f, int32 len);
static int _mr_TestComC(int input0, char* input1, int32 len, int32 code);
int32 mr_stop_ex(int16 freemem);

static const unsigned char* mr_m0_files[50];
static const void* _mr_c_internal_table[17];
static void* _mr_c_port_table[4];
static void* _mr_c_function_table[150];


static int32 _mr_div(int32 a, int32 b) {
    return a / b;
}

static int32 _mr_mod(int32 a, int32 b) {
    return a % b;
}

void mythroad_init(void) {
    memset2(_mr_c_port_table, 0, sizeof(_mr_c_port_table));
    memset2(mr_m0_files, 0, sizeof(mr_m0_files));

    ///////////////////////////////////////////////////////////////////////
    _mr_c_internal_table[0] = (void*)mr_m0_files;
    _mr_c_internal_table[1] = (void*)&vm_state;
    _mr_c_internal_table[2] = (void*)&mr_state;
    _mr_c_internal_table[3] = (void*)&bi;

    _mr_c_internal_table[4] = (void*)&mr_timer_p;
    _mr_c_internal_table[5] = (void*)&mr_timer_state;
    _mr_c_internal_table[6] = (void*)&mr_timer_run_without_pause;

    _mr_c_internal_table[7] = (void*)&mr_gzInBuf;
    _mr_c_internal_table[8] = (void*)&mr_gzOutBuf;
    _mr_c_internal_table[9] = (void*)&LG_gzinptr;
    _mr_c_internal_table[10] = (void*)&LG_gzoutcnt;

    _mr_c_internal_table[11] = (void*)&mr_sms_cfg_need_save;
    _mr_c_internal_table[12] = (void*)asm_mr_smsSetBytes;
    _mr_c_internal_table[13] = (void*)asm_mr_smsAddNum;
    _mr_c_internal_table[14] = (void*)asm_mr_newSIMInd;

    _mr_c_internal_table[15] = (void*)asm_mr_isMr;
    _mr_c_internal_table[16] = NULL;

    ///////////////////////////////////////////////////////////////////////
    // 如果函数使用了全局变量，必需用asm_xxx
    _mr_c_function_table[0] = (void*)asm_mr_malloc;
    _mr_c_function_table[1] = (void*)asm_mr_free;
    _mr_c_function_table[2] = (void*)asm_mr_realloc;  // 3

    _mr_c_function_table[3] = (void*)memcpy2;
    _mr_c_function_table[4] = (void*)memmove2;
    _mr_c_function_table[5] = (void*)strcpy2;
    _mr_c_function_table[6] = (void*)strncpy2;
    _mr_c_function_table[7] = (void*)strcat2;
    _mr_c_function_table[8] = (void*)strncat2;
    _mr_c_function_table[9] = (void*)memcmp2;
    _mr_c_function_table[10] = (void*)strcmp2;
    _mr_c_function_table[11] = (void*)strncmp2;
    _mr_c_function_table[12] = (void*)STRCOLL;
    _mr_c_function_table[13] = (void*)memchr2;
    _mr_c_function_table[14] = (void*)memset2;
    _mr_c_function_table[15] = (void*)strlen2;
    _mr_c_function_table[16] = (void*)strstr2;
    _mr_c_function_table[17] = (void*)sprintf_;
    _mr_c_function_table[18] = (void*)atoi2;
    _mr_c_function_table[19] = (void*)strtoul2;  // 20
    _mr_c_function_table[20] = (void*)asm_mr_rand;

    _mr_c_function_table[21] = (void*)NULL;
    _mr_c_function_table[22] = (void*)asm_mr_stop_ex;  //V1939
    _mr_c_function_table[23] = (void*)_mr_c_internal_table;

    _mr_c_function_table[24] = (void*)_mr_c_port_table;
    _mr_c_function_table[25] = (void*)_mr_c_function_new;  //26
    _mr_c_function_table[26] = (void*)asm_mr_printf;
    _mr_c_function_table[27] = (void*)asm_mr_mem_get;
    _mr_c_function_table[28] = (void*)asm_mr_mem_free;
    _mr_c_function_table[29] = (void*)asm_mr_drawBitmap;
    _mr_c_function_table[30] = (void*)asm_mr_getCharBitmap;
    _mr_c_function_table[31] = (void*)asm_mr_timerStart;
    _mr_c_function_table[32] = (void*)asm_mr_timerStop;
    _mr_c_function_table[33] = (void*)asm_mr_getTime;
    _mr_c_function_table[34] = (void*)asm_mr_getDatetime;
    _mr_c_function_table[35] = (void*)asm_mr_getUserInfo;
    _mr_c_function_table[36] = (void*)asm_mr_sleep;  //37

    _mr_c_function_table[37] = (void*)asm_mr_plat;
    _mr_c_function_table[38] = (void*)asm_mr_platEx;  //39

    _mr_c_function_table[39] = (void*)mr_ferrno;
    _mr_c_function_table[40] = (void*)asm_mr_open;
    _mr_c_function_table[41] = (void*)asm_mr_close;
    _mr_c_function_table[42] = (void*)asm_mr_info;
    _mr_c_function_table[43] = (void*)asm_mr_write;
    _mr_c_function_table[44] = (void*)asm_mr_read;
    _mr_c_function_table[45] = (void*)asm_mr_seek;
    _mr_c_function_table[46] = (void*)asm_mr_getLen;
    _mr_c_function_table[47] = (void*)asm_mr_remove;
    _mr_c_function_table[48] = (void*)asm_mr_rename;
    _mr_c_function_table[49] = (void*)asm_mr_mkDir;
    _mr_c_function_table[50] = (void*)asm_mr_rmDir;
    _mr_c_function_table[51] = (void*)asm_mr_findStart;
    _mr_c_function_table[52] = (void*)asm_mr_findGetNext;
    _mr_c_function_table[53] = (void*)asm_mr_findStop;  //54

    _mr_c_function_table[54] = (void*)asm_mr_exit;
    _mr_c_function_table[55] = (void*)asm_mr_startShake;
    _mr_c_function_table[56] = (void*)asm_mr_stopShake;
    _mr_c_function_table[57] = (void*)asm_mr_playSound;
    _mr_c_function_table[58] = (void*)asm_mr_stopSound;  //59

    _mr_c_function_table[59] = (void*)asm_mr_sendSms;
    _mr_c_function_table[60] = (void*)asm_mr_call;
    _mr_c_function_table[61] = (void*)mr_getNetworkID;
    _mr_c_function_table[62] = (void*)asm_mr_connectWAP;

    _mr_c_function_table[63] = (void*)mr_menuCreate;
    _mr_c_function_table[64] = (void*)mr_menuSetItem;
    _mr_c_function_table[65] = (void*)mr_menuShow;
    _mr_c_function_table[66] = (void*)NULL;  //mr_menuSetFocus,
    _mr_c_function_table[67] = (void*)mr_menuRelease;
    _mr_c_function_table[68] = (void*)mr_menuRefresh;
    _mr_c_function_table[69] = (void*)asm_mr_dialogCreate;
    _mr_c_function_table[70] = (void*)asm_mr_dialogRelease;
    _mr_c_function_table[71] = (void*)asm_mr_dialogRefresh;
    _mr_c_function_table[72] = (void*)asm_mr_textCreate;
    _mr_c_function_table[73] = (void*)asm_mr_textRelease;
    _mr_c_function_table[74] = (void*)asm_mr_textRefresh;
    _mr_c_function_table[75] = (void*)asm_mr_editCreate;
    _mr_c_function_table[76] = (void*)asm_mr_editRelease;
    _mr_c_function_table[77] = (void*)asm_mr_editGetText;
    _mr_c_function_table[78] = (void*)mr_winCreate;
    _mr_c_function_table[79] = (void*)mr_winRelease;

    _mr_c_function_table[80] = (void*)asm_mr_getScreenInfo;

    _mr_c_function_table[81] = (void*)asm_mr_initNetwork;
    _mr_c_function_table[82] = (void*)asm_mr_closeNetwork;
    _mr_c_function_table[83] = (void*)asm_mr_getHostByName;
    _mr_c_function_table[84] = (void*)asm_mr_socket;
    _mr_c_function_table[85] = (void*)asm_mr_connect;
    _mr_c_function_table[86] = (void*)asm_mr_closeSocket;
    _mr_c_function_table[87] = (void*)asm_mr_recv;
    _mr_c_function_table[88] = (void*)asm_mr_recvfrom;
    _mr_c_function_table[89] = (void*)asm_mr_send;
    _mr_c_function_table[90] = (void*)asm_mr_sendto;

    _mr_c_function_table[91] = (void*)&mr_screenBuf;
    _mr_c_function_table[92] = (void*)&mr_screen_w;
    _mr_c_function_table[93] = (void*)&mr_screen_h;
    _mr_c_function_table[94] = (void*)&mr_screen_bit;
    _mr_c_function_table[95] = (void*)mr_bitmap;
    _mr_c_function_table[96] = (void*)mr_tile;
    _mr_c_function_table[97] = (void*)mr_map;
    _mr_c_function_table[98] = (void*)mr_sound;
    _mr_c_function_table[99] = (void*)mr_sprite;

    _mr_c_function_table[100] = (void*)pack_filename;
    _mr_c_function_table[101] = (void*)start_filename;
    _mr_c_function_table[102] = (void*)old_pack_filename;
    _mr_c_function_table[103] = (void*)old_start_filename;

    _mr_c_function_table[104] = (void*)&mr_ram_file;
    _mr_c_function_table[105] = (void*)&mr_ram_file_len;

    _mr_c_function_table[106] = (void*)&mr_soundOn;
    _mr_c_function_table[107] = (void*)&mr_shakeOn;

    _mr_c_function_table[108] = (void*)&LG_mem_base;
    _mr_c_function_table[109] = (void*)&LG_mem_len;
    _mr_c_function_table[110] = (void*)&LG_mem_end;
    _mr_c_function_table[111] = (void*)&LG_mem_left;

    _mr_c_function_table[112] = (void*)&mr_sms_cfg_buf;
    _mr_c_function_table[113] = (void*)mr_md5_init;
    _mr_c_function_table[114] = (void*)mr_md5_append;
    _mr_c_function_table[115] = (void*)mr_md5_finish;
    _mr_c_function_table[116] = (void*)asm_mr_load_sms_cfg;
    _mr_c_function_table[117] = (void*)asm_mr_save_sms_cfg;
    _mr_c_function_table[118] = (void*)asm_DispUpEx;

    _mr_c_function_table[119] = (void*)asm_DrawPoint;
    _mr_c_function_table[120] = (void*)asm_DrawBitmap;
    _mr_c_function_table[121] = (void*)asm_DrawBitmapEx;
    _mr_c_function_table[122] = (void*)asm_DrawRect;
    _mr_c_function_table[123] = (void*)asm_DrawText;
    _mr_c_function_table[124] = (void*)asm_BitmapCheck;
    _mr_c_function_table[125] = (void*)asm_mr_readFile;
    _mr_c_function_table[126] = (void*)wstrlen;
    _mr_c_function_table[127] = (void*)asm_mr_registerAPP;
    _mr_c_function_table[128] = (void*)asm_DrawTextEx;  //1936
    _mr_c_function_table[129] = (void*)asm_mr_EffSetCon;
    _mr_c_function_table[130] = (void*)asm_mr_TestCom;
    _mr_c_function_table[131] = (void*)asm_mr_TestCom1;  //1938
    _mr_c_function_table[132] = (void*)asm_c2u;          //1939
    _mr_c_function_table[133] = (void*)_mr_div;          //1941
    _mr_c_function_table[134] = (void*)_mr_mod;

    _mr_c_function_table[135] = (void*)&LG_mem_min;
    _mr_c_function_table[136] = (void*)&LG_mem_top;
    _mr_c_function_table[137] = (void*)asm_mr_updcrc;        //1943
    _mr_c_function_table[138] = (void*)start_fileparameter;  //1945
    _mr_c_function_table[139] = (void*)&mr_sms_return_flag;  //1949
    _mr_c_function_table[140] = (void*)&mr_sms_return_val;
    _mr_c_function_table[141] = (void*)asm_mr_unzip;         //1950
    _mr_c_function_table[142] = (void*)&mr_exit_cb;          //1951
    _mr_c_function_table[143] = (void*)&mr_exit_cb_data;     //1951
    _mr_c_function_table[144] = (void*)mr_entry;             //1952
    _mr_c_function_table[145] = (void*)asm_mr_platDrawChar;  //2004
    _mr_c_function_table[146] = (void*)&LG_mem_free;         //1967,2009

    _mr_c_function_table[147] = (void*)asm_mr_transbitmapDraw;
    _mr_c_function_table[148] = (void*)asm_mr_drawRegion;
    _mr_c_function_table[149] = NULL;
}

void _DrawPoint(int16 x, int16 y, uint16 nativecolor) {
    if (x < 0 || y < 0 || x >= MR_SCREEN_W || y >= MR_SCREEN_H) {
        return;
    }
    *MR_SCREEN_CACHE_POINT(x, y) = nativecolor;
}

void _DrawBitmap(uint16* p, int16 x, int16 y, uint16 w, uint16 h, uint16 rop, uint16 transcoler, int16 sx, int16 sy, int16 mw) {
    uint16 *dstp, *srcp;
    uint16 dx, dy;
    int MinX, MinY, MaxX, MaxY;

    MinY = MAX(0, y);
    MinX = MAX(0, x);
    MaxX = MIN(MR_SCREEN_W, x + w);
    MaxY = MIN(MR_SCREEN_H, y + h);

    if (rop > MR_SPRITE_TRANSPARENT) {
        uint16 BitmapRop = rop & MR_SPRITE_INDEX_MASK;
        uint16 BitmapMode = (rop >> MR_TILE_SHIFT) & 0x3;
        uint16 BitmapFlip = (rop >> MR_TILE_SHIFT) & 0x4;
        switch (BitmapRop) {
            case BM_TRANSPARENT:
                for (dy = MinY; dy < MaxY; dy++) {
                    dstp = MR_SCREEN_CACHE_POINT(MinX, dy);
                    srcp = p + (dy - y) * w + (MinX - x);
                    for (dx = MinX; dx < MaxX; dx++) {
                        if (*srcp != transcoler)
                            *dstp = *srcp;
                        dstp++;
                        srcp++;
                    }
                }
                break;
            case BM_COPY:
                switch (BitmapMode) {
                    case MR_ROTATE_0:
                        if (MaxX > MinX) {
                            for (dy = MinY; dy < MaxY; dy++) {
                                dstp = MR_SCREEN_CACHE_POINT(MinX, dy);
                                srcp = BitmapFlip ? p + (h - 1 - (dy - y)) * w + (MinX - x) : p + (dy - y) * w + (MinX - x);
                                MEMCPY(dstp, srcp, (MaxX - MinX) << 1);
                                /*
                                for (dx = MinX; dx < MaxX; dx++)
                                {
                                *dstp = *srcp;
                                dstp++;
                                srcp++;
                                }
                                */
                            }
                        }
                        break;
                    case MR_ROTATE_90:
                        for (dy = MinY; dy < MaxY; dy++) {
                            dstp = MR_SCREEN_CACHE_POINT(MinX, dy);
                            srcp = BitmapFlip ? p + (h - 1 - (MinX - x)) * w + (w - 1 - (dy - y)) : p + (MinX - x) * w + (w - 1 - (dy - y));
                            for (dx = MinX; dx < MaxX; dx++) {
                                *dstp = *srcp;
                                dstp++;
                                srcp = BitmapFlip ? srcp - w : srcp + w;
                            }
                        }
                        break;
                    case MR_ROTATE_180:
                        for (dy = MinY; dy < MaxY; dy++) {
                            dstp = MR_SCREEN_CACHE_POINT(MinX, dy);
                            srcp = BitmapFlip ? p + (dy - y) * w + (w - 1 - (MinX - x)) : p + (h - 1 - (dy - y)) * w + (w - 1 - (MinX - x));
                            for (dx = MinX; dx < MaxX; dx++) {
                                *dstp = *srcp;
                                dstp++;
                                srcp--;
                            }
                        }
                        break;
                    case MR_ROTATE_270:
                        for (dy = MinY; dy < MaxY; dy++) {
                            dstp = MR_SCREEN_CACHE_POINT(MinX, dy);
                            srcp = BitmapFlip ? p + (MinX - x) * w + (dy - y) : p + (h - 1 - (MinX - x)) * w + (dy - y);
                            for (dx = MinX; dx < MaxX; dx++) {
                                *dstp = *srcp;
                                dstp++;
                                srcp = BitmapFlip ? srcp + w : srcp - w;
                            }
                        }
                        break;
                }
        }
    } else {
        switch (rop) {
            case BM_TRANSPARENT:
                for (dy = MinY; dy < MaxY; dy++) {
                    dstp = MR_SCREEN_CACHE_POINT(MinX, dy);
                    srcp = p + (dy - y + sy) * mw + (MinX - x + sx);
                    for (dx = MinX; dx < MaxX; dx++) {
                        if (*srcp != transcoler)
                            *dstp = *srcp;
                        dstp++;
                        srcp++;
                    }
                }
                break;
            case BM_COPY:
                if (MaxX > MinX) {
                    for (dy = MinY; dy < MaxY; dy++) {
                        //dstp = mr_screenBuf + dy * MR_SCREEN_MAX_W + MinX;
                        dstp = MR_SCREEN_CACHE_POINT(MinX, dy);
                        srcp = p + (dy - y + sy) * mw + (MinX - x + sx);
                        MEMCPY(dstp, srcp, (MaxX - MinX) << 1);
                        /*
                        for (dx = MinX; dx < MaxX; dx++)
                        {
                        *dstp = *srcp;
                        dstp++;
                        srcp++;
                        }
                        */
                    }
                }
                break;
            case BM_GRAY:
            case BM_OR:
            case BM_XOR:
            case BM_NOT:
            case BM_MERGENOT:
            case BM_ANDNOT:
            case BM_AND:
            case BM_REVERSE:
                for (dy = MinY; dy < MaxY; dy++) {
                    dstp = MR_SCREEN_CACHE_POINT(MinX, dy);
                    srcp = p + (dy - y + sy) * mw + (MinX - x + sx);
                    for (dx = MinX; dx < MaxX; dx++) {
                        switch (rop) {
                            case BM_GRAY:
                                if (*srcp != transcoler) {
                                    uint32 color_old = *srcp;
                                    uint32 r, g, b;
                                    r = ((color_old & 0xf800) >> 11);
                                    g = ((color_old & 0x7e0) >> 6);
                                    b = ((color_old & 0x1f));
                                    r = (r * 60 + g * 118 + b * 22) / 25;
                                    *dstp = MAKERGB(r, r, r);
                                }
                                break;
                            case BM_REVERSE:
                                if (*srcp != transcoler) {
                                    *dstp = ~*srcp;
                                }
                                break;
                            case BM_OR:
                                *dstp = (*srcp) | (*dstp);
                                break;
                            case BM_XOR:
                                *dstp = (*srcp) ^ (*dstp);
                                break;
                            case BM_NOT:
                                *dstp = ~(*srcp);
                                break;
                            case BM_MERGENOT:
                                *dstp = (~*srcp) | (*dstp);
                                break;
                            case BM_ANDNOT:
                                *dstp = (~*srcp) & (*dstp);
                                break;
                            case BM_AND:
                                *dstp = (*srcp) & (*dstp);
                                break;
                        }
                        dstp++;
                        srcp++;
                    }
                }
                break;
        }
    }
}

void DrawRect(int16 x, int16 y, int16 w, int16 h, uint8 r, uint8 g, uint8 b) {
    uint16 *dstp, *srcp;
    int MaxY, MaxX, MinY, MinX;
    uint16 dx, dy;
    uint16 nativecolor;

    MaxY = MIN(MR_SCREEN_H, y + h);
    MaxX = MIN(MR_SCREEN_W, x + w);
    MinY = MAX(0, y);
    MinX = MAX(0, x);
    nativecolor = MAKERGB(r, g, b);

    if ((MaxY > MinY) && (MaxX > MinX)) {
#if 0
		// for align speed test
		srcp = MR_MALLOC((MaxX - MinX)<<1+8);
		dstp = srcp;
		for (dx = MinX; dx < MaxX; dx++)
		{
			*dstp= nativecolor;
			dstp++;
		}
		for (dy=MinY; dy < MaxY; dy++)
		{
			dstp = mr_screenBuf + dy * MR_SCREEN_MAX_W + MinX;
			memcpy(dstp, srcp+1, (MaxX - MinX)<<1);
			/*
			for (dx = MinX; dx < MaxX; dx++)
			{
			*dstp = nativecolor;
			dstp++;
			}
			*/
		}
		MR_FREE(srcp, (MaxX - MinX)<<1+8);
#endif
#if 0
		// for align test, shut down
		dstp = mr_screenBuf + MinY * MR_SCREEN_MAX_W + MinX;
		srcp = dstp;
		for (dx = MinX; dx < MaxX; dx++)
		{
			*dstp = nativecolor;
			dstp++;
		}
		for (dy=MinY+1; dy < MaxY; dy++)
		{
			dstp = mr_screenBuf + dy * MR_SCREEN_MAX_W + MinX;
			//memcpy(dstp, srcp, (MaxX - MinX)<<1);
			for (dx = MinX; dx < MaxX; dx++)
			{
				*dstp = nativecolor;
				dstp++;
			}
		}

#else
        dstp = MR_SCREEN_CACHE_POINT(MinX, MinY);
        srcp = dstp;
        for (dx = MinX; dx < MaxX; dx++) {
            *dstp = nativecolor;
            dstp++;
        }

        if (((uint32)srcp & 0x00000003) != 0) {
            //srcp = ((srcp+1) & 0xfffffffc);
            srcp++;
            for (dy = MinY + 1; dy < MaxY; dy++) {
                dstp = MR_SCREEN_CACHE_POINT(MinX, dy);
                *dstp = nativecolor;
                //dstp = ((dstp+1) & 0xfffffffc);
                dstp++;
                MEMCPY(dstp, srcp, (MaxX - MinX - 1) << 1);
                /*
				for (dx = MinX; dx < MaxX; dx++)
				{
				*dstp = nativecolor;
				dstp++;
				}
				*/
            }
        } else {
            for (dy = MinY + 1; dy < MaxY; dy++) {
                dstp = MR_SCREEN_CACHE_POINT(MinX, dy);
                MEMCPY(dstp, srcp, (MaxX - MinX) << 1);
                /*
				for (dx = MinX; dx < MaxX; dx++)
				{
				*dstp = nativecolor;
				dstp++;
				}
				*/
            }
        }
#endif
    }
}

int32 _DrawText(char* pcText, int16 x, int16 y, uint8 r, uint8 g, uint8 b, int is_unicode, uint16 font) {
    int TextSize;
    uint16* tempBuf;

#ifdef MYTHROAD_DEBUG
    if (!pcText) {
        MRDBGPRINTF("DrawText x=%d: txt is nil!", x);
        goto end;
    }
#endif

    if (!is_unicode) {
        tempBuf = c2u((const char*)pcText, NULL, &TextSize);
        if (!tempBuf) {
            MRDBGPRINTF("DrawText x=%d:c2u err!", x);
            goto end;
        }
    } else {
        tempBuf = (uint16*)pcText;
    }

    {
        uint16 ch;
        int width, height;
        const char* current_bitmap;
        uint8* p = (uint8*)tempBuf;
        // int32 X1,Y1;
        // uint16 a_,b_;
        uint16 chx = x, chy = y;
        // uint16 color=MAKERGB(r, g, b);
        ch = (uint16)((*p << 8) + *(p + 1));
        while (ch) {
            current_bitmap = mr_getCharBitmap(ch, font, &width, &height);
            if (current_bitmap) {
                //MRDBGPRINTF("mr_platDrawChar 21!");
#ifndef MR_PLAT_DRAWTEXT
#ifndef MR_VIA_MOD
#ifndef MR_FONT_LIB_REDUNDANCY_BIT
                int32 font_data_size = ((width * height) + 7) >> 3;
                int32 X2 = 0, Y2;
                X1 = chx;
                Y1 = chy;
                while (font_data_size--) {
                    uint8 pattern = *current_bitmap++;

                    if (!pattern) {
                        int32 nTemp;

                        X2 += 8;
                        nTemp = X2 / width;

                        if (nTemp) {
                            Y1 += nTemp;

                            height -= nTemp;

                            if (!height)
                                break;
                        }

                        X2 %= width;
                        X1 = chx + X2;
                    } else {
                        for (Y2 = 0; Y2 < 8; Y2++) {
#ifdef MTK_MOD
                            if (pattern & 1)
#else
                            if (pattern & 0x80)
#endif
                                _DrawPoint(X1, Y1, color);
                            ++X2;
                            if (X2 == width) {
                                X1 = chx;
                                height--;
                                ++Y1;

                                if (height == 0)
                                    break;
                                X2 = 0;
                            } else {
                                ++X1;
                            }
#ifdef MTK_MOD
                            pattern >>= 1;
#else
                            pattern <<= 1;
#endif
                        }
                    }
                }
#else

#ifndef MR_FONT_LIB_REDUNDANCY_BIT24
                for (Y1 = 0; Y1 < height; Y1++)
                    for (X1 = 0; X1 < width; X1++) {
                        a_ = (X1 & (0x07));
                        b_ = Y1 * ((width + 7) >> 3) + ((X1 & 0xF8) >> 3);
                        if (((uint16)(current_bitmap[b_])) & (0x80 >> a_))
                            _DrawPoint((int16)(chx + X1), (int16)(chy + Y1), color);
                    };
#else
                for (Y1 = 0; Y1 < height; Y1++)
                    for (X1 = 0; X1 < width; X1++) {
                        a_ = (X1 & (0x07));
                        b_ = Y1 * 3 + ((X1 & 0xF8) >> 3);
                        if (((uint16)(current_bitmap[b_])) & (0x80 >> a_))
                            _DrawPoint((int16)(chx + X1), (int16)(chy + Y1), color);
                    };
#endif

#endif
#else  //defined MR_VIA_MOD
                for (X1 = 0; X1 < width; X1++)
                    for (Y1 = 0; Y1 < height; Y1++) {
                        a_ = (Y1 & (0x07));
                        b_ = X1 + ((Y1 & 0xF8) >> 3) * width;
                        if (((uint16)(current_bitmap[b_])) & (0x01 << a_))
                            _DrawPoint((int16)(chx + X1), (int16)(chy + Y1), color);
                    };
#endif
#else  // MR_PLAT_DRAWTEXT
                mr_platDrawChar(ch, chx, chy, MAKERGB(r, g, b));
#endif
                chx = chx + width;
            };
            p += 2;
            ch = (uint16)((*p << 8) + *(p + 1));
        };
    }
    if (!is_unicode) {
        MR_FREE((void*)tempBuf, TextSize);
    }
end:
    return 0;
}

int32 _DrawTextEx(char* pcText, int16 x, int16 y, mr_screenRectSt rect, mr_colourSt colorst, int flag, uint16 font) {
    int TextSize, endchar_index;
    uint16* tempBuf;
    uint16 ch;

    endchar_index = 0;

    if (!pcText) {
        MRDBGPRINTF("DrawTextEx x=%d: txt is nil!", x);
        goto end;
    }

    if (!(flag & DRAW_TEXT_EX_IS_UNICODE)) {
        tempBuf = c2u((const char*)pcText, NULL, &TextSize);
        if (!tempBuf) {
            MRDBGPRINTF("DrawTextEx x=%d:c2u err!", x);
            goto end;
        }
    } else {
        tempBuf = (uint16*)pcText;
    }

    {
        int width, height, mh;
        const char* current_bitmap;
        uint8* p = (uint8*)tempBuf;
        int32 X1, Y1;
        // uint16 a_,b_;
        uint16 chx = x, chy = y, color = MAKERGB(colorst.r, colorst.g, colorst.b);
        ch = (uint16)((*p << 8) + *(p + 1));
        mh = 0;
        while (ch) {
            if ((ch == 0x0a) || (ch == 0x0d)) {
                current_bitmap = mr_getCharBitmap(0x20, font, &width, &height);
            } else {
                current_bitmap = mr_getCharBitmap(ch, font, &width, &height);
            }
            if (current_bitmap) {
                // int32 font_data_size = ((width * height) + 7) >> 3;
                // int32 X2=0,Y2;
                if (flag & DRAW_TEXT_EX_IS_AUTO_NEWLINE) {
                    if (((chx + width) > (x + rect.w)) || (ch == 0x0a)) {
                        if ((chy + mh) < (y + rect.h)) {
                            endchar_index = p - (uint8*)tempBuf;
                        }
                        X1 = chx = x;
                        Y1 = chy = chy + mh + 2;
                        mh = 0;
                        if (Y1 > (y + rect.h)) {
                            break;
                        }
                    } else {
                        X1 = chx;
                        Y1 = chy;
                    }
                    mh = (mh > height) ? mh : height;
                } else {
                    if ((chx > (x + rect.w)) || (ch == 0x0a)) {
                        break;
                    }
                    if ((chx + width) > (x + rect.w)) {
                        endchar_index = p - (uint8*)tempBuf;
                    }
                    X1 = chx;
                    Y1 = chy;
                }

                if ((ch == 0x0a) || (ch == 0x0d)) {
                    p += 2;
                    ch = (uint16)((*p << 8) + *(p + 1));
                    continue;
                }
#ifndef MR_PLAT_DRAWTEXT
#ifndef MR_FONT_LIB_REDUNDANCY_BIT
#ifndef MR_VIA_MOD
                while (font_data_size--) {
                    uint8 pattern = *current_bitmap++;

                    if (!pattern) {
                        int32 nTemp;

                        X2 += 8;
                        nTemp = X2 / width;

                        if (nTemp) {
                            Y1 += nTemp;

                            height -= nTemp;

                            if (!height)
                                break;
                        }

                        X2 %= width;
                        X1 = chx + X2;
                    } else {
                        for (Y2 = 0; Y2 < 8; Y2++) {
#ifdef MTK_MOD
                            if (pattern & 1)
#else
                            if (pattern & 0x80)
#endif
                                if (X1 < (x + rect.w) && Y1 < (y + rect.h))
                                    _DrawPoint(X1, Y1, color);
                            ++X2;
                            if (X2 == width) {
                                X1 = chx;
                                height--;
                                ++Y1;

                                if (height == 0)
                                    break;
                                X2 = 0;
                            } else {
                                ++X1;
                            }
#ifdef MTK_MOD
                            pattern >>= 1;
#else
                            pattern <<= 1;
#endif
                        }
                    }
                }
#else  //defined MR_VIA_MOD
                for (X1 = 0; X1 < width; X1++)
                    for (Y1 = 0; Y1 < height; Y1++) {
                        a_ = (Y1 & (0x07));
                        b_ = X1 + ((Y1 & 0xF8) >> 3) * width;
                        if (((uint16)(current_bitmap[b_])) & (0x01 << a_))
                            _DrawPoint((int16)(chx + X1), (int16)(chy + Y1), color);
                    };
#endif

#else  //#ifndef MR_FONT_LIB_REDUNDANCY_BIT
                /*
				if(flag & DRAW_TEXT_EX_IS_AUTO_NEWLINE)
				{
				if(((chx + width) > (x + rect.w)) || (ch == 0x0a)){
				if ((chy + mh) < (y + rect.h) ){
				endchar_index = p - (uint8*)tempBuf;
				}
				chx = x;
				chy = chy + mh + 2;
				mh = 0;
				if(chy > (y + rect.h)){
				break;
				}
				}
				mh = (mh > height)? mh:height;
				}else{
				if((chx > (x + rect.w)) || (ch == 0x0a)){
				break;
				}
				if((chx + width) > (x + rect.w)){
				endchar_index = p - (uint8*)tempBuf;
				}
				}

				if ((ch == 0x0a) || (ch == 0x0d)){
				p+=2;
				ch = (uint16) ((*p<<8)+*(p+1));
				continue;
				}
				*/

#ifndef MR_FONT_LIB_REDUNDANCY_BIT24
                for (Y1 = 0; Y1 < height; Y1++)
                    for (X1 = 0; X1 < width; X1++) {
                        a_ = (X1 & (0x07));
                        b_ = Y1 * ((width + 7) >> 3) + ((X1 & 0xF8) >> 3);
                        if (((uint16)(current_bitmap[b_])) & (0x80 >> a_))
                            if ((chx + X1) < (x + rect.w) && (chy + Y1) < (y + rect.h))
                                _DrawPoint((int16)(chx + X1), (int16)(chy + Y1), color);
                    };
#else  //MR_FONT_LIB_REDUNDANCY_BIT24
                for (Y1 = 0; Y1 < height; Y1++)
                    for (X1 = 0; X1 < width; X1++) {
                        a_ = (X1 & (0x07));
                        b_ = Y1 * 3 + ((X1 & 0xF8) >> 3);
                        if (((uint16)(current_bitmap[b_])) & (0x80 >> a_))
                            if ((chx + X1) < (x + rect.w) && (chy + Y1) < (y + rect.h))
                                _DrawPoint((int16)(chx + X1), (int16)(chy + Y1), color);
                    };
#endif

#endif  //MR_FONT_LIB_REDUNDANCY_BIT

#else  //MR_PLAT_DRAWTEXT
                mr_platDrawChar(ch, chx, chy, color);
#endif

                chx = chx + width;
            };
            p += 2;
            ch = (uint16)((*p << 8) + *(p + 1));
        };
        if (!ch) {
            if (flag & DRAW_TEXT_EX_IS_AUTO_NEWLINE) {
                if ((chy + mh) < (y + rect.h)) {
                    endchar_index = wstrlen((char*)tempBuf);
                }
            } else {
                if (!((chx > (x + rect.w)) || (ch == 0x0a))) {
                    endchar_index = wstrlen((char*)tempBuf);
                }
            }
        }
        Y1 = X1;  // 避免 warning: variable ‘X1’ set but not used
    }

    if (!(flag & DRAW_TEXT_EX_IS_UNICODE)) {
        MR_FREE((void*)tempBuf, TextSize);
    }
end:
    return endchar_index;
}

int _BitmapCheck(uint16* p, int16 x, int16 y, uint16 w, uint16 h, uint16 transcoler, uint16 color_check) {
    uint16 *dstp, *srcp;
    int16 MaxY, MaxX, MinY, MinX;
    uint16 dx, dy;
    int nResult = 0;

    MaxY = MIN(MR_SCREEN_H, y + h);
    MaxX = MIN(MR_SCREEN_W, x + w);
    MinY = MAX(0, y);
    MinX = MAX(0, x);
    for (dy = MinY; dy < MaxY; dy++) {
        dstp = MR_SCREEN_CACHE_POINT(MinX, dy);
        srcp = p + (dy - y) * w + (MinX - x);
        for (dx = MinX; dx < MaxX; dx++) {
            if (*srcp != transcoler) {
                if (*dstp != color_check) {
                    nResult++;
                }
            }
            dstp++;
            srcp++;
        }
    }
    return nResult;
}

int _mr_EffSetCon(int16 x, int16 y, int16 w, int16 h, int16 perr, int16 perg, int16 perb) {
    uint16* dstp;
    uint32 color_old, coloer_new;
    int MaxY, MaxX, MinY, MinX;
    uint16 dx, dy;

    MaxY = MIN(MR_SCREEN_H, y + h);
    MaxX = MIN(MR_SCREEN_W, x + w);
    MinY = MAX(0, y);
    MinX = MAX(0, x);
    for (dy = MinY; dy < MaxY; dy++) {
        dstp = MR_SCREEN_CACHE_POINT(MinX, dy);
        for (dx = MinX; dx < MaxX; dx++) {
            color_old = *dstp;
            coloer_new = (((color_old & 0xf800) * perr) >> 8) & 0xf800;
            coloer_new |= (((color_old & 0x7e0) * perg) >> 8) & 0x7e0;
            coloer_new |= (((color_old & 0x1f) * perb) >> 8) & 0x1f;
            *dstp = (uint16)coloer_new;
            dstp++;
        }
    }
    return 0;
}

void _mr_showErrorInfo(const char* errstr) {
    int32 i;
    int32 len = STRLEN(errstr);
    char buf[16];

    MRDBGPRINTF(errstr);
    len = (len < (12 * 8)) ? len : 12 * 8;
    DrawRect(0, 0, (int16)MR_SCREEN_W, (int16)MR_SCREEN_H, (uint8)255, (uint8)255, (uint8)255);
    for (i = 0; i < len; i = i + 12) {
        MEMSET(buf, 0, sizeof(buf));
        MEMCPY(buf, errstr + i, ((len - i) > 12) ? 12 : (len - i));
        _DrawText(buf, (int16)0, (int16)((i / 12) * 18), 0, 0, 0, (int)FALSE, MR_FONT_MEDIUM);
    }

    mr_drawBitmap(mr_screenBuf, 0, 0, (uint16)MR_SCREEN_W, (uint16)MR_SCREEN_H);
    //MRF_DrawText(errstr, 2, 2, 0, 0,0);
}

static void _mr_readFileShowInfo(const char* filename, int32 code) {
    MRDBGPRINTF("mythroad_mini.c read file  \"%s\" err, code=%d", filename, code);
}

void* _mr_readFile(const char* filename, int* filelen, int lookfor) {
    uint32 reallen, found = 0;
    int32 oldlen, nTmp;
    uint32 len;
    void *filebuf, *retv;
    int32 f;
    char TempName[MR_MAX_FILENAME_SIZE];
    int is_rom_file = FALSE;

    MRDBGPRINTF("_mr_readFile('%s', %p, %d)", filename, filelen, lookfor);

    // 插件化mrp会使用到这部分代码，pack_filename="$",构造一个特殊的mrp放到mr_ram_file和mr_ram_file_len传进来
    if ((pack_filename[0] == '*') || (pack_filename[0] == '$')) {
        char* mr_m0_file;
        uint32 pos = 0;
        uint32 m0file_len;

        if (pack_filename[0] == '*') {                                /*m0 file?*/
            mr_m0_file = (char*)mr_m0_files[pack_filename[1] - 'A'];  //这里定义文件名为*A即是第一个m0文件 *B是第二个.........
        } else {
            mr_m0_file = mr_ram_file;
        }

        if (mr_m0_file == NULL) {
            if ((char*)mr_m0_files[pack_filename[1] - 'A'] == NULL) MRDBGPRINTF("mr_m0_files[%d] nil!", pack_filename[1] - 'A');
            if (mr_ram_file == NULL) MRDBGPRINTF("mr_ram_file nil!");
            _mr_readFileShowInfo(filename, 1001);
            goto err;
        }
        pos = pos + 4;
        MEMCPY(&len, &mr_m0_file[pos], 4);
        pos = pos + 4;

        if ((pack_filename[0] == '$')) {
            m0file_len = mr_ram_file_len;

#ifdef MR_AUTHORIZATION
            if (bi & MR_FLAGS_AI) {
                if (_mr_isMr(&mr_m0_file[52]) != MR_SUCCESS) {
                    _mr_readFileShowInfo("unauthorized", 3);
                    goto err;
                }
            }
#endif
        } else {
            MEMCPY(&m0file_len, &mr_m0_file[pos], 4);
        }
        pos = pos + len;
        while (!found) {
            if (((pos + 4) >= m0file_len) || (len < 1) || (len >= MR_MAX_FILE_SIZE)) {
                _mr_readFileShowInfo(filename, 1004);
                goto err;
            }
            MEMCPY(&len, &mr_m0_file[pos], 4);

            pos = pos + 4;
            if (((len + pos) >= m0file_len) || (len < 1) || (len >= MR_MAX_FILENAME_SIZE)) {
                _mr_readFileShowInfo(filename, 1002);
                goto err;
            }
            MEMSET(TempName, 0, sizeof(TempName));
            MEMCPY(TempName, &mr_m0_file[pos], len);
            pos = pos + len;
            if (STRCMP(filename, TempName) == 0) {
                if (lookfor == 1) {
                    goto ret1;
                }
                found = 1;
                MEMCPY(&len, &mr_m0_file[pos], 4);
                pos = pos + 4;
                if (((len + pos) > m0file_len) || (len < 1) || (len >= MR_MAX_FILE_SIZE)) {
                    _mr_readFileShowInfo(filename, 1003);
                    goto err;
                }
            } else {
                MEMCPY(&len, &mr_m0_file[pos], 4);
                pos = pos + 4 + len;
            }
        }

        *filelen = len;
        if (*filelen <= 0) {
            _mr_readFileShowInfo(filename, 1005);
            goto err;
        }

        if (lookfor == 2) {
            retv = (void*)&mr_m0_file[pos];
            goto end;
        }
        filebuf = &mr_m0_file[pos];
        is_rom_file = TRUE;

    } else { /*read file from efs , EFS 中的文件*/
        f = mr_open(pack_filename, MR_FILE_RDONLY);
        if (f == 0) {
            _mr_readFileShowInfo(filename, 2002);
            goto err;
        }

        {  // 从这里开始是新版的mrp处理
            uint32 headbuf[4];
            MEMSET(headbuf, 0, sizeof(headbuf));
            nTmp = mr_read(f, &headbuf, sizeof(headbuf));
            if ((nTmp != 16) || (headbuf[0] != 1196446285)) {
                mr_close(f);
                _mr_readFileShowInfo(filename, 3001);
                goto err;
            }
            if (headbuf[1] <= 232) {
                mr_close(f);
                _mr_readFileShowInfo(filename, 3051);
                goto err;
            }
            {  //新版mrp
                uint32 indexlen = headbuf[1] + 8 - headbuf[3];
                uint8* indexbuf = MR_MALLOC(indexlen);
                uint32 pos = 0;
                uint32 file_pos = 0, file_len = 0;
                if (!indexbuf) {
                    mr_close(f);
                    _mr_readFileShowInfo(filename, 3003);
                    goto err;
                }
                nTmp = mr_seek(f, headbuf[3] - 16, MR_SEEK_CUR);
                if (nTmp < 0) {
                    mr_close(f);
                    MR_FREE(indexbuf, indexlen);
                    _mr_readFileShowInfo(filename, 3002);
                    goto err;
                }

                nTmp = mr_read(f, indexbuf, indexlen);

                if ((nTmp != (int32)indexlen)) {
                    mr_close(f);
                    MR_FREE(indexbuf, indexlen);
                    _mr_readFileShowInfo(filename, 3003);
                    goto err;
                }

                while (!found) {
                    MEMCPY(&len, &indexbuf[pos], 4);
                    pos = pos + 4;
                    if (((len + pos) > indexlen) || (len < 1) || (len >= MR_MAX_FILENAME_SIZE)) {
                        mr_close(f);
                        MR_FREE(indexbuf, indexlen);
                        _mr_readFileShowInfo(filename, 3004);
                        goto err;
                    }
                    MEMSET(TempName, 0, sizeof(TempName));
                    MEMCPY(TempName, &indexbuf[pos], len);
                    pos = pos + len;

                    if (STRCMP(filename, TempName) == 0) {
                        if (lookfor == 1) {
                            mr_close(f);
                            MR_FREE(indexbuf, indexlen);
                            goto ret1;
                        }
                        found = 1;
                        file_pos = *(uint32*)(&indexbuf[pos]);
                        pos = pos + 4;
                        file_len = *(uint32*)(&indexbuf[pos]);
                        pos = pos + 4;
                        if ((file_pos + file_len) > headbuf[2]) {
                            mr_close(f);
                            MR_FREE(indexbuf, indexlen);
                            _mr_readFileShowInfo(filename, 3005);
                            goto err;
                        }
                    } else {
                        pos = pos + 12;
                        if (pos >= indexlen) {
                            mr_close(f);
                            MR_FREE(indexbuf, indexlen);
                            _mr_readFileShowInfo(filename, 3006);
                            goto err;
                        }
                    } /*if (STRCMP(filename, TempName)==0)*/
                }

                MR_FREE(indexbuf, indexlen);

                *filelen = file_len;
                filebuf = MR_MALLOC(file_len);
                if (filebuf == NULL) {
                    mr_close(f);
                    _mr_readFileShowInfo(filename, 3007);
                    goto err;
                }

                nTmp = mr_seek(f, file_pos, MR_SEEK_SET);
                if (nTmp < 0) {
                    MR_FREE(filebuf, file_len);
                    mr_close(f);
                    _mr_readFileShowInfo(filename, 3008);
                    goto err;
                }

                oldlen = 0;
                while (oldlen < file_len) {
                    nTmp = mr_read(f, (char*)filebuf + oldlen, file_len - oldlen);
                    if (nTmp <= 0) {
                        MR_FREE(filebuf, file_len);
                        mr_close(f);
                        _mr_readFileShowInfo(filename, 3009);
                        goto err;
                    }
                    oldlen = oldlen + nTmp;
                }
                mr_close(f);
            }
        }
        // 新版的mrp处理
    } /*efs file*/

    mr_gzInBuf = filebuf;
    LG_gzoutcnt = 0;
    LG_gzinptr = 0;

    if (mr_get_method(*filelen) < 0) {
        retv = filebuf;
        goto end;
    }

    reallen = *(uint32*)((uint8*)filebuf + *filelen - sizeof(uint32));

    oldlen = *filelen;
    *filelen = reallen;

    mr_gzOutBuf = MR_MALLOC(reallen);
    if (mr_gzOutBuf == NULL) {
        if (!is_rom_file)
            MR_FREE(mr_gzInBuf, oldlen);
        goto err;
    }

    if (mr_unzip() != 0) {
        if (!is_rom_file)
            MR_FREE(mr_gzInBuf, oldlen);
        MR_FREE(mr_gzOutBuf, reallen);
        MRDBGPRINTF("_mr_readFile: \"%s\" Unzip err!", filename);
        goto err;
    }

    if (!is_rom_file)
        MR_FREE(mr_gzInBuf, oldlen);

    retv = mr_gzOutBuf;
end:
    return retv;
err:
    return NULL;
ret1:
    return (void*)1;
}

int32 _DispUpEx(int16 x, int16 y, uint16 w, uint16 h) {
    if (mr_state == MR_STATE_RUN) {
        mr_drawBitmap(mr_screenBuf, x, y, (uint16)w, (uint16)h);
    }
    return 0;
}

int _mr_TestCom(mrp_State* L, int input0, int input1) {
    int ret = 0;
    MRDBGPRINTF("_mr_TestCom(0x%p, 0x%X, 0x%X", L, input0, input1);
    switch (input0) {
        case 1:
            ret = mr_getTime();
            break;
        case 2:
            mr_event_function = (MR_EVENT_FUNCTION)input1;
            break;
        case 3:
            mr_timer_function = (MR_TIMER_FUNCTION)input1;
            break;
        case 4:
            mr_stop_function = (MR_STOP_FUNCTION)input1;
            break;
        case 5:
            mr_pauseApp_function = (MR_PAUSEAPP_FUNCTION)input1;
            break;
        case 6:
            mr_resumeApp_function = (MR_RESUMEAPP_FUNCTION)input1;
            break;

#ifdef MR_PLAT_DRAWTEXT
        case 7:
            return input1;
#endif

#ifdef MR_VIA_MOD
        case 8:
            return input1;
#endif
        case 9:
            mrc_appInfo_st.ram = input1;
            break;
        case 100:
            ret = LG_mem_min;
            break;
        case 101:
            ret = LG_mem_top;
            break;
        case 102:
            ret = LG_mem_left;
            break;
        case 200:
            if (!(mr_state == MR_STATE_RUN) || (!mr_shakeOn)) {
                ret = MR_SUCCESS;
                break;
            }
            ret = mr_startShake(input1);
            break;
        case 201:
            //ret = mr_stopShake();
            break;
        case 300:
            mr_soundOn = input1;
            break;
        case 301:
            mr_shakeOn = input1;
            break;
        case 302:
            bi = bi | MR_FLAGS_RI;
            break;
        case 303:
            bi = bi & (~MR_FLAGS_RI);
            break;
        case 304:
            bi = bi | MR_FLAGS_EI;
            break;
        case 305:
            bi = bi & (~MR_FLAGS_EI);
            break;
        case 306:
            mr_sms_return_flag = 1;
            mr_sms_return_val = input1;
            break;
        case 307:
            mr_sms_return_flag = 0;
            break;
        case 400:
            mr_sleep(input1);
            break;
        case 401:
            ret = MR_SCREEN_MAX_W;
            MR_SCREEN_MAX_W = input1;
            break;
        case 404:
            ret = _mr_newSIMInd((int16)input1, NULL);
            break;
        case 405:
            ret = mr_closeNetwork();
            break;
        case 406:
            ret = MR_SCREEN_H;
            MR_SCREEN_H = input1;
            break;
        case 407:
            mr_timer_run_without_pause = input1;
            mr_plat(1202, input1);
            break;

        case 408:
            if (mr_bitmap[BITMAPMAX].type == MR_SCREEN_FIRST_BUF) {
                mr_bitmap[BITMAPMAX].p = (uint16*)MR_MALLOC(input1);
                if (mr_bitmap[BITMAPMAX].p) {
                    MR_FREE(mr_screenBuf, mr_bitmap[BITMAPMAX].buflen);
                    mr_screenBuf = mr_bitmap[BITMAPMAX].p;
                    mr_bitmap[BITMAPMAX].buflen = input1;
                    ret = MR_SUCCESS;
                } else {
                    ret = MR_FAILED;
                }
            } else if (mr_bitmap[BITMAPMAX].type == MR_SCREEN_SECOND_BUF) {
                if (mr_bitmap[BITMAPMAX].buflen >= input1) {
                    ret = MR_SUCCESS;
                } else {
                    ret = MR_FAILED;
                }
            }
            break;

        case 500:
#ifdef MR_SM_SURPORT
            ret = _mr_load_sms_cfg();  //only for sm dsm;
#endif
            break;
        case 503:
#ifdef MR_SM_SURPORT
        {
            uint8 flag = 0;
            _mr_smsGetBytes(CFG_USE_UNICODE_OFFSET, (char*)&flag, 1);
            ret = flag;
        }
#endif
        break;
        case 504:
            ret = _mr_save_sms_cfg(input1);
            break;
        case 3629:
            if (input1 == 2913)
                bi = bi | MR_FLAGS_BI;
            break;
        case 3921:
            if (input1 == 98352)
                bi = bi | MR_FLAGS_AI;
            break;
        case 3251:
            if (input1 == 648826)
                bi = bi & (~MR_FLAGS_AI);
            break;
    }
    return ret;
}

int32 _mr_c_function_new(MR_C_FUNCTION f, int32 len) {
    if (mr_c_function_P) {
        MR_FREE(mr_c_function_P, mr_c_function_P_len);
    }
    mr_c_function_P = MR_MALLOC(len);
    if (!mr_c_function_P) {
        mr_state = MR_STATE_ERROR;
        return MR_FAILED;
    }
    mr_c_function_P_len = len;
    MEMSET(mr_c_function_P, 0, mr_c_function_P_len);
    mr_c_function = f;
    MRDBGPRINTF("mr_c_function: 0x%X, mr_c_function_P: 0x%X, len: %d", mr_c_function, mr_c_function_P, len);
    *((void**)(mr_load_c_function)-1) = mr_c_function_P;
    return MR_SUCCESS;
}

int _mr_TestCom1(mrp_State* L, int input0, char* input1, int32 len) {
    int ret = 0;

    MRDBGPRINTF("_mr_TestCom1(0x%p, 0x%X, 0x%p, 0x%d)", L, input0, input1, len);
    switch (input0) {
        case 2:
            if (mr_ram_file) {
                MR_FREE(mr_ram_file, mr_ram_file_len);
                mr_ram_file = NULL;
            }
            mr_ram_file = input1;
            mr_ram_file_len = len;
            break;
        case 3: {
            MEMSET(old_pack_filename, 0, sizeof(old_pack_filename));
            if (input1) {
                STRNCPY(old_pack_filename, input1, sizeof(old_pack_filename) - 1);
            }
            MEMSET(old_start_filename, 0, sizeof(old_start_filename));
            STRNCPY(old_start_filename, MR_START_FILE, sizeof(old_start_filename) - 1);
            break;
        }
        case 4: {
            MEMSET(start_fileparameter, 0, sizeof(start_fileparameter));
            if (input1) {
                STRNCPY(start_fileparameter, input1, sizeof(start_fileparameter) - 1);
            }
            break;
        }
            //1948 add exception set
        case 5:
            mr_exception_str = input1;
            break;
        case 6:
            mr_exception_str = NULL;
            break;
            //1948 add exception set
        case 9: {
            // extern int32 clean_arm9_dcache(uint32 addr, uint32 len);
            // extern int32 invalidate_arm9_icache(int32 addr, int32 len);

            // clean_arm9_dcache((uint32)((uint32)(input1)&(~0x0000001F)), ((len+0x0000001F*3)&(~0x0000001F)));
            // invalidate_arm9_icache((uint32)((uint32)(input1)&(~0x0000001F)), ((len+0x0000001F*3)&(~0x0000001F)));
            mr_printf("[WARN]_mr_TestCom1 mr_cacheSyncRaw 0x%p, %d", input1, len);
            // writeFile("dump.data", input1, len);
            mr_cacheSync((void*)((uint32)(input1) & (~0x0000001F)), ((len + 0x0000001F * 3) & (~0x0000001F)));
            break;
        }
        case 200:
            mr_updcrc(NULL, 0); /* initialize crc */
            mr_updcrc((unsigned char*)input1, len);
            ret = mr_updcrc((unsigned char*)input1, 0);
            break;
        case 300: {
            break;
        }
        case 700: {
            int type = len;
            ret = _mr_newSIMInd(type, (uint8*)input1);
            break;
        }
        case 701: {
            uint8* pNum = ((uint8*)(input1 + 1));
            int32 type = *((int32*)(input1 + 2));
            ret = mr_smsIndiaction((uint8*)input1, len, pNum, type);
            break;
        }
        case 900:
            ret = mr_platEx(200001, (uint8*)_mr_c_port_table, sizeof(_mr_c_port_table), NULL, NULL, NULL);
            break;
    }
    return ret;
}

static int _mr_TestComC(int input0, char* input1, int32 len, int32 code) {
    int ret = 0;
    switch (input0) {
        case 800: {
            mr_load_c_function = (MR_LOAD_C_FUNCTION)(input1 + 8);
            *((void**)(input1)) = (void*)_mr_c_function_table;
            // extern int32 clean_arm9_dcache(uint32 addr, uint32 len);
            // extern int32 invalidate_arm9_icache(int32 addr, int32 len);
            // clean_arm9_dcache((uint32)((uint32)(input1)&(~0x0000001F)), ((len+0x0000001F*3)&(~0x0000001F)));
            // invalidate_arm9_icache((uint32)((uint32)(input1)&(~0x0000001F)), ((len+0x0000001F*3)&(~0x0000001F)));
            mr_printf("[WARN]_mr_TestComC mr_cacheSyncRaw 0x%p, %d", input1, len);
            mr_cacheSync((void*)((uint32)(input1) & (~0x0000001F)), ((len + 0x0000001F * 3) & (~0x0000001F)));
            MRDBGPRINTF("mr_load_c_function: 0x%X", mr_load_c_function);
            fixR9_saveMythroad();
            ret = mr_load_c_function(code);
        } break;
        case 801: {
            int32 output_len = 0;
            uint8* output = NULL;
            fixR9_saveMythroad();
            ret = mr_c_function(mr_c_function_P, code, (uint8*)input1, len, (uint8**)&output, &output_len);
        } break;
    }
    return ret;
}

typedef enum {
    MRP_ORICODING,    //直接读取编码。只有斯凯的特权用户方可执行该类型操作。
    MRP_FILENAME,     //MRP文件名称，最大11个有效字符，不包括'\0'
    MRP_APPNAME,      //MRP应用名称，用户可见的应用名，最大23个有效字符，不包括'\0'，例如"雷电1944"。
    MRP_APPID,        //每个应用对应一个唯一的ID，uint32类型。
    MRP_APPVER,       //uint32类型
    MRP_VENDER,       //开发商信息，最大39个有效字符，不包括'\0'。
    MRP_DESCRIPTION,  //应用描述信息 ，最大63个有效字符
    MRP_VERSION,      //计费通道版本编号,uint16类型，两个字节。
    MRP_CHANNEL,      //计费通道编号,两个字节，低地址的RecBuf[0]是移动，高地址的RecBuf[1]是联通。
    MRP_RAM,          //MRP启动需要的RAM大小
    MRP_NONE
} E_MRP_INFOID;

/*
函数名称:		mrc_GetMrpInfo

函数功能:		从当前MRP文件中读取头信息。

输入参数:		CMD，操作命令码。
RecBuf，接收返回数据的缓冲区指针；
BufLen，接收返回数据的缓冲区字节数；

返回值:			当操作不支持、操作失败等情况时，函数返回值小于等于0；
若操作成功，函数返回值为RecBuf中实际填写的字节数。
*/
#define MRP_FILENAME_LEN 12
static int32 mrc_GetMrpInfoClose(int32 IsFixed, int32 handle) {
    if (!handle)
        return MR_FAILED;
    if (IsFixed)
        return MR_SUCCESS;
    else
        return mr_close(handle);
}

static int32 mrc_GetMrpInfoOpen(char* MrpName, int32* IsFixed) {
    uint32 Handle = 0;
    MRDBGPRINTF("mrc_GetMrpInfoOpen:%s", MrpName);
    if (!IsFixed || !MrpName)
        return 0;
    if (MrpName[0] == '*') { /*m0 file?*/
        *IsFixed = 1;
        Handle = (uint32)mr_m0_files[MrpName[1] - 'A'];
    } else if (MrpName[0] == '$') {
        *IsFixed = 1;
        Handle = (uint32)mr_ram_file;
    } else {
        *IsFixed = 0;
        Handle = mr_open(MrpName, MR_FILE_RDONLY);
    }
    return Handle;
}

static int32 mrc_GetMrpInfoRead(int32 IsFixed, int32 Handle, int32 Offset, uint8* RecBuf, int32 BufLen) {
    int32 ret;
    if (!RecBuf)
        return MR_FAILED;

    if (IsFixed) {
        memcpy2(RecBuf, (uint8*)Handle + Offset, BufLen);
        ret = BufLen;
    } else {
        ret = mr_seek(Handle, Offset, MR_SEEK_SET);
        if (MR_SUCCESS != ret)
            return MR_FAILED;
        ret = mr_read(Handle, RecBuf, BufLen);
        if (ret != BufLen)
            return MR_FAILED;
    }
    return ret;
}

int32 mrc_GetMrpInfoEx(int32 IsFixed, int32 Handle, E_MRP_INFOID CMD, uint8* RecBuf, int32 BufLen) {
    int32 ret = MR_FAILED;
    uint32 temp, *p32;
    //LIB_EXB_LOG(("mrc_GetMrpInfo:开始入参检查。"));
    memset2(RecBuf, 0, BufLen);
    switch (CMD) {
#if 0
	case MRP_FILENAME:{//MRP文件名称，最大11个有效字符，不包括'\0'
		int32 DotOffset=0;
		if(BufLen<12)
			break;	
		ret=mrc_GetMrpInfoRead(IsFixed,Handle,16,RecBuf,12);
		pDot= (char*)strrchr((char *)RecBuf,'.');
		DotOffset = (int32)pDot -(int32)RecBuf ;
		memset(RecBuf+DotOffset,0,BufLen-DotOffset);			
		break;		
	}
	case MRP_APPNAME://MRP应用名称，用户可见的应用名，最大23个有效字符，不包括'\0'。
		if(BufLen<24)
			break;	
		ret=mrc_GetMrpInfoRead(IsFixed,Handle,28,RecBuf,24);
		break;
#endif
        case MRP_APPID:
        case MRP_APPVER:  //uint32类型
            if (BufLen < 4)
                break;
            temp = (CMD == MRP_APPID) ? 192 : 196;
            ret = mrc_GetMrpInfoRead(IsFixed, Handle, temp, RecBuf, 4);
            p32 = (uint32*)RecBuf;
            temp = *p32;
            temp = htonl(temp);  //MTK平台，需要转为网络字节序
            *(uint32*)RecBuf = temp;
            break;
        case MRP_RAM:  //uint32类型
        {
            uint16 ram, ram_check;
            if (BufLen < 4)
                break;
            ret = mrc_GetMrpInfoRead(IsFixed, Handle, 228, (uint8*)&ram, 2);
            ret = mrc_GetMrpInfoRead(IsFixed, Handle, 230, (uint8*)&ram_check, 2);
            ram = htonl(ram);
            ram_check = htonl(ram_check);
            mr_updcrc(NULL, 0); /* initialize crc */
            mr_updcrc((unsigned char*)&ram, 2);
            mr_updcrc((unsigned char*)&ram, 2);
            if (ram_check == (mr_updcrc((unsigned char*)&ram, 0) & 0xFF)) {
                *(uint32*)RecBuf = ram;
            }
            break;
        }
#if 0
	case MRP_VENDER://开发商信息，最大39个有效字符，不包括'\0'。
		if(BufLen<40)
			break;	
		ret=mrc_GetMrpInfoRead(IsFixed,Handle,88,RecBuf,40);
		break;		
	case MRP_DESCRIPTION:  //应用描述信息 ，最大63个有效字符
		if(BufLen<64)
			break;	
		ret=mrc_GetMrpInfoRead(IsFixed,Handle,128,RecBuf,64);	
		break;
	case MRP_VERSION://
		//200:char[2]  =   计费通道版本号，网络字节序				
		if(BufLen<2)
			break;	
		ret=mrc_GetMrpInfoRead(IsFixed,Handle,200,RecBuf,2);
		data=RecBuf[0]*256+RecBuf[1];
		memcpy(RecBuf,&data,sizeof(data));	
		break;	
	case MRP_CHANNEL:			
		if(BufLen<2)
			break;	
		//在原有方案中，202:char[2]  =   计费通道编号，网络字节序								
		//ret=mrc_GetMrpInfoRead(IsFixed,Handle,202,RecBuf,2);
		//data=RecBuf[0]*256+RecBuf[1];
		//MR_MEMCPY(RecBuf,&data,sizeof(data));				
		//在自动切换方案中，计费通道编号,两个字节，低地址的RecBuf[0]是移动，高地址的RecBuf[1]是联通。				
		RecBuf[0]=0;
		RecBuf[1]=0;
		ret=2;
		mrc_GetMrpInfoRead(IsFixed,Handle,203,RecBuf,1);
		mrc_GetMrpInfoRead(IsFixed,Handle,209,RecBuf+1,1);
		break;
#endif
        default:;
    }
    return ret;
}

static int32 getAppInfo() {
    int32 IsFixed = 0, Handle = 0;

    Handle = mrc_GetMrpInfoOpen(pack_filename, &IsFixed);
    if (Handle == 0) {
        return MR_FAILED;
    }
    mrc_GetMrpInfoEx(IsFixed, Handle, MRP_APPID, (uint8*)&mrc_appInfo_st.id, 4);
    mrc_GetMrpInfoEx(IsFixed, Handle, MRP_APPVER, (uint8*)&mrc_appInfo_st.ver, 4);
    if (mrc_appInfo_st.ram == 0) {
        mrc_GetMrpInfoEx(IsFixed, Handle, MRP_RAM, (uint8*)&mrc_appInfo_st.ram, 4);
    }
    //mrc_GetMrpInfo(IsFixed, Handle, MRP_FILENAME, (uint8 *)&mrc_appInfo_st.sidName[0], 12);
    mrc_appInfo_st.sidName = NULL;
    mrc_GetMrpInfoClose(IsFixed, Handle);
    return MR_SUCCESS;
}

int32 mr_doExt(char* extName) {
    char* filebuf;
    int32 filelen;

    filebuf = _mr_readFile((const char*)extName, (int*)&filelen, 0);
    if (!filebuf) {
        MRDBGPRINTF("mr_doExt err:%d", 11001);
        return MR_FAILED;
    }
    _mr_TestCom(NULL, 3629, 2913);

    if (_mr_TestComC(800, filebuf, filelen, 0) == 0) {  // 调用mr_load_c_function()
        _mr_TestComC(801, filebuf, MR_VERSION, 6);
        _mr_TestComC(801, (char*)&mrc_appInfo_st, sizeof(mrc_appInfo_st), 8);
        _mr_TestComC(801, filebuf, MR_VERSION, 0);  // 这一步会最终会进入mrc_init函数
    } else {
        MRDBGPRINTF("mr_doExt err:%d", 11002);
        return MR_FAILED;
    }
    return MR_SUCCESS;
}

static int32 _mr_intra_start(char* appExName, const char* entry) {
    int i, ret;
    //ret = mr_plat(1250, mrc_appInfo_st.ram);
    if (_mr_mem_init() != MR_SUCCESS) {
        return MR_FAILED;
    }
    MRDBGPRINTF("Total memory:%d", LG_mem_len);
    getAppInfo();
    dsm_prepare();

    mr_event_function = NULL;
    mr_timer_function = NULL;
    mr_stop_function = NULL;
    mr_pauseApp_function = NULL;
    mr_resumeApp_function = NULL;
    mr_ram_file = NULL;
    mr_c_function_P = NULL;
    mr_c_function_P_len = 0;
    mr_exception_str = NULL;

    {
        int32 len = 0;
        mr_screenBuf = NULL;
        if (mr_platEx(1001, NULL, 0, (uint8**)&mr_screenBuf, &len, NULL) == MR_SUCCESS) {
            if ((mr_screenBuf != NULL) && (len >= MR_SCREEN_MAX_W * MR_SCREEN_H * MR_SCREEN_DEEP)) {
                mr_bitmap[BITMAPMAX].type = MR_SCREEN_SECOND_BUF;
                mr_bitmap[BITMAPMAX].buflen = len;
            } else if (mr_screenBuf != NULL) {
                mr_platEx(1002, (uint8*)mr_screenBuf, len, (uint8**)NULL, NULL, NULL);
                mr_screenBuf = NULL;
            }
        }
        if (mr_screenBuf == NULL) {
            mr_screenBuf = (uint16*)MR_MALLOC(MR_SCREEN_MAX_W * MR_SCREEN_H * MR_SCREEN_DEEP);
            mr_bitmap[BITMAPMAX].type = MR_SCREEN_FIRST_BUF;
            mr_bitmap[BITMAPMAX].buflen = MR_SCREEN_MAX_W * MR_SCREEN_H * MR_SCREEN_DEEP;
        }
    }

    mr_bitmap[BITMAPMAX].p = mr_screenBuf;
    mr_bitmap[BITMAPMAX].h = mr_screen_h;
    mr_bitmap[BITMAPMAX].w = mr_screen_w;

    vm_state = NULL;
    mr_timer_state = MR_TIMER_STATE_IDLE;
    mr_timer_run_without_pause = FALSE;
    bi = bi & MR_FLAGS_AI;
    MEMSET(mr_bitmap, 0, sizeof(mr_bitmapSt) * BITMAPMAX);
    MEMSET(mr_sound, 0, sizeof(mr_sound));

    MEMSET(mr_sprite, 0, sizeof(mr_sprite));
    MEMSET(mr_tile, 0, sizeof(mr_tile));
    MEMSET(mr_map, 0, sizeof(mr_map));

    for (i = 0; i < TILEMAX; i++) {
        mr_tile[i].x1 = 0;
        mr_tile[i].y1 = 0;
        mr_tile[i].x2 = (int16)MR_SCREEN_W;
        mr_tile[i].y2 = (int16)MR_SCREEN_H;
    }

    if (!entry) {
        entry = "_dsm";
    }
    STRNCPY(mr_entry, entry, sizeof(mr_entry) - 1);
    MRDBGPRINTF("Used by VM(include screen buffer):%d bytes", LG_mem_len - LG_mem_left);
    mr_state = MR_STATE_RUN;
    ret = mr_doExt(appExName);
    if (0 != ret)
        ret = mr_doExt("logo.ext");  //尝试加载 logo.ext

    //这里需要完善
    if (ret != 0) {
        mr_state = MR_STATE_ERROR;
        mr_stop();
        MRDBGPRINTF("init failed");
        mr_connectWAP(MR_ERROR_WAP);
        return MR_FAILED;
    }
    return MR_SUCCESS;
}

int32 mr_start_dsm(char* filename, char* ext, char* entry) {
    mr_screeninfo screeninfo;
    if (mr_getScreenInfo(&screeninfo) != MR_SUCCESS) {
        return MR_FAILED;
    }
    mr_screen_w = screeninfo.width;
    mr_screen_h = screeninfo.height;
    mr_screen_bit = screeninfo.bit;

    MRDBGPRINTF("filename:%s, ext:%s, entry:%s", filename, ext, entry ? entry : "(NULL)");
    MEMSET(pack_filename, 0, sizeof(pack_filename));
    if (filename && (*filename == '*')) {
        STRCPY(pack_filename, filename);
    } else if (filename && (*filename == '%')) {
        char* loc = strchr2(entry, ',');
        if (loc != NULL) {
            *loc = '\0';
            STRCPY(pack_filename, entry + 1);
            *loc = ',';
        } else {
            STRCPY(pack_filename, entry + 1);
        }
    } else if (filename && (*filename == '#') && (*(filename + 1) == '<')) {
        STRCPY(pack_filename, filename + 2);
    } else {
        STRCPY(pack_filename, filename);
    }
    MRDBGPRINTF(pack_filename);
    MEMSET(old_pack_filename, 0, sizeof(old_pack_filename));
    MEMSET(old_start_filename, 0, sizeof(old_start_filename));
    MEMSET(start_fileparameter, 0, sizeof(start_fileparameter));
    mrc_appInfo_st.ram = 0;
    // return _mr_intra_start("cfunction.ext", entry);
    // return _mr_intra_start("logo.ext", filename);
    return _mr_intra_start(ext, entry);
}

int32 mr_stop_ex(int16 freemem) {
    if (mr_state == MR_STATE_IDLE) {
        return MR_IGNORE;
    }

    if ((mr_state == MR_STATE_RUN) || (mr_state == MR_STATE_PAUSE)) {
        c_event_st.code = MR_EXIT_EVENT;
        c_event_st.param0 = 0;
        c_event_st.param1 = 0;
        _mr_TestComC(801, (char*)&c_event_st, sizeof(c_event_st), 1);
    }

    mr_state = MR_STATE_IDLE;
    mr_timer_state = MR_TIMER_STATE_IDLE;
    mr_timer_run_without_pause = FALSE;

    if (freemem) {
        if (mr_bitmap[BITMAPMAX].type == MR_SCREEN_FIRST_BUF) {
            //MR_FREE(mr_screenBuf, mr_bitmap[BITMAPMAX].buflen);
        } else if (mr_bitmap[BITMAPMAX].type == MR_SCREEN_SECOND_BUF) {
            mr_platEx(1002, (uint8*)mr_screenBuf, mr_bitmap[BITMAPMAX].buflen, (uint8**)NULL, NULL, NULL);
        }
        mr_screenBuf = NULL;
    }

    if (freemem) {
        mr_mem_free(Origin_LG_mem_base, Origin_LG_mem_len);
    }
    //mr_timerStop();
    return MR_SUCCESS;
}

int32 mr_stop(void) {
    if (mr_stop_function) {
        int status = mr_stop_function();
        mr_stop_function = NULL;  //1943
        if (status != MR_IGNORE)
            return status;
    }
    return mr_stop_ex(TRUE);
}

/*暂停应用*/
int32 mr_pauseApp(void) {
    // mr_initOk = FALSE;
    if (mr_state == MR_STATE_RUN) {
        mr_state = MR_STATE_PAUSE;
    } else if (mr_state == MR_STATE_RESTART) {
        MR_TIME_STOP();
        //mr_timer_state = MR_TIMER_STATE_IDLE;
        return MR_SUCCESS;
    } else {
        return MR_IGNORE;
    };

    if (mr_pauseApp_function) {
        int status = mr_pauseApp_function();
        if (status != MR_IGNORE)
            return status;
    }

    _mr_TestComC(801, NULL, 1, 4);

    if (!mr_timer_run_without_pause) {
        if (mr_timer_state == MR_TIMER_STATE_RUNNING) {
            MR_TIME_STOP();
            mr_timer_state = MR_TIMER_STATE_SUSPENDED;
        }
    }
    return MR_SUCCESS;
}

/*恢复应用*/
int32 mr_resumeApp(void) {
    if (mr_state == MR_STATE_PAUSE) {
        mr_state = MR_STATE_RUN;
    } else if (mr_state == MR_STATE_RESTART) {
        mr_timer_p = (void*)"restart";
        MR_TIME_START(100);
        //mr_timer_state = MR_TIMER_STATE_RUNNING;
        return MR_SUCCESS;
    } else {
        return MR_IGNORE;
    };

    if (mr_resumeApp_function) {
        int status = mr_resumeApp_function();
        if (status != MR_IGNORE)
            return status;
    }

    _mr_TestComC(801, NULL, 1, 5);

    if (mr_timer_state == MR_TIMER_STATE_SUSPENDED) {
        MR_TIME_START(300);
        //mr_timer_state = MR_TIMER_STATE_RUNNING;
    }
    return MR_SUCCESS;
}

int32 mr_event(int16 type, int32 param1, int32 param2) {
    if ((mr_state == MR_STATE_RUN) || ((mr_timer_run_without_pause) && (mr_state == MR_STATE_PAUSE))) {
        if (mr_event_function) {
            int status = mr_event_function(type, param1, param2);
            if (status != MR_IGNORE)
                return status;
        }
        c_event_st.code = type;
        c_event_st.param0 = param1;
        c_event_st.param1 = param2;
        _mr_TestComC(801, (char*)&c_event_st, sizeof(c_event_st), 1);
        return MR_SUCCESS;  //deal
    }
    return MR_IGNORE;  //didnot deal
}

int32 mr_timer(void) {
    if (mr_timer_state != MR_TIMER_STATE_RUNNING) {
        MRDBGPRINTF("warning:mr_timer event unexpected!");
        return MR_IGNORE;
    }
    mr_timer_state = MR_TIMER_STATE_IDLE;
    if ((mr_state == MR_STATE_RUN) || ((mr_timer_run_without_pause) && (mr_state == MR_STATE_PAUSE))) {
        MRDBGPRINTF("mr_timer 1, %p", mr_timer_function);
        if (mr_timer_function) {
            int status = mr_timer_function();
            if (status != MR_IGNORE)
                return status;
        }
        _mr_TestComC(801, NULL, 1, 2);
        return MR_SUCCESS;
    } else if (mr_state == MR_STATE_RESTART) {
        MRDBGPRINTF("mr_timer 2");
        mr_stop();  //1943 修改为mr_stop
        //mr_stop_ex(TRUE);      //1943
        _mr_intra_start(start_filename, NULL);
        return MR_SUCCESS;
    }
    return MR_IGNORE;
}

int32 mr_registerAPP(uint8* p, int32 len, int32 index) {
    MRDBGPRINTF("mr_registerAPP:%d p:%d", index, p);
    if (index < (sizeof(mr_m0_files) / sizeof(uint8*))) {
        mr_m0_files[index] = p;
    } else {
        MRDBGPRINTF("mr_registerAPP err!");
        return MR_FAILED;
    }
    MRDBGPRINTF("mr_registerAPP mr_m0_files[%d]:%d ", index, mr_m0_files[index]);
    return MR_SUCCESS;
}

//****************************短信

/*
首先定义包的定义：
一个包为：数据长度（一个字节，数据内容的长度，长度不包括
自己的一个字节）＋数据内容（数据内容的长度为"数据长度"字段定义）
一个包内的数据内容可以是预定义的数据格式，其中也可以包含若干个
子包。
如一个包，数据内容为CD F2 D5，则整个包为03 CD F2 D5。


功能:
从数据缓冲中取得一个数据包。

输入
in:数据指针
inlen:数据长度
输出

in:剩下的数据指针
inlen:剩下的数据长度
chunk:取得的数据包指针
chunklen:取得的数据包长度

*/
int32 _mr_getChunk(uint8** in, int32* inlen, uint8** chunk, int32* chunklen) {
    if (*inlen <= 1) {  // 数据包已经读完
        *chunk = *in;
        *chunklen = *inlen;
        return MR_IGNORE;
    }
    *chunklen = **in;
    if ((*chunklen >= *inlen) || (*chunklen <= 0)) {  // 数据包比数据缓冲还长，出错
        *chunk = *in;
        *chunklen = *inlen;
        return MR_FAILED;
    }

    *chunk = *in + 1;
    *in = *in + *chunklen + 1;
    *inlen = *inlen - *chunklen - 1;
    return MR_SUCCESS;
}

#ifdef MR_CFG_USE_A_DISK
static int32 _mr_change_to_root(void) {
    char* root;
    uint8* output;
    int32 output_len;
    MR_PLAT_EX_CB cb;
    int32 ret;
    root = "Y:";
    ret = mr_platEx(1204, (uint8*)root, strlen(root) + 1, &output, &output_len, &cb);
    if (ret != MR_SUCCESS) {
        memset(temp_current_path, 0, sizeof(temp_current_path));
        return MR_FAILED;
    }
    strncpy(temp_current_path, (char*)output, sizeof(temp_current_path));
    root = "X:";
    ret = mr_platEx(1204, (uint8*)root, strlen(root) + 1, &output, &output_len, &cb);
    if (ret != MR_SUCCESS) {
        memset(temp_current_path, 0, sizeof(temp_current_path));
        return MR_FAILED;
    }
    return MR_SUCCESS;
}

static int32 _mr_change_to_current(void) {
    uint8* output;
    int32 output_len;
    MR_PLAT_EX_CB cb;
    if (temp_current_path[0]) {
        mr_platEx(1204, (uint8*)temp_current_path, strlen(temp_current_path) + 1, &output, &output_len, &cb);
    }
    return MR_SUCCESS;
}
#endif

int32 _mr_save_sms_cfg(int32 f) {
    int32 ret;

    if (mr_sms_cfg_need_save) {
        mr_sms_cfg_need_save = FALSE;
#ifdef MR_CFG_USE_A_DISK
        _mr_change_to_root();
#endif
        f = mr_open(DSM_CFG_FILE_NAME, MR_FILE_WRONLY | MR_FILE_CREATE);
#ifdef MR_CFG_USE_A_DISK
        _mr_change_to_current();
#endif
        if (f == 0) {
            goto err;
        }
        ret = mr_seek(f, 0, MR_SEEK_SET);
        if (ret == MR_FAILED) {
            mr_close(f);
            goto err;
        }
        ret = mr_write(f, mr_sms_cfg_buf, MR_SMS_CFG_BUF_LEN);
        if (ret == MR_FAILED) {
            mr_close(f);
            goto err;
        }
        mr_close(f);
    }
    return MR_SUCCESS;
err:
    return MR_FAILED;
}

//查看DSM配置文件是否存在，不存在则创建之
int32 _mr_load_sms_cfg(void) {
    int32 f;
    int32 ret;

    mr_sms_cfg_need_save = FALSE;
    MEMSET(mr_sms_cfg_buf, 0, MR_SMS_CFG_BUF_LEN);
#ifdef MR_CFG_USE_A_DISK
    _mr_change_to_root();
#endif
    if (mr_info(DSM_CFG_FILE_NAME) == MR_IS_FILE) {
        f = mr_open(DSM_CFG_FILE_NAME, MR_FILE_RDONLY);
        if (f == 0) {
#ifdef MR_CFG_USE_A_DISK
            _mr_change_to_current();
#endif
            goto err;
        }
        ret = mr_read(f, mr_sms_cfg_buf, MR_SMS_CFG_BUF_LEN);
        mr_close(f);
        if (ret != MR_SMS_CFG_BUF_LEN) {
            f = mr_open(DSM_CFG_FILE_NAME, MR_FILE_WRONLY | MR_FILE_CREATE);
            if (f == 0) {
#ifdef MR_CFG_USE_A_DISK
                _mr_change_to_current();
#endif
                goto err;
            }
            mr_close(f);
            _mr_smsAddNum(0, "518869058");
            _mr_smsAddNum(1, "918869058");
            _mr_smsAddNum(3, "aa");
        }
    } else {
        _mr_smsAddNum(0, "518869058");
        _mr_smsAddNum(1, "918869058");
        _mr_smsAddNum(3, "aa");
    }

#ifdef MR_CFG_USE_A_DISK
    _mr_change_to_current();
#endif
    return MR_SUCCESS;
err:
    return MR_FAILED;
}

int32 _mr_smsGetBytes(int32 pos, char* p, int32 len) {
    if ((pos >= MR_SMS_CFG_BUF_LEN) || (pos < 0) || ((pos + len) >= MR_SMS_CFG_BUF_LEN)) {
        return MR_FAILED;
    }
    MEMCPY(p, mr_sms_cfg_buf + pos, len);
    return MR_SUCCESS;
}

int32 _mr_smsSetBytes(int32 pos, char* p, int32 len) {
    if ((pos >= MR_SMS_CFG_BUF_LEN) || (pos < 0) || ((pos + len) >= MR_SMS_CFG_BUF_LEN)) {
        return MR_FAILED;
    }
    mr_sms_cfg_need_save = TRUE;
    MEMCPY(mr_sms_cfg_buf + pos, p, len);
    //MRDBGPRINTF("mr_smsSetBytes %d", *p);
    return MR_SUCCESS;
}

int32 _mr_smsGetNum(int32 index, char* pNum) {
    char num[MR_MAX_NUM_LEN];
    uint32 len;

    _mr_smsGetBytes(MR_MAX_NUM_LEN * index + MR_SECTION_LEN, num, MR_MAX_NUM_LEN);
    len = _mr_decode((uint8*)num, STRNLEN(num, MR_MAX_NUM_LEN - 1), (uint8*)pNum);
    if ((len == 0) || (len >= MR_MAX_NUM_LEN)) {
        pNum[0] = 0;
        return MR_FAILED;
    }
    pNum[len] = 0;

    return MR_SUCCESS;
}

/*
1、   文件格式说明：
2、   第一个120字节：
a)   第1个32字节：4字节（版本号），1（是否使用SMS更新数据，>128，使用）；
b)   第2个32字节：32字节消息指示。
3、   第二、第三个120字节：
a)   240个字节（定长），每24个字节存放一个接收号码，最多10个接收号码
，每24个字节的格式为，号码字符串包，长度不够后面填充\0。
b)   前三个号码定义：移动发送号码，联通发送号码，统一发送号码。
4、   第四个120字节：
a)   120字节，WAP的URL。
5、   第5～36个120字节：
a)   120×32个字节，每120个字节存放一条DSM更新短消息的全部内容。
*/

/**********************************************
*name:        _mr_smsAddNum
*description: add a cmd num form the ffs
*input:
*                  index---Num index
*                  pNum---pointer to the Num address
*return:     
*                  MR_SUCCESS---success, 
*                  MR_FAILED--failed
*                  MR_IGNORE--already exist
*Note: 
***********************************************/
int32 _mr_smsAddNum(int32 index, char* pNum) {
    int32 len = STRLEN(pNum);
    char num[MR_MAX_NUM_LEN];
    if (len > (((MR_MAX_NUM_LEN - 1) / 4 * 3))) {
        MRDBGPRINTF("num too long");
        return MR_FAILED;
    }
    MEMSET(num, 0, MR_MAX_NUM_LEN);
    _mr_encode((uint8*)pNum, len, (uint8*)num);
    _mr_smsSetBytes(MR_MAX_NUM_LEN * index + MR_SECTION_LEN, num, MR_MAX_NUM_LEN);
    return MR_SUCCESS;
}

/**********************************************
*name:        _mr_smsDelNum
*description: del a cmd num form the ffs
*input:
*                  index---Num index
*return:     
*                  MR_SUCCESS---success, 
*                  MR_FAILED--failed
*                  MR_IGNORE--already exist
*Note: 
***********************************************/
int32 _mr_smsDelNum(int32 index) {
    char num[MR_MAX_NUM_LEN];
    MEMSET(num, 0, MR_MAX_NUM_LEN);
    _mr_smsSetBytes(MR_MAX_NUM_LEN * index + MR_SECTION_LEN, num, MR_MAX_NUM_LEN);
    return MR_SUCCESS;
}

/**********************************************
*name:        _mr_smsUpdateURL
*description: update URL form the ffs
*input:
*                  pURL---pointer to the URL
*return:     
*                  MR_SUCCESS---success, 
*                  MR_FAILED--failed
*                  MR_IGNORE--already exist
*Note: 
***********************************************/
int32 _mr_smsUpdateURL(uint8* pURL, uint8 len) {
    uint8 flag = 128;
    uint8 out[MR_SECTION_LEN];

    if (len > (((MR_SECTION_LEN - 1) / 4 * 3))) {
        MRDBGPRINTF("url too long");
        return MR_FAILED;
    }
    _mr_smsSetBytes(CFG_USE_URL_UPDATE_OFFSET, (char*)&flag, 1);
    MEMSET(out, 0, sizeof(out));
    len = _mr_encode(pURL, len, out);
    _mr_smsSetBytes(MR_SECTION_LEN * 3, (char*)out, MR_SECTION_LEN);
    return MR_SUCCESS;
}

/**********************************************
*name:        _mr_smsDsmSave
*description: save a sms content to the ffs
*input:
*                  pSMSContent---pointer to the input sms content buf
*                  
*return:     
*                  MR_SUCCESS---save success
*                  MR_FAILED--save failed
*Note: 
***********************************************/
int32 _mr_smsDsmSave(char* pSMSContent, int32 len) {
    uint8 contnet[MR_SECTION_LEN];
    uint8 flag = 128;
    int32 index;

    MEMSET(contnet, 0, MR_SECTION_LEN);
    MEMCPY((char*)contnet, (char*)pSMSContent, len);
    index = contnet[2];  //取得消息的位置号
    if ((index > 31)) {
        return MR_FAILED;
    }
    _mr_smsSetBytes(CFG_USE_SM_UPDATE_OFFSET, (char*)&flag, 1);
    _mr_smsSetBytes(CFG_SM_FLAG_OFFSET + index, (char*)&flag, 1);
    _mr_smsSetBytes(MR_SECTION_LEN * (index + 4), (char*)contnet, MR_SECTION_LEN);
    return MR_SUCCESS;
}

/**********************************************
*name:        _mr_smsReplyServer
*description: send a sms back to server
*input:
*                  pNum---pointer to the input number address
*                  
*return:     
*                  MR_SUCCESS---send sms success
*                  MR_FAILED--send sms failed
*Note: 
***********************************************/
int32 _mr_smsReplyServer(char* pNum, uint8* old_IMSI) {
    uint8 sms[MR_SECTION_LEN];
    uint8 smsstring[MR_MAX_SM_LEN];
    mr_userinfo info;
    uint32 offset = 0;
    //int32 f;

    if (mr_getUserInfo(&info) != MR_SUCCESS) {
        return MR_FAILED;
    }

    MEMSET(smsstring, 0, sizeof(smsstring));

    sms[0] = 0xFA;
    sms[1] = 0xF1;
    offset = offset + 2;

    if (old_IMSI) {
        //长度16+1
        sms[offset] = 17;
        offset = offset + 1;
        //旧IMSI
        sms[offset] = 6;
        offset = offset + 1;
        MEMCPY(&sms[offset], old_IMSI, 16);
        offset = offset + 16;
    }

    //长度16+1
    sms[offset] = 17;
    offset = offset + 1;
    //IMEI
    sms[offset] = 2;
    offset = offset + 1;
    MEMCPY(&sms[offset], &info.IMEI, sizeof(info.IMEI));
    offset = offset + 16;

    //长度16+1
    sms[offset] = 17;
    offset = offset + 1;
    //IMSI
    sms[offset] = 3;
    offset = offset + 1;
    MEMCPY(&sms[offset], &info.IMSI, sizeof(info.IMSI));
    offset = offset + 16;

    //长度20+1
    sms[offset] = 21;
    offset = offset + 1;
    //手机信息
    sms[offset] = 4;
    offset = offset + 1;
    info.ver = htonl(info.ver);
    MEMCPY(&sms[offset], &info.manufactory, 20);
    offset = offset + 20;

    _mr_encode(sms, offset, smsstring);
    mr_sendSms((char*)pNum, (char*)smsstring, MR_ENCODE_ASCII | MR_SMS_REPORT_FLAG | MR_SMS_RESULT_FLAG);

    //MRDBGPRINTF("Debug:send sms content=");
    //MRDBGPRINTF((char*)smsstring);
    //MRDBGPRINTF("Debug:send sms num=");
    //MRDBGPRINTF((char*)pNum);

    return MR_SUCCESS;
}

static int32 _mr_u2c_c(char* input, int32 inlen, char* output, int32 outlen) {
    int32 pos = 0;
    int32 upos = 0;
    MEMSET(output, 0, outlen);
    while ((upos < (inlen - 1)) && ((*(input + upos) + *(input + upos + 1)) != 0) && (pos < outlen)) {
        if (*(input + upos) == 0) {
            output[pos] = *(input + upos + 1);
            pos = pos + 1;
            upos = upos + 2;
        } else {
            break;
        }
    }
    return pos;
}

static const char* _mr_memfind_c(const char* s1, size_t l1,
                                 const char* s2, size_t l2) {
    if (l2 == 0)
        return s1; /* empty strings are everywhere */
    else if (l2 > l1)
        return NULL; /* avoids a negative `l1' */
    else {
        const char* init; /* to search for a `*s2' inside `s1' */
        l2--;             /* 1st char will be checked by `memchr' */
        l1 = l1 - l2;     /* `s2' cannot be found after that */
        while (l1 > 0 && (init = (const char*)MEMCHR(s1, *s2, l1)) != NULL) {
            init++; /* 1st char is already checked */
            if (MEMCMP(init, s2 + 1, l2) == 0)
                return init - 1;
            else { /* correct `l1' and `s1' to try again */
                l1 -= init - s1;
                s1 = init;
            }
        }
        return NULL; /* not found */
    }
}

static int32 _mr_smsIndiaction(uint8* pContent, int32 nLen, uint8* pNum, int32 type)  //nLen 变为 int32，方便以后扩展
{
    uint8 outbuf[160];
    int32 memlen;

    if ((mr_state == MR_STATE_RUN) || ((mr_timer_run_without_pause) && (mr_state == MR_STATE_PAUSE))) {
        c_event_st.code = MR_SMS_INDICATION;
        c_event_st.param0 = (int32)pContent;
        c_event_st.param1 = (int32)pNum;
        c_event_st.param2 = type;
        c_event_st.param3 = nLen;

        _mr_TestComC(801, (char*)&c_event_st, sizeof(c_event_st), 1);
    }

    //decode the content
    if ((nLen < 12) || (nLen > 160)) {
        return MR_IGNORE;
    }

    /*
	短信接口说明：
	1、   每条短信内容120个字节。
	2、   网络发往手机的短消息；前两个字节作为本条短信内容指示： 
	a)   FA  F1：DSM配置短信；内容：如"DSM配置短信格式说明"。
	b)   FA  F2：DSM更新短信；内容：如前面（"DSM更新短信格式说明"）。
	3、   手机发往网络的短消息；前两个字节作为本条短信内容指示：
	a)   FA  F1：手机上发消息；内容：如"手机上发消息格式说明"。
	*/

    /*
	DSM配置短信格式说明：
	1、   一个DSM配置短信内容由若干个包构成。
	2、   包的内容：操作码（一个字节）＋操作码对应的操作数据。
	3、   操作码定义：
	1: 添加一个命令接收号码；操作数据：号码位置（一个字节）＋号码字符串＋\0。
	2: 删除一个命令接收号码；操作数据：号码位置（一个字节）。
	3: 设置WAP的URL；操作数据：URL字符串＋\0。
	4: 要求手机回复版本及信息消息；操作数据：无。

	*/

    MEMSET(outbuf, 0, sizeof(outbuf));
    switch (type) {
        case MR_ENCODE_ASCII:
            if ((pContent[0] == 'M') && (pContent[1] == 'R') && (pContent[2] == 'P') && (pContent[3] == 'G')) {
                //这里放宽了要求
                memlen = _mr_decode(pContent + 4, nLen - 4, outbuf);
            } else {
                //mr_printf("mr_sms not  cmd num");
                const char* s1 = _mr_memfind_c((const char*)pContent, nLen, (const char*)"~#^~", 4);
                const char* s2;
                if (s1) {
                    s2 = _mr_memfind_c((const char*)s1, nLen - ((uint8*)s1 - pContent), (const char*)"&^", 2);
                    if (s2) {
                        memlen = _mr_decode((uint8*)s1 + 4, (s2 - s1 - 4), outbuf);
                    } else {
                        return MR_IGNORE;
                    }
                } else {
                    return MR_IGNORE;
                }
            }
            break;
        case MR_ENCODE_UNICODE: {
            const char* s1 = _mr_memfind_c((const char*)pContent, nLen, (const char*)"\0~\0#\0^\0~", 8);
            const char* s2;
            if (s1) {
                s2 = _mr_memfind_c((const char*)s1, nLen - ((uint8*)s1 - pContent), (const char*)"\0&\0^", 4);
                if (s2) {
                    char inbuf[70];
                    int32 inlen;
                    inlen = _mr_u2c_c((char*)s1 + 8, (s2 - s1 - 8), inbuf, sizeof(inbuf));
                    memlen = _mr_decode((uint8*)inbuf, inlen, outbuf);
                } else {
                    return MR_IGNORE;
                }
            } else {
                return MR_IGNORE;
            }
            break;
        }
        default:
            return MR_IGNORE;
            break;
    }

    if (memlen < 0) {
        //mr_printf("_mr_decode failed");
        return MR_IGNORE;
    }

    MRDBGPRINTF("mr_smsIndiaction check ok!");
    {
        int32 f;
        f = _mr_load_sms_cfg();
        if ((outbuf[0] == 0xfc) && (outbuf[1] == 0xfc)) {
            uint8* in;
            int32 inlen;
            uint8* chunk;
            int32 chunklen;
            int32 ret;
            in = (uint8*)outbuf + 2;
            inlen = memlen - 2;

            ret = _mr_getChunk(&in, &inlen, &chunk, &chunklen);  //取得一个Chunk
            while (ret == MR_SUCCESS) {
                int32 code = *chunk;
                int32 tempret = MR_FAILED;
                //uint8 flag=128;
                switch (code) {
                    case 1:
                        tempret = _mr_smsAddNum(*(chunk + 1), (char*)(chunk + 2));
                        break;
                    case 2:
                        tempret = _mr_smsDelNum(*(chunk + 1));
                        break;
                    case 3:
                        tempret = _mr_smsUpdateURL((chunk + 1), (uint8)(chunklen - 1));
                        break;
                    case 4:
                        tempret = _mr_smsReplyServer((char*)pNum, NULL);
                        break;
                    case 5:
                        tempret = _mr_smsSetBytes(CFG_USE_UNICODE_OFFSET, (char*)(chunk + 1), 1);
                        //MRDBGPRINTF("mr_smsIndiaction UNICODE!");
                        break;
                    case 6:
                        tempret = _mr_smsSetBytes(((*(chunk + 1)) * 256) + (*(chunk + 2)), (char*)(chunk + 4), *(chunk + 3));
                        break;
                    case 7:
                    case 17:
                    case 27:
                    case 37:
                        tempret = MR_SUCCESS;
                        break;
                    default:
                        _mr_save_sms_cfg(f);
                        return MR_FAILED;
                }  //switch
                if (tempret != MR_SUCCESS) {
                    _mr_save_sms_cfg(f);
                    return MR_FAILED;
                }
                ret = _mr_getChunk(&in, &inlen, &chunk, &chunklen);  //取得下一个Chunk
            }                                                        //while
        } else if ((outbuf[0] == 0xfa) && (outbuf[1] == 0xf2)) {
            _mr_smsDsmSave((char*)outbuf, memlen);
        }
        _mr_save_sms_cfg(f);
        return MR_SUCCESS;
    }
}

/**********************************************
*name:        mr_smsIndiaction
*description: get a new sms coming, check it whether was send by cmd server
*input:
*                  pNum---pointer to the Num address
*                  pContent---pointer to the sms content
*            nLen   ---
*return:     
*                  MR_SUCCESS---packet ok
*                  MR_FAILED--something error when doing the sending action
*            MR_IGNORE--- normal sms , do not do mr treating.
*Note: 
***********************************************/
int32 mr_smsIndiaction(uint8* pContent, int32 nLen, uint8* pNum, int32 type)  //nLen 变为 int32，方便以后扩展
{
    int32 ret;
    mr_sms_return_flag = 0;
    ret = _mr_smsIndiaction(pContent, nLen, pNum, type);
    if (mr_sms_return_flag == 1)
        ret = mr_sms_return_val;
    return ret;
}

int32 _mr_newSIMInd(int16 type, uint8* old_IMSI) {
    int32 id;
    uint8 flag;
    char num[MR_MAX_NUM_LEN];
    int32 f;

    id = mr_getNetworkID();
    if ((MR_SIM_NEW == type) || (MR_SIM_CHANGE == type)) {
        f = _mr_load_sms_cfg();
        _mr_save_sms_cfg(f);
        _mr_smsGetBytes(5, (char*)&flag, 1);
        if (flag >= 128) {
            _mr_smsGetNum(3, num);
        } else {
            switch (id) {
                case MR_NET_ID_MOBILE:
                    if (_mr_smsGetNum(MR_NET_ID_MOBILE, num) == MR_FAILED)
                        goto err;
                    break;
                case MR_NET_ID_CN:
                case MR_NET_ID_CDMA:
                    if (_mr_smsGetNum(MR_NET_ID_CN, num) == MR_FAILED)
                        goto err;
                    break;
                default:
                    goto err;
                    break;
            }
        }
        _mr_smsReplyServer(num, old_IMSI);
    }
    return MR_SUCCESS;
err:
    return MR_FAILED;
}

//****************************短信

static void encode02(char* value, int len, unsigned char cBgnInit, unsigned char cEndInit)  //简单加密
{
    int iLeft;
    int iRight;

    for (iLeft = 0; iLeft < len; iLeft++) {
        if (iLeft == 0)
            value[0] ^= cBgnInit;
        else {
            if (value[iLeft] != value[iLeft - 1])
                value[iLeft] ^= value[iLeft - 1];
        }
    }
    for (iRight = len - 1; iRight >= 0; iRight--) {
        if (iRight == len - 1)
            value[iRight] ^= cEndInit;
        else {
            if (value[iRight] != value[iRight + 1])
                value[iRight] ^= value[iRight + 1];
        }
    }
}

int _mr_isMr(char* input) {
    mr_userinfo info;
    char enc[16];
    int appid, appver;
    int ret = MR_FAILED;
    if (mr_getUserInfo(&info) == MR_SUCCESS) {
        appid = htonl(*((int*)&input[16]));
        appver = htonl(*((int*)&input[20]));
        enc[0] = info.IMEI[1];
        enc[1] = info.IMEI[2];
        enc[2] = info.IMEI[3];
        enc[3] = info.IMEI[4];
        enc[4] = info.IMEI[5];
        enc[5] = info.IMEI[7];
        enc[6] = info.IMEI[8];
        enc[7] = appid % 239;
        enc[8] = appver % 237;
        enc[9] = info.manufactory[0];
        enc[10] = info.type[0];
        enc[11] = STRLEN(info.manufactory);
        enc[12] = MR_VERSION % 251;
        enc[13] = MR_VERSION % 247;
        enc[14] = info.ver % 253;
        enc[15] = info.ver % 241;
        encode02(enc, 16, (info.IMEI[0] % 10) * 21 + info.IMEI[6],
                 ((info.IMEI[11] + info.IMEI[12]) % 10) * 21 + info.IMEI[14]);
        if (MEMCMP(enc, input, 16) == 0) {
            ret = MR_SUCCESS;
        }
    }
    return ret;
}

uint32 mr_ltoh(char* startAddr) {
    return (startAddr[3] << 24) | ((startAddr[2] & 0xff) << 16) | ((startAddr[1] & 0xff) << 8) | (startAddr[0] & 0xff);
}

uint32 mr_ntohl(char* startAddr) {
    return ((startAddr[0] & 0xff) << 24) | ((startAddr[1] & 0xff) << 16) | ((startAddr[2] & 0xff) << 8) | (startAddr[3] & 0xFF);
}

#if 0
#define CFG_FILENAME "#807022#*"

int32 _mr_getMetaMemLimit() {
    int32 nTmp;
    int32 len = 0, file_len = 0;
    // void* workbuffer = NULL;
    int32 f;
    char TempName[MR_MAX_FILENAME_SIZE];
    // int is_rom_file = FALSE;
    uint32 headbuf[4];
    char* this_packname;
    char* mr_m0_file;
    char _v[4];
    int32 memValue;

    this_packname = pack_filename;
    if ((this_packname[0] == '*') || (this_packname[0] == '$')) {
        /*read file from m0*/
        uint32 pos = 0;
        uint32 m0file_len;

        if (this_packname[0] == '*') {                                /*m0 file?*/
            mr_m0_file = (char*)mr_m0_files[this_packname[1] - 'A'];  //这里定义文件名为*A即是第一个m0文件,*B是第二个.........
        } else {
            mr_m0_file = mr_ram_file;
        }
        if (mr_m0_file == NULL) {
            return 0;
        }
        pos = pos + 4;
        MEMCPY(&_v[0], &mr_m0_file[pos], 4);
        len = mr_ltoh((char*)_v);
        pos = pos + 4;
        if ((this_packname[0] == '$')) {
            m0file_len = mr_ram_file_len;
        } else {
            MEMCPY(&_v[0], &mr_m0_file[pos], 4);
            m0file_len = mr_ltoh((char*)_v);
        }
        pos = pos + len;
        if (((pos + 4) >= m0file_len) || (len < 1) || (len >= MR_MAX_FILE_SIZE)) {
            return 0;
        }
        MEMCPY(&_v[0], &mr_m0_file[pos], 4);
        len = mr_ltoh((char*)_v);
        pos = pos + 4;
        if (((len + pos) >= m0file_len) || (len < 1) || (len >= MR_MAX_FILENAME_SIZE)) {
            return 0;
        }
        MEMCPY(TempName, &mr_m0_file[pos], len);
        TempName[len] = 0;
        pos = pos + len;
        if (STRCMP(CFG_FILENAME, TempName) == 0) {
            MEMCPY(&_v[0], &mr_m0_file[pos], 4);
            len = mr_ltoh((char*)_v);
            pos = pos + 4;
            if (((len + pos) > m0file_len) || (len < 1) || (len >= MR_MAX_FILE_SIZE)) {
                return 0;
            }
        } else {
            return 0;
        }
        file_len = len;
        if (file_len <= 0) {
            return 0;
        }
        pos += 3 * 4;
        MEMCPY(&_v[0], &mr_m0_file[pos], 4);
    } else { /*read file from efs , EFS 中的文件*/
        f = mr_open(this_packname, MR_FILE_RDONLY);
        MEMSET(headbuf, 0, sizeof(headbuf));
        nTmp = mr_read(f, &headbuf, sizeof(headbuf));
        headbuf[0] = mr_ltoh((char*)&headbuf[0]);
        headbuf[1] = mr_ltoh((char*)&headbuf[1]);
        headbuf[2] = mr_ltoh((char*)&headbuf[2]);
        headbuf[3] = mr_ltoh((char*)&headbuf[3]);
        if ((nTmp != 16) || (headbuf[0] != 1196446285) || (headbuf[1] <= 232)) {
            mr_close(f);
            return 0;
        }
        {  //新版mrp
            uint32 indexlen = headbuf[1] + 8 - headbuf[3];
            uint32 pos = 0;
            uint32 file_pos = 0;

            nTmp = mr_seek(f, headbuf[3] - 16, MR_SEEK_CUR);
            if (nTmp < 0) {
                mr_close(f);
                return 0;
            }
            nTmp = mr_read(f, &_v[0], 4);
            if (nTmp != 4) {
                mr_close(f);
                return 0;
            }
            len = mr_ltoh((char*)_v);
            pos = pos + 4;
            if (((len + pos) > indexlen) || (len < 1) || (len >= MR_MAX_FILENAME_SIZE)) {
                mr_close(f);
                return 0;
            }
            nTmp = mr_read(f, &TempName[0], len);
            if (nTmp != len) {
                mr_close(f);
                return 0;
            }
            TempName[len] = 0;
            pos = pos + len;
            if (STRCMP(CFG_FILENAME, TempName) == 0) {
                nTmp = mr_read(f, &_v[0], 4);
                pos = pos + 4;
                file_pos = mr_ltoh((char*)_v);
                nTmp = mr_read(f, &_v[0], 4);
                pos = pos + 4;
                file_len = mr_ltoh((char*)_v);
                if ((file_pos + file_len) > headbuf[2]) {
                    mr_close(f);
                    return 0;
                }
            } else {
                mr_close(f);
                MRDBGPRINTF("can not found %s", CFG_FILENAME);
                return 0;
            }
            nTmp = mr_seek(f, file_pos + 3 * 4, MR_SEEK_SET); /*精简虚拟器读取第四个int32*/
            if (nTmp < 0) {
                mr_close(f);
                return 0;
            }
            nTmp = mr_read(f, &_v[0], 4);
            mr_close(f);
            if (nTmp != 4) {
                return nTmp;
            }
        }
    }
    memValue = mr_ntohl((char*)_v);
    return memValue;
}

#endif

void mr_getScrBuf(uint16** buf, int32* width, int32* height) {
    if (buf) *buf = mr_screenBuf;
    if (width) *width = mr_screen_w;
    if (height) *height = mr_screen_h;
}

void mr_setScrBuf(uint16* buf) {
    mr_screenBuf = buf;
}
