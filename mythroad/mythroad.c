#include "./include/mythroad.h"

#include "./include/encode.h"
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
#include "./include/mr_store.h"
#include "./include/mr_tcp_target.h"
#include "./include/mrporting.h"
#include "./include/other.h"
#include "./include/printf.h"
#include "./include/string.h"
#include "./tomr/tomr.h"
#include "./luadec/luadec.h"

const unsigned char* mr_m0_files[50];

#define MRDBGPRINTF mr_printf

mrp_State* vm_state;

uint16* mr_screenBuf;
#ifdef MR_TRACE
mr_bitmapSt mr_bitmap[BITMAPMAX + 1];
mr_tileSt mr_tile[TILEMAX];
int16* mr_map[TILEMAX];
mr_soundSt mr_sound[SOUNDMAX];
#else
static mr_bitmapSt mr_bitmap[BITMAPMAX + 1];
static mr_tileSt mr_tile[TILEMAX];
static int16* mr_map[TILEMAX];
static mr_soundSt mr_sound[SOUNDMAX];
#endif
static mr_spriteSt mr_sprite[SPRITEMAX];
int32 mr_state = MR_STATE_IDLE;
static int32 bi = 0;
static char pack_filename[MR_MAX_FILENAME_SIZE];
static char start_filename[MR_MAX_FILENAME_SIZE];

static char start_fileparameter[MR_MAX_FILENAME_SIZE];

static char old_pack_filename[MR_MAX_FILENAME_SIZE];
static char old_start_filename[MR_MAX_FILENAME_SIZE];

static char mr_entry[MR_MAX_FILENAME_SIZE];

int32 mr_screen_w;
int32 mr_screen_h;

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
mr_c_function_st* mr_c_function_P;
int32 mr_c_function_P_len;

static int32* mr_c_function_fix_p;

MR_EVENT_FUNCTION mr_event_function = NULL;
MR_TIMER_FUNCTION mr_timer_function = NULL;
MR_STOP_FUNCTION mr_stop_function = NULL;
MR_PAUSEAPP_FUNCTION mr_pauseApp_function = NULL;
MR_RESUMEAPP_FUNCTION mr_resumeApp_function = NULL;

static mrc_timerCB mr_exit_cb = NULL;
static int32 mr_exit_cb_data;

int32 _mr_smsSetBytes(int32 pos, char* p, int32 len);
int32 _mr_smsAddNum(int32 index, char* pNum);
int32 _mr_load_sms_cfg(void);
int32 _mr_save_sms_cfg(int32 f);
int32 _mr_newSIMInd(int16 type, uint8* old_IMSI);
int _mr_isMr(char* input);
void _DrawPoint(int16 x, int16 y, uint16 nativecolor);
void _DrawBitmap(uint16* p, int16 x, int16 y, uint16 w, uint16 h, uint16 rop, uint16 transcoler, int16 sx, int16 sy, int16 mw);
void DrawRect(int16 x, int16 y, int16 w, int16 h, uint8 r, uint8 g, uint8 b);
int32 _DrawText(char* pcText, int16 x, int16 y, uint8 r, uint8 g, uint8 b, int is_unicode, uint16 font);
int _BitmapCheck(uint16* p, int16 x, int16 y, uint16 w, uint16 h, uint16 transcoler, uint16 color_check);
void* _mr_readFile(const char* filename, int* filelen, int lookfor);
int32 mr_registerAPP(uint8* p, int32 len, int32 index);
int32 _mr_c_function_new(MR_C_FUNCTION f, int32 len);
int _mr_EffSetCon(int16 x, int16 y, int16 w, int16 h, int16 perr, int16 perg, int16 perb);
int32 _DrawTextEx(char* pcText, int16 x, int16 y, mr_screenRectSt rect, mr_colourSt colorst, int flag, uint16 font);
int _mr_TestCom(mrp_State* L, int input0, int input1);
int _mr_TestCom1(mrp_State* L, int input0, char* input1, int32 len);
int32 mr_stop_ex(int16 freemem);
static int32 _mr_div(int32 a, int32 b);
static int32 _mr_mod(int32 a, int32 b);

static const void* _mr_c_internal_table[78];

static void _mr_c_internal_table_init() {
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

    _mr_c_internal_table[16] = (void*)asm_mrp_gettop;  //1937
    _mr_c_internal_table[17] = (void*)asm_mrp_settop;
    _mr_c_internal_table[18] = (void*)asm_mrp_pushvalue;
    _mr_c_internal_table[19] = (void*)asm_mrp_remove;
    _mr_c_internal_table[20] = (void*)asm_mrp_insert;
    _mr_c_internal_table[21] = (void*)asm_mrp_replace;

    _mr_c_internal_table[22] = (void*)asm_mrp_isnumber;
    _mr_c_internal_table[23] = (void*)asm_mrp_isstring;
    _mr_c_internal_table[24] = (void*)asm_mrp_iscfunction;
    _mr_c_internal_table[25] = (void*)asm_mrp_isuserdata;
    _mr_c_internal_table[26] = (void*)asm_mrp_type;
    _mr_c_internal_table[27] = (void*)asm_mrp_typename;
    _mr_c_internal_table[28] = (void*)asm_mrp_shorttypename;

    _mr_c_internal_table[29] = (void*)asm_mrp_equal;
    _mr_c_internal_table[30] = (void*)asm_mrp_rawequal;
    _mr_c_internal_table[31] = (void*)asm_mrp_lessthan;

    _mr_c_internal_table[32] = (void*)asm_mrp_tonumber;
    _mr_c_internal_table[33] = (void*)asm_mrp_toboolean;
    _mr_c_internal_table[34] = (void*)asm_mrp_tostring;
    _mr_c_internal_table[35] = (void*)asm_mrp_strlen;
    _mr_c_internal_table[36] = (void*)asm_mrp_tostring_t;
    _mr_c_internal_table[37] = (void*)asm_mrp_strlen_t;
    _mr_c_internal_table[38] = (void*)asm_mrp_tocfunction;
    _mr_c_internal_table[39] = (void*)asm_mrp_touserdata;
    _mr_c_internal_table[40] = (void*)asm_mrp_tothread;
    _mr_c_internal_table[41] = (void*)asm_mrp_topointer;

    _mr_c_internal_table[42] = (void*)asm_mrp_pushnil;
    _mr_c_internal_table[43] = (void*)asm_mrp_pushnumber;
    _mr_c_internal_table[44] = (void*)asm_mrp_pushlstring;
    _mr_c_internal_table[45] = (void*)asm_mrp_pushstring;
    _mr_c_internal_table[46] = (void*)asm_mrp_pushvfstring;
    _mr_c_internal_table[47] = (void*)asm_mrp_pushfstring;
    _mr_c_internal_table[48] = (void*)asm_mrp_pushboolean;
    _mr_c_internal_table[49] = (void*)asm_mrp_pushcclosure;

    _mr_c_internal_table[50] = (void*)asm_mrp_gettable;
    _mr_c_internal_table[51] = (void*)asm_mrp_rawget;
    _mr_c_internal_table[52] = (void*)asm_mrp_rawgeti;
    _mr_c_internal_table[53] = (void*)asm_mrp_newtable;
    _mr_c_internal_table[54] = (void*)asm_mrp_getmetatable;

    _mr_c_internal_table[55] = (void*)asm_mrp_settable;
    _mr_c_internal_table[56] = (void*)asm_mrp_rawset;
    _mr_c_internal_table[57] = (void*)asm_mrp_rawseti;

    _mr_c_internal_table[58] = (void*)asm_mrp_call;
    _mr_c_internal_table[59] = (void*)asm_mrp_pcall;
    _mr_c_internal_table[60] = (void*)asm_mrp_load;

    _mr_c_internal_table[61] = (void*)asm_mrp_getgcthreshold;
    _mr_c_internal_table[62] = (void*)asm_mrp_setgcthreshold;

    _mr_c_internal_table[63] = (void*)asm_mrp_error;

    _mr_c_internal_table[64] = (void*)asm_mrp_checkstack;
    _mr_c_internal_table[65] = (void*)asm_mrp_newuserdata;
    _mr_c_internal_table[66] = (void*)asm_mrp_getfenv;
    _mr_c_internal_table[67] = (void*)asm_mrp_setfenv;
    _mr_c_internal_table[68] = (void*)asm_mrp_setmetatable;
    _mr_c_internal_table[69] = (void*)asm_mrp_cpcall;
    _mr_c_internal_table[70] = (void*)asm_mrp_next;
    _mr_c_internal_table[71] = (void*)asm_mrp_concat;
    _mr_c_internal_table[72] = (void*)asm_mrp_pushlightuserdata;
    _mr_c_internal_table[73] = (void*)asm_mrp_getgccount;
    _mr_c_internal_table[74] = (void*)asm_mrp_dump;
    _mr_c_internal_table[75] = (void*)asm_mrp_yield;
    _mr_c_internal_table[76] = (void*)asm_mrp_resume;
    _mr_c_internal_table[77] = NULL;
}

static void* _mr_c_port_table[4];
static const void* _mr_c_function_table[150];

static void _mr_c_function_table_init() {
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
    _mr_c_function_table[145] = (void*)asm_mr_platDrawChar;  //1961
    _mr_c_function_table[146] = (void*)&LG_mem_free;         //1967,2009

    _mr_c_function_table[147] = (void*)asm_mr_transbitmapDraw;
    _mr_c_function_table[148] = (void*)asm_mr_drawRegion;
    _mr_c_function_table[149] = NULL;
}

static int32 _mr_div(int32 a, int32 b) {
    return a / b;
}

static int32 _mr_mod(int32 a, int32 b) {
    return a % b;
}

void _DrawPoint(int16 x, int16 y, uint16 nativecolor) {
    if (x < 0 || y < 0 || x >= MR_SCREEN_W || y >= MR_SCREEN_H)
        return;
    *MR_SCREEN_CACHE_POINT(x, y) = nativecolor;
}

void _DrawBitmap(uint16* p, int16 x, int16 y, uint16 w, uint16 h, uint16 rop, uint16 transcoler, int16 sx, int16 sy, int16 mw) {
    uint16 *dstp, *srcp;
    int MaxY = MIN(MR_SCREEN_H, y + h);
    int MaxX = MIN(MR_SCREEN_W, x + w);
    int MinY = MAX(0, y);
    int MinX = MAX(0, x);
    uint16 dx, dy;

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
    //   mr_drawRect(x,y,w,h,MAKERGB(r, g, b));
    uint16 *dstp, *srcp;
    int MaxY = MIN(MR_SCREEN_H, y + h);
    int MaxX = MIN(MR_SCREEN_W, x + w);
    int MinY = MAX(0, y);
    int MinX = MAX(0, x);
    uint16 dx, dy;
    uint16 nativecolor;

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
    return;
}

int32 _DrawText(char* pcText, int16 x, int16 y, uint8 r, uint8 g, uint8 b, int is_unicode, uint16 font) {
    int TextSize;
    uint16* tempBuf;
    // int tempret=0;

#ifdef MYTHROAD_DEBUG
    if (!pcText) {
        MRDBGPRINTF("DrawText x=%d: txt is nil!", x);
        return 0;
    }
#endif

    if (!is_unicode) {
        tempBuf = c2u((const char*)pcText, NULL, &TextSize);
        if (!tempBuf) {
            MRDBGPRINTF("DrawText x=%d:c2u err!", x);
            return 0;
        }
    } else {
        tempBuf = (uint16*)pcText;
    }

    {
        int width, height;
        const char* current_bitmap;
        uint8* p = (uint8*)tempBuf;
        // int32 X1,Y1;
        // uint16 a_,b_;
        uint16 chx = x, chy = y;
        // uint16 color=MAKERGB(r, g, b);
        uint16 ch = (uint16)((*p << 8) | *(p + 1));
        while (ch) {
            current_bitmap = mr_getCharBitmap(ch, font, &width, &height);
            if (current_bitmap) {
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
#else  //MR_FONT_LIB_REDUNDANCY_BIT

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

#endif  //MR_FONT_LIB_REDUNDANCY_BIT

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
            ch = (uint16)((*p << 8) | *(p + 1));
        };
    }
    if (!is_unicode) {
        MR_FREE((void*)tempBuf, TextSize);
    }
    return 0;
}

int32 _DrawTextEx(char* pcText, int16 x, int16 y, mr_screenRectSt rect, mr_colourSt colorst, int flag, uint16 font) {
    int TextSize, endchar_index;
    uint16* tempBuf;
    // int tempret=0;
    endchar_index = 0;

    if (!pcText) {
        MRDBGPRINTF("DrawTextEx x=%d: txt is nil!", x);
        return 0;
    }

    if (!(flag & DRAW_TEXT_EX_IS_UNICODE)) {
        tempBuf = c2u((const char*)pcText, NULL, &TextSize);
        if (!tempBuf) {
            MRDBGPRINTF("DrawTextEx x=%d:c2u err!", x);
            return 0;
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
        uint16 ch = (uint16)((*p << 8) | *(p + 1));
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
                    ch = (uint16)((*p << 8) | *(p + 1));
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
            ch = (uint16)((*p << 8) | *(p + 1));
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
        Y1 = X1;  // 抑制gcc编译时的set but not used警告
    }

    if (!(flag & DRAW_TEXT_EX_IS_UNICODE)) {
        MR_FREE((void*)tempBuf, TextSize);
    }
    return endchar_index;
}

int _BitmapCheck(uint16* p, int16 x, int16 y, uint16 w, uint16 h, uint16 transcoler, uint16 color_check) {
    uint16 *dstp, *srcp;
    int16 MaxY = MIN(MR_SCREEN_H, y + h);
    int16 MaxX = MIN(MR_SCREEN_W, x + w);
    int16 MinY = MAX(0, y);
    int16 MinX = MAX(0, x);
    uint16 dx, dy;
    int nResult = 0;

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

static int MRF_BmGetScr(mrp_State* L) {
    uint16 i = ((uint16)to_mr_tonumber(L, 1, 0));
    uint16 *srcp, *dstp;
    uint16 dx, dy;
    if (i >= BITMAPMAX) {
        mrp_pushfstring(L, "BmGetScr:index %d invalid!", i);
        mrp_error(L);
        return 0;
    }
    if (mr_bitmap[i].p) {
        MR_FREE(mr_bitmap[i].p, mr_bitmap[i].buflen);
        mr_bitmap[i].p = NULL;
    }

    mr_bitmap[i].p = MR_MALLOC(MR_SCREEN_W * MR_SCREEN_H * MR_SCREEN_DEEP);
    if (!mr_bitmap[i].p) {
        mrp_pushfstring(L, "BmGetScr %d :No memory!", i);
        mrp_error(L);
        return 0;
    }

    mr_bitmap[i].w = (int16)MR_SCREEN_W;
    mr_bitmap[i].h = (int16)MR_SCREEN_H;
    mr_bitmap[i].buflen = MR_SCREEN_W * MR_SCREEN_H * MR_SCREEN_DEEP;
    dstp = mr_bitmap[i].p;
    for (dy = 0; dy < MR_SCREEN_H; dy++) {
        //srcp = mr_screenBuf + dy * MR_SCREEN_MAX_W;
        srcp = MR_SCREEN_CACHE_POINT(0, dy);
        for (dx = 0; dx < MR_SCREEN_W; dx++) {
            *dstp = *srcp;
            dstp++;
            srcp++;
        }
    }
    return 0;
}

int _mr_EffSetCon(int16 x, int16 y, int16 w, int16 h, int16 perr, int16 perg, int16 perb) {
    uint16* dstp;
    uint32 color_old, coloer_new;
    int MaxY = MIN(MR_SCREEN_H, y + h);
    int MaxX = MIN(MR_SCREEN_W, x + w);
    int MinY = MAX(0, y);
    int MinX = MAX(0, x);
    uint16 dx, dy;

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

static int MRF_SpriteCheck(mrp_State* L) {
    uint16 i = ((uint16)to_mr_tonumber(L, 1, 0));
    uint16 spriteindex = ((uint16)to_mr_tonumber(L, 2, 0));
    int16 x = ((int16)to_mr_tonumber(L, 3, 0));
    int16 y = ((int16)to_mr_tonumber(L, 4, 0));
    uint32 color_check = ((uint32)to_mr_tonumber(L, 5, 0));
    uint32 color;
    uint16 r, g, b;
#ifdef MYTHROAD_DEBUG
    if (i >= SPRITEMAX) {
        mrp_pushfstring(L, "SpriteCheck:index %d invalid!", i);
        mrp_error(L);
        return 0;
    }
    if (!mr_bitmap[i].p) {
        mrp_pushfstring(L, "SpriteCheck:Sprite %d is nil!", i);
        mrp_error(L);
        return 0;
    }
#endif
    r = (uint16)((color_check & 0xff0000) >> 16);
    g = (uint16)((color_check & 0xff00) >> 8);
    b = (uint16)(color_check & 0xff);

    color = MAKERGB(r, g, b);
    //   return mr_check(mr_bitmap[i].p + spriteindex*mr_bitmap[i].w*mr_sprite[i].h,
    //      x, y, mr_bitmap[i].w, mr_sprite[i].h, *(mr_bitmap[i].p), color);
    {
        int to_mr_ret = (int)_BitmapCheck(mr_bitmap[i].p +
                                              spriteindex * mr_bitmap[i].w * mr_sprite[i].h,
                                          (uint16)x, (uint16)y, (uint16)mr_bitmap[i].w, (uint16)mr_sprite[i].h,
                                          (uint16) * (mr_bitmap[i].p), (uint16)color);
        to_mr_pushnumber(L, (mrp_Number)to_mr_ret);
    }

    return 1;
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
    MRDBGPRINTF("read file  \"%s\" err, code=%d", filename, code);
}

void* _mr_readFile(const char* filename, int* filelen, int lookfor) {
    // int ret;
    int method;
    uint32 reallen, found = 0;
    int32 oldlen, nTmp;
    uint32 len;
    void* filebuf;
    int32 f;
    char TempName[MR_MAX_FILENAME_SIZE];
    char* mr_m0_file;
    int is_rom_file = FALSE;

    if ((pack_filename[0] == '*') || (pack_filename[0] == '$')) { /*m0 file or ram file?*/
        uint32 pos = 0;
        uint32 m0file_len;

        if (pack_filename[0] == '*') {                                 /*m0 file?*/
            mr_m0_file = (char*)mr_m0_files[pack_filename[1] - 0x41];  //这里定义文件名为*A即是第一个m0文件 *B是第二个.........
        } else {
            mr_m0_file = mr_ram_file;
        }

        if (mr_m0_file == NULL) {
            //MRDBGPRINTF( "_mr_readFile:mr_m0_file nil at \"%s\"!",filename);
            _mr_readFileShowInfo(filename, 1001);
            return 0;
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
                    return 0;
                }
            } else {
            }
#endif
        } else {
            MEMCPY(&m0file_len, &mr_m0_file[pos], 4);
        }

        //MRDBGPRINTF("readFile 11 len = %d", len);
        //MRDBGPRINTF("readFile 21 len = %d", m0file_len);
        pos = pos + len;
        while (!found) {
            if (((pos + 4) >= m0file_len) || (len < 1) || (len >= MR_MAX_FILE_SIZE)) {
                _mr_readFileShowInfo(filename, 1004);
                return 0;
            }
            MEMCPY(&len, &mr_m0_file[pos], 4);

            pos = pos + 4;
            if (((len + pos) >= m0file_len) || (len < 1) || (len >= MR_MAX_FILENAME_SIZE)) {
                _mr_readFileShowInfo(filename, 1002);
                return 0;
            }
            MEMSET(TempName, 0, sizeof(TempName));
            MEMCPY(TempName, &mr_m0_file[pos], len);
            pos = pos + len;
            if (STRCMP(filename, TempName) == 0) {
                if (lookfor == 1) {
                    return (void*)1;
                }
                found = 1;
                MEMCPY(&len, &mr_m0_file[pos], 4);

                pos = pos + 4;
                if (((len + pos) > m0file_len) || (len < 1) || (len >= MR_MAX_FILE_SIZE)) {
                    _mr_readFileShowInfo(filename, 1003);
                    return 0;
                }
            } else {
                MEMCPY(&len, &mr_m0_file[pos], 4);

                pos = pos + 4 + len;
            } /*if (STRCMP(filename, TempName)==0)*/
        }

        *filelen = len;
        if (*filelen <= 0) {
            _mr_readFileShowInfo(filename, 1005);
            return 0;
        }

        if (lookfor == 2) {
            return (void*)&mr_m0_file[pos];
        }
        filebuf = &mr_m0_file[pos];
        is_rom_file = TRUE;
    } else { /*read file from efs , EFS 中的文件*/
        f = mr_open(pack_filename, MR_FILE_RDONLY);
        if (f == 0) {
            _mr_readFileShowInfo(filename, 2002);
            return 0;
        }

        // 从这里开始是新版的mrp处理
        {
            uint32 headbuf[4];
            nTmp = mr_read(f, &headbuf, sizeof(headbuf));
            if ((nTmp != 16) || (headbuf[0] != 1196446285)) {
                mr_close(f);
                _mr_readFileShowInfo(filename, 3001);
                return 0;
            }
            if (headbuf[1] > 232) {  //新版mrp
                uint32 indexlen = headbuf[1] + 8 - headbuf[3];
                uint8* indexbuf = MR_MALLOC(indexlen);
                uint32 pos = 0;
                uint32 file_pos, file_len;
                if (!indexbuf) {
                    mr_close(f);
                    _mr_readFileShowInfo(filename, 3003);
                    return 0;
                }
                nTmp = mr_seek(f, headbuf[3] - 16, MR_SEEK_CUR);
                if (nTmp < 0) {
                    mr_close(f);
                    MR_FREE(indexbuf, indexlen);
                    _mr_readFileShowInfo(filename, 3002);
                    return 0;
                }

                nTmp = mr_read(f, indexbuf, indexlen);

                if ((nTmp != (int32)indexlen)) {
                    mr_close(f);
                    MR_FREE(indexbuf, indexlen);
                    _mr_readFileShowInfo(filename, 3003);
                    return 0;
                }

                while (!found) {
                    MEMCPY(&len, &indexbuf[pos], 4);
                    pos = pos + 4;
                    if (((len + pos) > indexlen) || (len < 1) || (len >= MR_MAX_FILENAME_SIZE)) {
                        mr_close(f);
                        MR_FREE(indexbuf, indexlen);
                        _mr_readFileShowInfo(filename, 3004);
                        return 0;
                    }
                    MEMSET(TempName, 0, sizeof(TempName));
                    MEMCPY(TempName, &indexbuf[pos], len);
                    pos = pos + len;
                    if (STRCMP(filename, TempName) == 0) {
                        if (lookfor == 1) {
                            mr_close(f);
                            MR_FREE(indexbuf, indexlen);
                            return (void*)1;
                        }
                        found = 1;
                        MEMCPY(&file_pos, &indexbuf[pos], 4);
                        pos = pos + 4;
                        MEMCPY(&file_len, &indexbuf[pos], 4);
                        pos = pos + 4;
                        if ((file_pos + file_len) > headbuf[2]) {
                            mr_close(f);
                            MR_FREE(indexbuf, indexlen);
                            _mr_readFileShowInfo(filename, 3005);
                            return 0;
                        }
                    } else {
                        pos = pos + 12;
                        if (pos >= indexlen) {
                            mr_close(f);
                            MR_FREE(indexbuf, indexlen);
                            _mr_readFileShowInfo(filename, 3006);
                            return 0;
                        }
                    } /*if (STRCMP(filename, TempName)==0)*/
                }

                MR_FREE(indexbuf, indexlen);

                *filelen = file_len;

                filebuf = MR_MALLOC((uint32)*filelen);
                if (filebuf == NULL) {
                    mr_close(f);
                    _mr_readFileShowInfo(filename, 3007);
                    return 0;
                }

                nTmp = mr_seek(f, file_pos, MR_SEEK_SET);
                if (nTmp < 0) {
                    MR_FREE(filebuf, *filelen);
                    mr_close(f);
                    _mr_readFileShowInfo(filename, 3008);
                    return 0;
                }

                oldlen = 0;
                while (oldlen < *filelen) {
                    nTmp = mr_read(f, (char*)filebuf + oldlen, *filelen - oldlen);
                    if (nTmp <= 0) {
                        MR_FREE(filebuf, *filelen);
                        mr_close(f);
                        _mr_readFileShowInfo(filename, 3009);
                        return 0;
                    }
                    oldlen = oldlen + nTmp;
                }

                /*

                  oldlen = mr_read(f, filebuf, *filelen);
                  if (oldlen <= 0)
                  {
                      MR_FREE(filebuf, *filelen);
                      mr_close(f);
                      _mr_readFileShowInfo(pack_filename, 2014);
                      return 0;
                  }
                */

                //mr_read1(filename, filebuf, *filelen);
                mr_close(f);

            } else {  //旧版mrp
                nTmp = mr_seek(f, headbuf[1] - 8, 1);
                if (nTmp < 0) {
                    mr_close(f);
                    _mr_readFileShowInfo(filename, 3002);
                    return 0;
                }

                while (!found) {
                    nTmp = mr_read(f, &len, 4);

                    if ((nTmp != 4) || (len < 1) || (len >= MR_MAX_FILENAME_SIZE)) {
                        mr_close(f);
                        _mr_readFileShowInfo(filename, 2007);
                        return 0;
                    }
                    MEMSET(TempName, 0, sizeof(TempName));
                    nTmp = mr_read(f, TempName, len);
                    if (nTmp != (int32)len) {
                        mr_close(f);
                        _mr_readFileShowInfo(filename, 2008);
                        return 0;
                    }
                    if (STRCMP(filename, TempName) == 0) {
                        if (lookfor == 1) {
                            mr_close(f);
                            return (void*)1;
                        }
                        found = 1;
                        nTmp = mr_read(f, &len, 4);

                        if ((nTmp != 4) || (len < 1) || (len > MR_MAX_FILE_SIZE)) {
                            _mr_readFileShowInfo(filename, 2009);
                            mr_close(f);
                            return 0;
                        }
                    } else {
                        nTmp = mr_read(f, &len, 4);

                        if ((nTmp != 4) || (len < 1) || (len > MR_MAX_FILE_SIZE)) {
                            _mr_readFileShowInfo(filename, 2010);
                            mr_close(f);
                            return 0;
                        }
                        nTmp = mr_seek(f, len, 1);
                        if (nTmp < 0) {
                            _mr_readFileShowInfo(filename, 2011);
                            mr_close(f);
                            return 0;
                        }
                    }
                }

                *filelen = len;
                if (*filelen <= 0) {
                    mr_close(f);
                    _mr_readFileShowInfo(filename, 2012);
                    return 0;
                }

                filebuf = MR_MALLOC((uint32)*filelen);
                if (filebuf == NULL) {
                    mr_close(f);
                    _mr_readFileShowInfo(filename, 2013);
                    return 0;
                }

                oldlen = 0;
                while (oldlen < *filelen) {
                    nTmp = mr_read(f, (char*)filebuf + oldlen, *filelen - oldlen);
                    if (nTmp <= 0) {
                        MR_FREE(filebuf, *filelen);
                        mr_close(f);
                        _mr_readFileShowInfo(filename, 2014);
                        return 0;
                    }
                    oldlen = oldlen + nTmp;
                }
                //mr_read1(filename, filebuf, *filelen);
                mr_close(f);
            }  //旧版mrp
        }
    } /*efs file*/

    mr_gzInBuf = filebuf;
    LG_gzoutcnt = 0;
    LG_gzinptr = 0;

    method = mr_get_method(*filelen);
    if (method < 0) {
        return filebuf;
    }

    reallen = *(uint32*)((uint8*)filebuf + *filelen - sizeof(uint32));

    //MRDBGPRINTF("Debug:_mr_readFile:filelen = %d",reallen);
    //MRDBGPRINTF("Debug:_mr_readFile:mem left = %d",LG_mem_left);

    //MRDBGPRINTF("1base=%d,end=%d",  (int32)LG_mem_base, (int32)LG_mem_end);
    //MRDBGPRINTF("is_rom_file = %d",is_rom_file);
    mr_gzOutBuf = MR_MALLOC(reallen);
    //MRDBGPRINTF("mr_gzOutBuf = %d",mr_gzOutBuf);
    oldlen = *filelen;
    *filelen = reallen;
    //MRDBGPRINTF("2base=%d,end=%d",  (int32)LG_mem_base, (int32)LG_mem_end);
    if (mr_gzOutBuf == NULL) {
        if (!is_rom_file)
            MR_FREE(mr_gzInBuf, oldlen);
        //MRDBGPRINTF("_mr_readFile  \"%s\" Not memory unzip!", filename);
        return 0;
    }

    //MRDBGPRINTF("3base=%d,end=%d",  (int32)LG_mem_base, (int32)LG_mem_end);
    if (mr_unzip() != 0) {
        if (!is_rom_file)
            MR_FREE(mr_gzInBuf, oldlen);
        MR_FREE(mr_gzOutBuf, reallen);
        MRDBGPRINTF("_mr_readFile: \"%s\" Unzip err!", filename);
        return 0;
    }

    //MRDBGPRINTF("4base=%d,end=%d",  (int32)LG_mem_base, (int32)LG_mem_end);
    //MRDBGPRINTF("is_rom_file = %d",is_rom_file);
    if (!is_rom_file)
        MR_FREE(mr_gzInBuf, oldlen);

    //MRDBGPRINTF("is_rom_file = %d",is_rom_file);
    //MRDBGPRINTF("5base=%d,end=%d",  (int32)LG_mem_base, (int32)LG_mem_end);
    return mr_gzOutBuf;
}

#define CHECK_MRP_BUF_SIZE 10240
int32 mr_checkMrp(char* mrp_name) {
    int32 f;
    uint32 headbuf[4];
    int32 nTmp, crc32;
    uint8* tempbuf;

    tempbuf = MR_MALLOC(CHECK_MRP_BUF_SIZE);
    if (tempbuf == NULL) {
        MRDBGPRINTF("mrc_checkMrp err %d", 0);
        return MR_FAILED - 1;
    }
    f = mr_open(mrp_name, MR_FILE_RDONLY);
    if (f == 0) {
        MR_FREE(tempbuf, CHECK_MRP_BUF_SIZE);
        MRDBGPRINTF("mrc_checkMrp err %d", 1);
        return MR_FAILED - 2;
    }

    MEMSET(headbuf, 0, sizeof(headbuf));
    nTmp = mr_read(f, &headbuf, sizeof(headbuf));
    mr_updcrc(NULL, 0);
    mr_updcrc((uint8*)&headbuf, sizeof(headbuf));
    if ((nTmp != 16) || (headbuf[0] != 1196446285 /*1196446285*/) || (headbuf[1] <= 232)) {
        mr_close(f);
        MR_FREE(tempbuf, CHECK_MRP_BUF_SIZE);
        //MRDBGPRINTF("%d", headbuf[0]);
        //MRDBGPRINTF("%d", headbuf[1]);
        //MRDBGPRINTF("%d", nTmp);
        MRDBGPRINTF("mrc_checkMrp err %d", 2);
        return MR_FAILED - 3;
    }

    nTmp = mr_read(f, tempbuf, 224);
    if (nTmp != 224) {
        mr_close(f);
        MR_FREE(tempbuf, CHECK_MRP_BUF_SIZE);
        MRDBGPRINTF("mrc_checkMrp err %d", 3);
        return MR_FAILED - 4;
    }

    //2008-6-11
    // if (tempbuf[192] != 2) // 展迅
    if (tempbuf[192] != 1) {
        mr_close(f);
        MR_FREE(tempbuf, CHECK_MRP_BUF_SIZE);
        MRDBGPRINTF("mrc_checkMrp err %d", 31);
        return MR_FAILED - 5;
    }
    //2008-6-11

    MEMCPY(&crc32, &tempbuf[68], 4);
    MEMSET(&tempbuf[68], 0, 4);
    mr_updcrc(tempbuf, 224);

    while (nTmp > 0) {
        nTmp = mr_read(f, tempbuf, 10240);
        if (nTmp > 0) {
            mr_updcrc(tempbuf, nTmp);
        }
    }
    if (crc32 == mr_updcrc(tempbuf, 0)) {
        nTmp = MR_SUCCESS;
    } else {
        //MRDBGPRINTF("%d", crc32);
        //MRDBGPRINTF("%d", t);
        MRDBGPRINTF("mrc_checkMrp err %d", 4);
        nTmp = MR_FAILED - 6;
    }
    mr_close(f);
    MR_FREE(tempbuf, CHECK_MRP_BUF_SIZE);
    return nTmp;
}

int32 _DispUpEx(int16 x, int16 y, uint16 w, uint16 h) {
    if (mr_state == MR_STATE_RUN) {
        mr_drawBitmap(mr_screenBuf, x, y, (uint16)w, (uint16)h);
    }
    return 0;
}

static int MRF_DispUpEx(mrp_State* L) {
    if (mr_state == MR_STATE_RUN) {
        int16 x = ((int16)mrp_tonumber(L, 1));
        int16 y = ((int16)mrp_tonumber(L, 2));
        uint16 w = ((uint16)mrp_tonumber(L, 3));
        uint16 h = ((uint16)mrp_tonumber(L, 4));
        _DispUpEx(x, y, w, h);
    }
    return 0;
}

static int MRF_DispUp(mrp_State* L) {
    int16 x = ((int16)mrp_tonumber(L, 1));
    int16 y = ((int16)mrp_tonumber(L, 2));
    uint16 w = ((uint16)mrp_tonumber(L, 3));
    uint16 h = ((uint16)mrp_tonumber(L, 4));
    uint16 i = ((uint16)mr_L_optlong(L, 5, BITMAPMAX));

    mr_drawBitmap(mr_bitmap[i].p + y * mr_bitmap[i].h + x, x, y, (uint16)w, (uint16)h);
    return 0;
}

static int MRF_TimerStart(mrp_State* L) {
    // int n = ((int)  to_mr_tonumber(L,1,0));
    uint16 thistime = ((uint16)to_mr_tonumber(L, 2, 0));
    char* pcFunction = ((char*)to_mr_tostring(L, 3, 0));
    if (!((mr_state == MR_STATE_RUN) || ((mr_timer_run_without_pause) && (mr_state == MR_STATE_PAUSE)))) {
        return 0;
    }
    mr_timer_p = (void*)pcFunction;
    MR_TIME_START(thistime);
    //mr_timer_state = MR_TIMER_STATE_RUNNING;
    return 0;
}

static int MRF_TimerStop(mrp_State* L) {
    // int n = ((int)  to_mr_tonumber(L,1,0));
    to_mr_tonumber(L, 1, 0);
    MR_TIME_STOP();
    //mr_timer_state = MR_TIMER_STATE_IDLE;
    return 0;
}

static int MRF_DrawText(mrp_State* L) {
    char* pcText = ((char*)to_mr_tostring(L, 1, 0));
    int16 x = ((int16)to_mr_tonumber(L, 2, 0));
    int16 y = ((int16)to_mr_tonumber(L, 3, 0));
    uint8 r = ((uint8)to_mr_tonumber(L, 4, 0));
    uint8 g = ((uint8)to_mr_tonumber(L, 5, 0));
    uint8 b = ((uint8)to_mr_tonumber(L, 6, 0));
    int is_unicode = to_mr_toboolean(L, 7, FALSE);
    uint16 font = (uint16)mr_L_optlong(L, 8, MR_FONT_MEDIUM);
    return _DrawText(pcText, x, y, r, g, b, is_unicode, font);
}

static int MRF_DrawTextEx(mrp_State* L) {
    char* pcText = ((char*)to_mr_tostring(L, 1, 0));
    int16 x, y;
    mr_screenRectSt rect;
    mr_colourSt color;
    int32 flag = (int32)mr_L_optnumber(L, 11, DRAW_TEXT_EX_IS_UNICODE | DRAW_TEXT_EX_IS_AUTO_NEWLINE);
    uint16 font = (uint16)mr_L_optnumber(L, 12, MR_FONT_MEDIUM);
    x = ((int16)to_mr_tonumber(L, 2, 0));
    y = ((int16)to_mr_tonumber(L, 3, 0));
    rect.x = ((int16)to_mr_tonumber(L, 4, 0));
    rect.y = ((int16)to_mr_tonumber(L, 5, 0));
    rect.w = ((int16)to_mr_tonumber(L, 6, 0));
    rect.h = ((int16)to_mr_tonumber(L, 7, 0));
    color.r = ((uint8)to_mr_tonumber(L, 8, 0));
    color.g = ((uint8)to_mr_tonumber(L, 9, 0));
    color.b = ((uint8)to_mr_tonumber(L, 10, 0));
    mrp_pushnumber(L, _DrawTextEx(pcText, x, y, rect, color, flag, font));
    return 1;
}

static int MRF_TextWidth(mrp_State* L) {
    char* pcText;
    int is_unicode;
    uint16 font;

    int TextSize;
    uint16* tempBuf;
    //int tempret=0;
    uint16 x = 0;
    uint16 y = 0;

    if (mrp_type(L, 1) == MRP_TSTRING) {
        pcText = ((char*)to_mr_tostring(L, 1, 0));
        is_unicode = to_mr_toboolean(L, 2, FALSE);
        font = (uint16)mr_L_optlong(L, 3, MR_FONT_MEDIUM);

        if (!pcText) {
            mrp_pushfstring(vm_state, "TextWidth: txt is nil!");
            mrp_error(vm_state);
            return 0;
        }

        if (!is_unicode) {
            tempBuf = c2u((const char*)pcText, NULL, &TextSize);
            if (!tempBuf) {
                mrp_pushfstring(vm_state, "TextWidth:c2u err! 1");
                mrp_error(vm_state);
                return 0;
            }
        } else {
            tempBuf = (uint16*)pcText;
        }

        {
            uint16 ch;
            int width, height;
            uint8* p = (uint8*)tempBuf;
            ch = (uint16)((*p << 8) + *(p + 1));
            while (ch) {
                mr_getCharBitmap(ch, font, &width, &height);
                p += 2;
                x = x + width;
                y = (height > y) ? height : y;
                ch = (uint16)((*p << 8) + *(p + 1));
            };
        }
        if (!is_unicode) {
            MR_FREE((void*)tempBuf, TextSize);
        }
        mrp_pushnumber(L, x);
        mrp_pushnumber(L, y);

    } else {
        char temp[4];
        uint16 ch = ((uint16)mrp_tonumber(L, 1));
        int width, height;

        is_unicode = to_mr_toboolean(L, 2, FALSE);
        font = (uint16)mr_L_optlong(L, 3, MR_FONT_MEDIUM);

        if (is_unicode) {
            mr_getCharBitmap(ch, font, &width, &height);
        } else {
            if (ch < 128) {
                mr_getCharBitmap(ch, font, &width, &height);
            } else {
                temp[0] = ch / 256;
                temp[1] = ch % 256;
                temp[3] = 0;
                tempBuf = c2u((const char*)temp, NULL, &TextSize);
                if (!tempBuf) {
                    mrp_pushfstring(vm_state, "TextWidth:c2u err! 2");
                    mrp_error(vm_state);
                    return 0;
                }
                ch = (uint16)(((tempBuf[0] << 8) + tempBuf[1]));
                mr_getCharBitmap(ch, font, &width, &height);
                MR_FREE((void*)tempBuf, TextSize);
            }
        }
        mrp_pushnumber(L, width);
        mrp_pushnumber(L, height);
    }
    return 2;
}

static int MRF_DrawRect(mrp_State* L) {
    int16 x = ((int16)to_mr_tonumber(L, 1, 0));
    int16 y = ((int16)to_mr_tonumber(L, 2, 0));
    int16 w = ((int16)to_mr_tonumber(L, 3, 0));
    int16 h = ((int16)to_mr_tonumber(L, 4, 0));
    uint8 r = ((uint8)to_mr_tonumber(L, 5, 0));
    uint8 g = ((uint8)to_mr_tonumber(L, 6, 0));
    uint8 b = ((uint8)to_mr_tonumber(L, 7, 0));
    DrawRect(x, y, w, h, r, g, b);
    return 0;
}

static int MRF_DrawPoint(mrp_State* L) {
    int16 x = ((int16)to_mr_tonumber(L, 1, 0));
    int16 y = ((int16)to_mr_tonumber(L, 2, 0));
    uint8 r = ((uint8)to_mr_tonumber(L, 3, 0));
    uint8 g = ((uint8)to_mr_tonumber(L, 4, 0));
    uint8 b = ((uint8)to_mr_tonumber(L, 5, 0));
    uint16 nativecolor;
    nativecolor = MAKERGB(r, g, b);
    _DrawPoint(x, y, nativecolor);
    return 0;
}

static int MRF_DrawLine(mrp_State* L) {
    int16 x1 = ((int16)to_mr_tonumber(L, 1, 0));
    int16 y1 = ((int16)to_mr_tonumber(L, 2, 0));
    int16 x2 = ((int16)to_mr_tonumber(L, 3, 0));
    int16 y2 = ((int16)to_mr_tonumber(L, 4, 0));
    uint8 r = ((uint8)to_mr_tonumber(L, 5, 0));
    uint8 g = ((uint8)to_mr_tonumber(L, 6, 0));
    uint8 b = ((uint8)to_mr_tonumber(L, 7, 0));
    int x, y, dx, dy, c1, c2, err, swap = 0;

    uint16 nativecolor;
    nativecolor = MAKERGB(r, g, b);

    /*   
    if (x1 < 0 || x1 >= MR_SCREEN_W || x2 < 0 || x2 >= MR_SCREEN_W ||
        y1 < 0 || y1 >= MR_SCREEN_H || y2 < 0 || y2 >= MR_SCREEN_H)
        return;
    */

    dx = x2 - x1;
    dy = y2 - y1;
    if (((dx < 0) ? -dx : dx) < ((dy < 0) ? -dy : dy)) {
        swap = 1; /* take the long way        */
        x = x1;
        x1 = y1;
        y1 = x;
        x = x2;
        x2 = y2;
        y2 = x;
    }
    if (x1 > x2) {
        x = x1;
        x1 = x2;
        x2 = x; /* always move to the right */
        y = y1;
        y1 = y2;
        y2 = y;
    }

    dx = x2 - x1;
    dy = y2 - y1;
    c1 = dy * 2;
    dy = 1;
    if (c1 < 0) {
        c1 = -c1;
        dy = -1;
    }
    err = c1 - dx;
    c2 = err - dx;
    x = x1;
    y = y1;
    while (x <= x2) {
        _DrawPoint((int16)(swap ? y : x), (int16)(swap ? x : y), nativecolor);
        x++;
        if (err < 0)
            err += c1;
        else {
            y += dy;
            err += c2;
        }
    }
    return 0;
}

static int MRF_BitmapLoad(mrp_State* L) {
    uint16 i = ((uint16)to_mr_tonumber(L, 1, 0));
    char* filename = ((char*)to_mr_tostring(L, 2, 0));
    int16 x = ((int16)to_mr_tonumber(L, 3, 0));
    int16 y = ((int16)to_mr_tonumber(L, 4, 0));
    uint16 w = ((uint16)to_mr_tonumber(L, 5, 0));
    uint16 h = ((uint16)to_mr_tonumber(L, 6, 0));
    uint16 max_w = ((uint16)to_mr_tonumber(L, 7, 0));
    uint16 *filebuf, *srcp, *dstp;
    int filelen;
    uint16 y2 = y + h;
    uint16 dx, dy;

    if (!(bi & MR_FLAGS_BI)) {
        mrp_pushfstring(L, "BitmapLoad:cannot read File \"%s\"!", filename);
        mrp_error(L);
        return 0;
    }

    if (i > BITMAPMAX) {
        mrp_pushfstring(L, "BitmapLoad:index %d invalid!", i);
        mrp_error(L);
        return 0;
    }
    if (mr_bitmap[i].p) {
        MR_FREE(mr_bitmap[i].p, mr_bitmap[i].buflen);
        mr_bitmap[i].p = NULL;
    }

    if (*filename == '*') {
        return 0;
    }
    //MRDBGPRINTF("BitmapLoad:1 %s", filename);
    filebuf = _mr_readFile(filename, &filelen, 0);
    if (!filebuf) {
        mrp_pushfstring(L, "BitmapLoad %d:cannot read \"%s\"!", i, filename);
        mrp_error(L);
        return 0;
    }

    mr_bitmap[i].w = w;
    mr_bitmap[i].h = h;

    //MRDBGPRINTF("BitmapLoad:2 %s", filename);
    if ((x == 0) && (y == 0) && (w == max_w)) {
        mr_bitmap[i].p = filebuf;
        mr_bitmap[i].buflen = filelen;
    } else if (w * h * MR_SCREEN_DEEP < filelen) {
        mr_bitmap[i].p = MR_MALLOC(w * h * MR_SCREEN_DEEP);
        if (!mr_bitmap[i].p) {
            MR_FREE(filebuf, filelen);
            mrp_pushfstring(L, "BitmapLoad %d \"%s\":No memory!", i, filename);
            mrp_error(L);
            return 0;
        }
        mr_bitmap[i].buflen = w * h * MR_SCREEN_DEEP;
        dstp = mr_bitmap[i].p;
        for (dy = y; dy < y2; dy++) {
            srcp = filebuf + dy * max_w + x;
            for (dx = 0; dx < w; dx++) {
                *dstp = *srcp;
                dstp++;
                srcp++;
            }
        }
        MR_FREE(filebuf, filelen);
        //MRDBGPRINTF("BitmapLoad:4 %s", filename);
    } else {
        //MRDBGPRINTF("BitmapLoad:5 %s", filename);
        MR_FREE(filebuf, filelen);
        mrp_pushfstring(L, "BitmapLoad %d \"%s\":len err!", i, filename);
        mrp_error(L);
        return 0;
    }

    //MRDBGPRINTF("BitmapLoad:3 %s", filename);
    return 0;
}

static int MRF_BitmapShow(mrp_State* L) {
    uint16 i = ((uint16)to_mr_tonumber(L, 1, 0));
    int16 x = ((int16)to_mr_tonumber(L, 2, 0));
    int16 y = ((int16)to_mr_tonumber(L, 3, 0));
    uint16 rop = ((uint16)mr_L_optint(L, 4, BM_COPY));
    int16 sx = ((int16)mr_L_optint(L, 5, 0));
    int16 sy = ((int16)mr_L_optint(L, 6, 0));
    int16 w = ((int16)mr_L_optint(L, 7, -1));
    int16 h = ((int16)mr_L_optint(L, 8, -1));
#ifdef MYTHROAD_DEBUG
    if (i > BITMAPMAX) {
        mrp_pushfstring(L, "BitmapShow:index %d invalid!", i);
        mrp_error(L);
        return 0;
    }
    if (!mr_bitmap[i].p) {
        mrp_pushfstring(L, "BitmapShow %d:bitmap is nil!", i);
        mrp_error(L);
        return 0;
    }
#endif

    w = (w == -1) ? mr_bitmap[i].w : w;
    h = (h == -1) ? mr_bitmap[i].h : h;
    //   mr_drawBitmap(mr_bitmap[i].p, x, y, mr_bitmap[i].w, mr_bitmap[i].h, rop, *(mr_bitmap[i].p));
    _DrawBitmap(mr_bitmap[i].p, x, y, w, h, rop, *(mr_bitmap[i].p), sx, sy, mr_bitmap[i].w);
    return 0;
}

static int MRF_BitmapShowEx(mrp_State* L) {
    uint16* p = ((uint16*)mrp_tonumber(L, 1));
    int16 x = ((int16)mrp_tonumber(L, 2));
    int16 y = ((int16)mrp_tonumber(L, 3));
    int16 mw = ((int16)mrp_tonumber(L, 4));
    int16 w = ((int16)mrp_tonumber(L, 5));
    int16 h = ((int16)mrp_tonumber(L, 6));
    uint16 rop = ((uint16)mr_L_optint(L, 7, BM_COPY));
    int16 sx = ((int16)mr_L_optint(L, 8, 0));
    int16 sy = ((int16)mr_L_optint(L, 9, 0));

    _DrawBitmap(p, x, y, w, h, rop, *p, sx, sy, mw);
    return 0;
}

static int MRF_BitmapNew(mrp_State* L) {
    uint16 i = ((uint16)to_mr_tonumber(L, 1, 0));
    uint16 w = ((uint16)to_mr_tonumber(L, 2, 0));
    uint16 h = ((uint16)to_mr_tonumber(L, 3, 0));
    if (i > BITMAPMAX) {
        mrp_pushfstring(L, "BitmapNew:index %d invalid!", i);
        mrp_error(L);
        return 0;
    }
    if (mr_bitmap[i].buflen != w * h * 2) {
        if (mr_bitmap[i].p) {
            MR_FREE(mr_bitmap[i].p, mr_bitmap[i].buflen);
            mr_bitmap[i].p = NULL;
        }
        mr_bitmap[i].p = MR_MALLOC(w * h * 2);
        if (!mr_bitmap[i].p) {
            mrp_pushfstring(L, "BitmapNew %d :No memory!", i);
            mrp_error(L);
            return 0;
        }
        MEMSET(mr_bitmap[i].p, 0, w * h * 2);
    }
    mr_bitmap[i].buflen = w * h * 2;
    mr_bitmap[i].w = w;
    mr_bitmap[i].h = h;
    return 0;
}

static int MRF_BitmapDraw(mrp_State* L) {
    uint16 di = ((uint16)to_mr_tonumber(L, 1, 0));
    int16 dx = ((int16)to_mr_tonumber(L, 2, 0));
    int16 dy = ((int16)to_mr_tonumber(L, 3, 0));
    uint16 si = ((uint16)to_mr_tonumber(L, 4, 0));
    int16 sx = ((int16)to_mr_tonumber(L, 5, 0));
    int16 sy = ((int16)to_mr_tonumber(L, 6, 0));
    uint16 w = ((uint16)to_mr_tonumber(L, 7, 0));
    uint16 h = ((uint16)to_mr_tonumber(L, 8, 0));
    int16 A = ((int16)to_mr_tonumber(L, 9, 0));
    int16 B = ((int16)to_mr_tonumber(L, 10, 0));
    int16 C = ((int16)to_mr_tonumber(L, 11, 0));
    int16 D = ((int16)to_mr_tonumber(L, 12, 0));
    uint16 rop = ((uint16)to_mr_tonumber(L, 13, BM_COPY));

    mr_transMatrixSt Trans;
    mr_bitmapDrawSt srcbmp;
    mr_bitmapDrawSt dstbmp;

    if ((si > BITMAPMAX) || (di > BITMAPMAX)) {
        mrp_pushfstring(L, "BitmapDraw:index %d or %d invalid!", di, si);
        mrp_error(L);
        return 0;
    }

    if ((!mr_bitmap[si].p) || (!mr_bitmap[di].p)) {
        mrp_pushfstring(L, "BitmapDraw:index %d or %d invalid!", di, si);
        mrp_error(L);
        return 0;
    }

    Trans.A = A;
    Trans.B = B;
    Trans.C = C;
    Trans.D = D;
    Trans.rop = rop;

    dstbmp.w = mr_bitmap[di].w;
    dstbmp.h = mr_bitmap[di].h;
    dstbmp.x = dx;
    dstbmp.y = dy;
    dstbmp.p = mr_bitmap[di].p;

    srcbmp.w = mr_bitmap[si].w;
    srcbmp.h = mr_bitmap[si].h;
    srcbmp.x = sx;
    srcbmp.y = sy;
    srcbmp.p = mr_bitmap[si].p;

    _DrawBitmapEx(&srcbmp, &dstbmp, w, h, &Trans, *(mr_bitmap[si].p));
    return 0;
}

static int MRF_BitmapInfo(mrp_State* L) {
    uint16 i = ((uint16)to_mr_tonumber(L, 1, 0));
    if (i > BITMAPMAX) {
        mrp_pushfstring(L, "MRF_BitmapInfo:index %d invalid!", i);
        mrp_error(L);
        return 0;
    }
    mrp_pushnumber(L, (mrp_Number)mr_bitmap[i].p);
    mrp_pushnumber(L, mr_bitmap[i].buflen);
    mrp_pushnumber(L, mr_bitmap[i].w);
    mrp_pushnumber(L, mr_bitmap[i].h);
    mrp_pushnumber(L, mr_bitmap[i].type);
    return 5;
}

static int MRF_SpriteSet(mrp_State* L) {
    uint16 i = ((uint16)to_mr_tonumber(L, 1, 0));
    uint16 h = ((uint16)to_mr_tonumber(L, 2, 0));
    if (i >= SPRITEMAX) {
        mrp_pushfstring(L, "SpriteSet:index %d invalid!", i);
        mrp_error(L);
        return 0;
    }
    mr_sprite[i].h = h;
    return 0;
}

static int MRF_SpriteDraw(mrp_State* L) {
    uint16 i = ((uint16)to_mr_tonumber(L, 1, 0));
    uint16 spriteindex = ((uint16)to_mr_tonumber(L, 2, 0));
    int16 x = ((int16)to_mr_tonumber(L, 3, 0));
    int16 y = ((int16)to_mr_tonumber(L, 4, 0));
    uint16 mod = ((uint16)to_mr_tonumber(L, 5, BM_TRANSPARENT));
#ifdef MYTHROAD_DEBUG
    if (i >= SPRITEMAX) {
        mrp_pushfstring(L, "SpriteDraw:index %d invalid!", i);
        mrp_error(L);
        return 0;
    }
    if (!mr_bitmap[i].p) {
        mrp_pushfstring(L, "SpriteDraw:Sprite %d is nil!", i);
        mrp_error(L);
        return 0;
    }
#endif
    /*
   mr_drawBitmap(mr_bitmap[i].p + spriteindex*mr_bitmap[i].w*mr_sprite[i].h,
      x, y, mr_bitmap[i].w, mr_sprite[i].h, BM_TRANSPARENT, *(mr_bitmap[i].p));
    */
    _DrawBitmap(mr_bitmap[i].p + spriteindex * mr_bitmap[i].w * mr_sprite[i].h,
                x, y, mr_bitmap[i].w, mr_sprite[i].h, mod, *(mr_bitmap[i].p), 0, 0, mr_bitmap[i].w);
    return 0;
}

static int MRF_SpriteDrawEx(mrp_State* L) {
    uint16 i = ((uint16)to_mr_tonumber(L, 1, 0));
    uint16 spriteindex = ((uint16)to_mr_tonumber(L, 2, 0));
    int16 x = ((int16)to_mr_tonumber(L, 3, 0));
    int16 y = ((int16)to_mr_tonumber(L, 4, 0));
    int16 A = ((int16)to_mr_tonumber(L, 5, 0));
    int16 B = ((int16)to_mr_tonumber(L, 6, 0));
    int16 C = ((int16)to_mr_tonumber(L, 7, 0));
    int16 D = ((int16)to_mr_tonumber(L, 8, 0));
    mr_transMatrixSt Trans;
    mr_bitmapDrawSt srcbmp;
    mr_bitmapDrawSt dstbmp;

    if (i >= SPRITEMAX) {
        mrp_pushfstring(L, "SpriteDrawEx:index %d invalid!", i);
        mrp_error(L);
        return 0;
    }
    Trans.A = A;
    Trans.B = B;
    Trans.C = C;
    Trans.D = D;
    Trans.rop = BM_TRANSPARENT;

    dstbmp.w = (uint16)MR_SCREEN_W;
    dstbmp.h = (uint16)MR_SCREEN_H;
    dstbmp.x = x;
    dstbmp.y = y;
    dstbmp.p = mr_screenBuf;

    srcbmp.w = mr_bitmap[i].w;
    srcbmp.h = mr_sprite[i].h;
    srcbmp.x = 0;
    srcbmp.y = 0;
    srcbmp.p = mr_bitmap[i].p + (spriteindex & MR_SPRITE_INDEX_MASK) * mr_bitmap[i].w * mr_sprite[i].h;
    _DrawBitmapEx(&srcbmp, &dstbmp, mr_bitmap[i].w, mr_sprite[i].h, &Trans, *(mr_bitmap[i].p));

    //_DrawBitmapEx(mr_bitmap[i].p + (spriteindex & MR_SPRITE_INDEX_MASK)*mr_bitmap[i].w*mr_sprite[i].h,
    //   x, y, mr_bitmap[i].w, mr_sprite[i].h, &Trans, *(mr_bitmap[i].p));
    return 0;
}

static int MRF_TileSet(mrp_State* L) {
    uint16 i = ((uint16)to_mr_tonumber(L, 1, 0));
    int16 x = ((int16)to_mr_tonumber(L, 2, 0));
    int16 y = ((int16)to_mr_tonumber(L, 3, 0));
    uint16 w = ((uint16)to_mr_tonumber(L, 4, 0));
    uint16 h = ((uint16)to_mr_tonumber(L, 5, 0));
    uint16 tileh = ((uint16)to_mr_tonumber(L, 6, 0));
#ifdef MYTHROAD_DEBUG
    if (i >= TILEMAX) {
        mrp_pushstring(L, "TileSet:tile index out of rang!");
        mrp_error(L);
        return 0;
    }
#endif

    if (w * h * 2 != mr_tile[i].w * mr_tile[i].h * 2) {
        if (mr_map[i]) {
            MR_FREE(mr_map[i], mr_tile[i].w * mr_tile[i].h * 2);
            mr_map[i] = NULL;
        }
        if (w == 0) {
            return 0;
        }
    }

    mr_tile[i].x = x;
    mr_tile[i].y = y;
    mr_tile[i].w = w;
    mr_tile[i].h = h;
    mr_tile[i].tileh = tileh;

    if (mr_map[i] == NULL)
        mr_map[i] = MR_MALLOC(w * h * 2);
    return 0;
}

static int MRF_TileSetRect(mrp_State* L) {
    uint16 i = ((uint16)to_mr_tonumber(L, 1, 0));
    int16 x1 = ((int16)to_mr_tonumber(L, 2, 0));
    int16 y1 = ((int16)to_mr_tonumber(L, 3, 0));
    int16 x2 = ((int16)to_mr_tonumber(L, 4, 0));
    int16 y2 = ((int16)to_mr_tonumber(L, 5, 0));
#ifdef MYTHROAD_DEBUG
    if (i >= TILEMAX) {
        mrp_pushstring(L, "TileSet:tile index out of rang!");
        mrp_error(L);
        return 0;
    }
#endif

    mr_tile[i].x1 = x1;
    mr_tile[i].y1 = y1;
    mr_tile[i].x2 = x2;
    mr_tile[i].y2 = y2;

    return 0;
}

static int MRF_TileDraw(mrp_State* L) {
    uint16 i = ((uint16)to_mr_tonumber(L, 1, 0));
    int16 x = mr_tile[i].x;
    int16 y = mr_tile[i].y;
    uint16 tilew = mr_bitmap[i].w;
    uint16 tileh = mr_tile[i].tileh;
    uint16 w = mr_tile[i].w;
    uint16 h = mr_tile[i].h;
    unsigned xStart = x > 0 ? 0 : (-x) / mr_bitmap[i].w;
    unsigned xEnd = MIN(w, ((unsigned)(MR_SCREEN_W - x + mr_bitmap[i].w - 1) / mr_bitmap[i].w));
    unsigned yStart = y > 0 ? 0 : (-y) / mr_tile[i].tileh;
    unsigned yEnd = MIN(h, ((unsigned)(MR_SCREEN_H - y + mr_tile[i].tileh - 1) / mr_tile[i].tileh));
    uint16 dx, dy;

#ifdef MYTHROAD_DEBUG
    if (i >= TILEMAX) {
        mrp_pushstring(L, "TileDraw:tile index out of rang!");
        mrp_error(L);
        return 0;
    }
#endif
#ifdef MYTHROAD_DEBUG
    if (!mr_bitmap[i].p) {
        mrp_pushfstring(L, "TileDraw:Tile %d is nil!", i);
        mrp_error(L);
        return 0;
    }
#endif

    for (dy = yStart; dy < yEnd; dy++) {
        for (dx = xStart; dx < xEnd; dx++) {
            //         mr_drawBitmap(mr_bitmap[i].p + mr_map[i][mr_tile[i].w * dy + dx]*mr_bitmap[i].w*mr_tile[i].tileh,
            //            dx * mr_bitmap[i].w + x, dy * mr_tile[i].tileh + y, mr_bitmap[i].w,
            //            mr_tile[i].tileh, BM_COPY, 0);
            uint16 unTile = mr_map[i][w * dy + dx];

            if ((unTile & MR_SPRITE_INDEX_MASK) != MR_SPRITE_INDEX_MASK) {
                int16 drawX = dx * tilew + x;
                int16 drawY = dy * tileh + y;
                if ((drawX + tilew >= mr_tile[i].x1) && (drawX < mr_tile[i].x2) && (drawY + tileh >= mr_tile[i].y1) && (drawY < mr_tile[i].y2))
                    _DrawBitmap(mr_bitmap[i].p +
                                    (unTile & MR_SPRITE_INDEX_MASK) * tilew * tileh,
                                (int16)drawX,
                                (int16)drawY,
                                (uint16)tilew,
                                (uint16)tileh,
                                (uint16)((unTile & 0xfc00) +
                                         ((unTile & MR_SPRITE_TRANSPARENT) ? BM_TRANSPARENT : BM_COPY)),
                                (uint16) * (mr_bitmap[i].p), 0, 0, (uint16)tilew);
            }
        }
    }  //for (dy = yStart; dy < yEnd; dy++)
    return 0;
}

static int MRF_TileShift(mrp_State* L) {
    uint16 i = ((uint16)mrp_tonumber(L, 1));
    uint16 mode = ((uint16)mrp_tonumber(L, 2));

    int32 j;
#ifdef MYTHROAD_DEBUG
    if (i >= TILEMAX) {
        mrp_pushstring(L, "TileShift:tile index out of rang!");
        mrp_error(L);
        return 0;
    }
#endif
    switch (mode) {
        case 0:  //up
            memmove2(mr_map[i],
                     mr_map[i] + mr_tile[i].w,
                     mr_tile[i].w * (mr_tile[i].h - 1) * 2);
            break;
        case 1:  //down
            memmove2(mr_map[i] + mr_tile[i].w,
                     mr_map[i],
                     mr_tile[i].w * (mr_tile[i].h - 1) * 2);
            break;
        case 2:  //left
            for (j = 0; j < mr_tile[i].h; j++) {
                memmove2(mr_map[i] + mr_tile[i].w * j,
                         mr_map[i] + mr_tile[i].w * j + 1,
                         (mr_tile[i].w * -1) * 2);
            }
            break;
        case 3:  //right
            for (j = 0; j < mr_tile[i].h; j++) {
                memmove2(mr_map[i] + mr_tile[i].w * j + 1,
                         mr_map[i] + mr_tile[i].w * j,
                         (mr_tile[i].w * -1) * 2);
            }
            break;
    }
    return 0;
}

static int MRF_TileLoad(mrp_State* L) {
    uint16 i = ((uint16)mrp_tonumber(L, 1));
    char* filename = ((char*)mrp_tostring(L, 2));
    int filelen;

#ifdef MYTHROAD_DEBUG
    if (i >= TILEMAX) {
        mrp_pushstring(L, "TileLoad:tile index out of rang!");
        mrp_error(L);
        return 0;
    }
#endif
    if (mr_map[i]) {
        MR_FREE(mr_map[i], mr_tile[i].w * mr_tile[i].h * 2);
        mr_map[i] = NULL;
    }

    mr_map[i] = _mr_readFile(filename, &filelen, 0);

#ifdef MYTHROAD_DEBUG
    if (!mr_map[i]) {
        mrp_pushfstring(L, "TileLoad %d:cannot read \"%s\"!", i, filename);
        mrp_error(L);
        return 0;
    }
#endif

    if (mr_tile[i].w * mr_tile[i].h * 2 != filelen) {
        MR_FREE(mr_map[i], filelen);
        mrp_pushfstring(L, "TileLoad: Map file \"%s\" len err %d %d !", filename, filelen, mr_tile[i].w * mr_tile[i].h * 2);
        mr_map[i] = NULL;
        mrp_error(L);
        return 0;
    }
    return 0;
}

static int MRF_GetTile(mrp_State* L) {
    uint16 i = ((uint16)mrp_tonumber(L, 1));
    uint16 x = ((uint16)mrp_tonumber(L, 2));
    uint16 y = ((uint16)mrp_tonumber(L, 3));
#ifdef MYTHROAD_DEBUG
    if (i >= TILEMAX) {
        mrp_pushstring(L, "GetTile:tile index out of rang!");
        mrp_error(L);
        return 0;
    }
#endif
#ifdef MYTHROAD_DEBUG
    if (!mr_map[i]) {
        mrp_pushfstring(L, "GetTile %d:tile is nil!", i);
        mrp_error(L);
        return 0;
    }
    if ((y > mr_tile[i].h) || (x > mr_tile[i].w)) {
        mrp_pushfstring(L, "GetTile overflow!", i);
        mrp_error(L);
        return 0;
    }
#endif
    {
        int16 to_mr_ret = mr_map[i][mr_tile[i].w * y + x];
        to_mr_pushnumber(L, (mrp_Number)to_mr_ret);
    }
    return 1;
}

static int MRF_SetTile(mrp_State* L) {
    uint16 i = ((uint16)mrp_tonumber(L, 1));
    uint16 x = ((uint16)mrp_tonumber(L, 2));
    uint16 y = ((uint16)mrp_tonumber(L, 3));
    uint16 v = ((uint16)mrp_tonumber(L, 4));
#ifdef MYTHROAD_DEBUG
    if (i >= TILEMAX) {
        mrp_pushstring(L, "SetTile:tile index out of rang!");
        mrp_error(L);
        return 0;
    }
#endif
#ifdef MYTHROAD_DEBUG
    if (!mr_map[i]) {
        mrp_pushfstring(L, "SetTile %d:tile is nil!", i);
        mrp_error(L);
        return 0;
    }
    if ((y > mr_tile[i].h) || (x > mr_tile[i].w)) {
        mrp_pushfstring(L, "SetTile %d overflow!", i);
        mrp_error(L);
        return 0;
    }
#endif
    mr_map[i][mr_tile[i].w * y + x] = v;
    return 0;
}

static int MRF_ClearScreen(mrp_State* L) {
    int r = ((int)mrp_tonumber(L, 1));
    int g = ((int)mrp_tonumber(L, 2));
    int b = ((int)mrp_tonumber(L, 3));
    DrawRect(0, 0, (int16)MR_SCREEN_W, (int16)MR_SCREEN_H, (uint8)r, (uint8)g, (uint8)b);
    return 0;
}

static int MRF_EffSetCon(mrp_State* L) {
    int16 x = ((int16)to_mr_tonumber(L, 1, 0));
    int16 y = ((int16)to_mr_tonumber(L, 2, 0));
    int16 w = ((int16)to_mr_tonumber(L, 3, 0));
    int16 h = ((int16)to_mr_tonumber(L, 4, 0));
    int16 perr = ((int16)to_mr_tonumber(L, 5, 0));
    int16 perg = ((int16)to_mr_tonumber(L, 6, 0));
    int16 perb = ((int16)to_mr_tonumber(L, 7, 0));
    return _mr_EffSetCon(x, y, w, h, perr, perg, perb);
}

static int MRF_GetRand(mrp_State* L) {
    int32 n = ((int32)mrp_tonumber(L, 1));
    {
        int32 to_mr_ret = (int32)mr_rand() % n;
        to_mr_pushnumber(L, (mrp_Number)to_mr_ret);
    }
    return 1;
}

static int MRF_mod(mrp_State* L) {
    int n = ((int)mrp_tonumber(L, 1));
    int m = ((int)mrp_tonumber(L, 2));
    {
        int to_mr_ret = (int)n % m;
        mrp_pushnumber(L, (mrp_Number)to_mr_ret);
    }
    return 1;
}

static int MRF_and(mrp_State* L) {
    int n = ((int)mrp_tonumber(L, 1));
    int m = ((int)mrp_tonumber(L, 2));
    {
        int to_mr_ret = (int)n & m;
        mrp_pushnumber(L, (mrp_Number)to_mr_ret);
    }
    return 1;
}

static int MRF_or(mrp_State* L) {
    int n = ((int)mrp_tonumber(L, 1));
    int m = ((int)mrp_tonumber(L, 2));
    {
        int to_mr_ret = (int)n | m;
        mrp_pushnumber(L, (mrp_Number)to_mr_ret);
    }
    return 1;
}

static int MRF_not(mrp_State* L) {
    int n = ((int)mrp_tonumber(L, 1));
    {
        int to_mr_ret = (int)!n;
        mrp_pushnumber(L, (mrp_Number)to_mr_ret);
    }
    return 1;
}

static int MRF_xor(mrp_State* L) {
    int n = ((int)mrp_tonumber(L, 1));
    int m = ((int)mrp_tonumber(L, 2));
    {
        int to_mr_ret = (int)n ^ m;
        mrp_pushnumber(L, (mrp_Number)to_mr_ret);
    }
    return 1;
}

static void SoundSet(mrp_State* L, uint16 i, char* filename, int32 type) {
    void* filebuf;
    int filelen;

    if (i >= SOUNDMAX) {
        mrp_pushfstring(L, "SoundSet :index %d invalid!", i);
        mrp_error(L);
    }

    if (mr_sound[i].p) {
        MR_FREE(mr_sound[i].p, mr_sound[i].buflen);
        mr_sound[i].p = NULL;
    }

    if (*filename == '*') {
        return;
    }
    //MRDBGPRINTF("SoundSet:1 %s", filename);
    filebuf = _mr_readFile(filename, &filelen, 0);
    if (!filebuf) {
        mrp_pushfstring(L, "SoundSet %d:cannot read \"%s\"!", i, filename);
        mrp_error(L);
        return;
    }

    mr_sound[i].p = filebuf;
    mr_sound[i].buflen = filelen;
    mr_sound[i].type = type;
    return;
}

static int MRF_SoundSet(mrp_State* L) {
    uint16 i = ((uint16)to_mr_tonumber(L, 1, 0));
    char* filename = ((char*)to_mr_tostring(L, 2, 0));
    int32 type = ((int32)to_mr_tonumber(L, 3, MR_SOUND_WAV));
    SoundSet(L, i, filename, type);
    return 0;
}

static int MRF_SoundPlay(mrp_State* L) {
    uint16 i = ((uint16)to_mr_tonumber(L, 1, 0));
    int32 loop = (int32)to_mr_toboolean(L, 2, FALSE);
    if (i >= SOUNDMAX) {
        mrp_pushfstring(L, "SoundPlay:index %d invalid!", i);
        mrp_error(L);
        return 0;
    }
    if (!(mr_state == MR_STATE_RUN) || (!mr_soundOn)) {
        return 0;
    }
    mr_playSound(mr_sound[i].type, mr_sound[i].p, mr_sound[i].buflen, loop);
    return 0;
}

static int MRF_SoundStop(mrp_State* L) {
    uint16 i = ((uint16)to_mr_tonumber(L, 1, 0));
    if (i >= SOUNDMAX) {
        mrp_pushfstring(L, "SoundStop:index %d invalid!", i);
        mrp_error(L);
        return 0;
    }
    mr_stopSound(mr_sound[i].type);
    return 0;
}

static int MRF_BgMusicSet(mrp_State* L) {
    char* filename = ((char*)to_mr_tostring(L, 1, 0));
    int32 type = ((int32)to_mr_tonumber(L, 2, MR_SOUND_MIDI));
    SoundSet(L, 0, filename, type);
    return 0;
}

static int MRF_BgMusicStart(mrp_State* L) {
    //char* filename = ((char*)  to_mr_tostring(L,1,0));
    //int32 loop = (int32)to_mr_tonumber(L, 1, 1);
    int32 loop = (int32)to_mr_toboolean(L, 1, TRUE);
    if (!(mr_state == MR_STATE_RUN) || (!mr_soundOn)) {
        return 0;
    }
    mr_playSound(mr_sound[0].type, mr_sound[0].p, mr_sound[0].buflen, loop);
    return 0;
}

static int MRF_BgMusicStop(mrp_State* L) {
    mr_stopSound(mr_sound[0].type);
    return 0;
}

static int MRF_Exit(mrp_State* L) {
    /*这里调用内存释放，内存的内容不能被
   清空，不然虚拟机会崩溃。如果内存会被
   清空，使用时钟延时释放内存。*/
    //mr_mem_free(LG_mem_base, LG_mem_len);

    //bi = bi|MR_FLAGS_RI;
    if (old_pack_filename[0]) {
        MEMSET(pack_filename, 0, sizeof(pack_filename));
        STRNCPY(pack_filename, old_pack_filename, sizeof(pack_filename) - 1);
        MEMSET(start_filename, 0, sizeof(start_filename));
        STRNCPY(start_filename, old_start_filename, sizeof(start_filename) - 1);

        mr_timer_p = (void*)"restart";
        MR_TIME_START(100);
        mr_state = MR_STATE_RESTART;
    } else {
        mr_exit();
        mr_state = MR_STATE_STOP;

        //下面的两句话在1943中曾被去掉，但目前已经不知道
        //这两句话为何被去掉，可能和C代码的调用有关
        //现在先恢复这两句话
        //这两句话用于移植层无需担心mr_stop的调用时间；
        mrp_pushstring(L, "Exiting...");
        mrp_error(L);
        //到这里为止
    }

    return 0;
}

static int bufwriter(mrp_State* L, const void* p, size_t sz, void* ud) {
    SaveF* wi = (SaveF*)ud;

    if (mr_write(wi->f, (void*)p, (uint32)sz) < 0) {
        mrp_pushstring(L, "SaveTable:mr_write failed");
        mr_close(wi->f);
        mrp_error(L);
        return 0;
    }
    return 0;
}

static int SaveTable(mrp_State* L) {
    SaveF wi;
    char* filename = ((char*)to_mr_tostring(L, 3, 0));

    mrp_settop(L, 2);
    /* perms? rootobj? */
    mr_L_checktype(L, 1, MRP_TTABLE);
    /* perms rootobj? */
    //mr_L_checktype(L, 1, MRP_TTABLE);
    /* perms rootobj */

    wi.f = mr_open(filename, MR_FILE_WRONLY | MR_FILE_CREATE);
    if (wi.f == 0) {
        //mrp_pushfstring(L, "SaveTable:mr_open \"%s\" failed",filename);
        //mrp_error(L);
        MRDBGPRINTF("SaveTable:mr_open \"%s\" failed", filename);
        return 0;
    }
    mr_store_persist(L, bufwriter, &wi);
    mrp_settop(L, 0);
    mr_close(wi.f);
    mrp_pushnumber(L, MR_SUCCESS);
    return 1;
}

static const char* bufreader(mrp_State* L, void* ud, size_t* sz) {
    LoadF* lf = (LoadF*)ud;
    (void)L;
    *sz = mr_read(lf->f, lf->buff, MRP_L_BUFFERSIZE);
    return (*sz > 0) ? lf->buff : NULL;
}

static int LoadTable(mrp_State* L) {
    LoadF lf;
    char* filename = ((char*)to_mr_tostring(L, 2, 0));

    mrp_settop(L, 2);
    mrp_pop(L, 1);
    //mr_L_checktype(L, 1, MRP_TTABLE);
    /* perms rootobj */
    mr_L_checktype(L, 1, MRP_TTABLE);

    lf.f = mr_open(filename, MR_FILE_RDONLY);
    if (lf.f == 0) {
        MRDBGPRINTF("LoadTable:mr_open \"%s\" err", filename);
        mrp_settop(L, 0);
        mrp_settop(L, 1);
        return 1;
    }

    mr_store_unpersist(L, bufreader, &lf);

    mr_close(lf.f);
    return 1;
}

static void setfield(mrp_State* L, const char* key, int value) {
    mrp_pushstring(L, key);
    mrp_pushnumber(L, value);
    mrp_rawset(L, -3);
}

static void setstrfield(mrp_State* L, const char* key, const char* value) {
    mrp_pushstring(L, key);
    mrp_pushstring(L, value);
    mrp_rawset(L, -3);
}

static void setlstrfield(mrp_State* L, const char* key, const char* value, int len) {
    mrp_pushstring(L, key);
    mrp_pushlstring(L, value, len);
    mrp_rawset(L, -3);
}

int _mr_GetSysInfo(mrp_State* L) {
    int width, height;
    mr_userinfo info;
    uint16 font = (uint16)mr_L_optlong(L, 1, MR_FONT_MEDIUM);

    mrp_newtable(L);
    setfield(L, "vmver", MR_VERSION);
#ifdef COMPATIBILITY01
    setfield(L, "ScreenW", MR_SCREEN_W);
    setfield(L, "ScreenH", MR_SCREEN_H);
#endif
    setfield(L, "scrw", MR_SCREEN_W);
    setfield(L, "scrh", MR_SCREEN_H);
    mr_getCharBitmap(0x70b9, font, &width, &height);
#ifdef COMPATIBILITY01
    setfield(L, "ChineseWidth", width);
    setfield(L, "ChineseHigh", height);
#endif
    setfield(L, "chw", width);
    setfield(L, "chh", height);

    mr_getCharBitmap(0x0032, font, &width, &height);
#ifdef COMPATIBILITY01
    setfield(L, "EnglishWidth", width);
    setfield(L, "EnglishHigh", height);
#endif
    setfield(L, "ascw", width);
    setfield(L, "asch", height);

#ifdef COMPATIBILITY01
    setstrfield(L, "PackName", pack_filename);
#endif
    setstrfield(L, "packname", pack_filename);

    if (mr_getUserInfo(&info) == MR_SUCCESS) {
        setstrfield(L, "hsman", info.manufactory);
        setstrfield(L, "hstype", info.type);
        setlstrfield(L, "IMEI", (const char*)info.IMEI, 16);
        setlstrfield(L, "IMSI", (const char*)info.IMSI, 16);
        setfield(L, "hsver", info.ver);

    } else {
        setstrfield(L, "hsman", "none");
        setstrfield(L, "hstype", "none");
        setstrfield(L, "IMEI", "00");
        setstrfield(L, "IMSI", "00");
        setfield(L, "hsver", 0);
    }
    return 1;
}

int _mr_GetDatetime(mrp_State* L) {
    mr_datetime datetime;
    if (MR_SUCCESS == mr_getDatetime(&datetime)) {
        mrp_newtable(L);
        setfield(L, "year", datetime.year);
        setfield(L, "mon", datetime.month);
        setfield(L, "day", datetime.day);
        setfield(L, "hour", datetime.hour);
        setfield(L, "min", datetime.minute);
        setfield(L, "sec", datetime.second);
        return 1;
    } else {
        return 0;
    }
}

static int Call(mrp_State* L) {
    char* number = ((char*)to_mr_tostring(L, 1, 0));
    mrp_settop(L, 1);
    mr_call(number);
    return 0;
}

static int LoadPack(mrp_State* L) {
    char* packname = ((char*)to_mr_tostring(L, 1, 0));

#ifdef MR_AUTHORIZATION
    char input[24];
    int32 f;
    int nTmp;

    //这里还要判断是否是ROM或RAM中的MRP文件，若是则不用进行鉴权。
    if (bi & MR_FLAGS_AI) {
        f = mr_open(packname, MR_FILE_RDONLY);
        if (f == 0) {
            MRDBGPRINTF("\"%s\" is unauthorized", packname);
            return 0;
        }

        nTmp = mr_seek(f, 52, MR_SEEK_SET);
        if (nTmp < 0) {
            mr_close(f);
            _mr_readFileShowInfo("unauthorized", 0);
            return 0;
        }

        nTmp = mr_read(f, input, sizeof(input));
        if (nTmp != sizeof(input)) {
            mr_close(f);
            _mr_readFileShowInfo("unauthorized", 1);
            return 0;
        }

        mr_close(f);
        if (_mr_isMr(input) == MR_SUCCESS) {
            mrp_settop(L, 1);
            mrp_pushstring(L, pack_filename);
            STRCPY(pack_filename, packname);
        } else {
            _mr_readFileShowInfo("unauthorized", 2);
            return 0;
        }
    } else {
        mrp_settop(L, 1);
        mrp_pushstring(L, pack_filename);
        STRCPY(pack_filename, packname);
    }
#else
    mrp_settop(L, 1);
    mrp_pushstring(L, pack_filename);
    STRCPY(pack_filename, packname);
#endif

    //   return 0;
    return 1;
}

/*
返回值
MR_SUCCESS  0    //成功
MR_FAILED   -1    //失败
MR_IGNORE  1     //未准备好
*/
static int SendSms(mrp_State* L) {
    char* number = ((char*)to_mr_tostring(L, 1, "0"));
    char* content = ((char*)to_mr_tostring(L, 2, "0"));
    int32 flag = ((int32)to_mr_tonumber(L, 3, MR_ENCODE_ASCII));
    mrp_settop(L, 2);

    mrp_pushnumber(L, mr_sendSms(number, content, flag));
    return 1;
}

/*取得网络ID，0 移动，1 联通*/
static int GetNetworkID(mrp_State* L) {
    int id = mr_getNetworkID();
    mrp_pushnumber(L, id);
    return 1;
}

static int ConnectWAP(mrp_State* L) {
    char* wap = ((char*)to_mr_tostring(L, 1, 0));

    mrp_settop(L, 1);
    mr_connectWAP(wap);

    return 0;
}

static int MRF_RunFile(mrp_State* L) {
    char* filename = ((char*)to_mr_tostring(L, 1, 0));
    char* runfilename = ((char*)to_mr_tostring(L, 2, 0));
    char* runfileparameter = ((char*)to_mr_tostring(L, 3, 0));

    memset2(pack_filename, 0, sizeof(pack_filename));
    //strcpy(pack_filename,"i/");//all installed appliation place under root_dir/i/
    //strncat(pack_filename,filename, sizeof(pack_filename) - 3);
    strncpy2(pack_filename, filename, sizeof(pack_filename) - 1);
    memset2(start_filename, 0, sizeof(start_filename));
    strncpy2(start_filename, runfilename, sizeof(start_filename) - 1);

    memset2(start_fileparameter, 0, sizeof(start_fileparameter));
    if (runfileparameter) {
        strncpy2(start_fileparameter, runfileparameter, sizeof(start_fileparameter) - 1);
    }

    mr_timer_p = (void*)"restart";
    MR_TIME_START(100);
    //mr_timer_state = MR_TIMER_STATE_RUNNING;
    mr_state = MR_STATE_RESTART;
    return 0;
}

int mr_Gb2312toUnicode(mrp_State* L) {
    char* text = ((char*)to_mr_tostring(L, 1, 0));

    int TextSize;
    uint16* tempBuf;
    // int tempret=0;
    //tempBuf = c2u((const char*)text, &tempret, &TextSize);
    tempBuf = c2u((const char*)text, NULL, &TextSize);
    if (!tempBuf) {
        mrp_pushfstring(L, "Gb2312toUnicode text[0]=%d: err!", *text);
        mrp_error(L);
        return 0;
    }

    mrp_pushlstring(L, (const char*)tempBuf, TextSize);
    MR_FREE((void*)tempBuf, TextSize);

    return 1;
}

static int MRF_plat(mrp_State* L) {
    int code = ((int)to_mr_tonumber(L, 1, 0));
    int param = ((int)to_mr_tonumber(L, 2, 0));
    mrp_pushnumber(L, (mrp_Number)mr_plat(code, param));
    return 1;
}

static int MRF_platEx(mrp_State* L) {
    int32 input_len, output_len, ret;
    int code = ((int)to_mr_tonumber(L, 1, 0));
    uint8* input = (uint8*)mr_L_checklstring(L, 2, (size_t*)&input_len);
    uint8* output = NULL;
    MR_PLAT_EX_CB cb = NULL;
    output_len = 0;

    ret = mr_platEx(code, input, input_len, &output, &output_len, &cb);

    if (output && output_len) {
        mrp_pushlstring(L, (const char*)output, output_len);
    } else {
        mrp_pushstring(L, "");
    }

    if (cb) {
        cb(output, output_len);
    }
    mrp_pushnumber(L, ret);
    return 2;
}

static int MRF_initNet(mrp_State* L) {
    const char* mode = (const char*)to_mr_tostring(L, 1, "cmnet");
    return mropen_socket(L, mode);
}

static int MRF_closeNet(mrp_State* L) {
    int32 ret;
    ret = mr_closeNetwork();
    mrp_pushstring(L, "socket");
    mrp_rawget(L, MRP_GLOBALSINDEX);

    //add this for nil socket obj protect.
    if (!mrp_istable(L, -1)) {
        mrp_pop(L, 1);
        MRDBGPRINTF("Socket IDLE!");
        to_mr_pushnumber(L, (mrp_Number)ret);
        return 1;
    }
    //end

    mrp_pushstring(L, "state");
    mrp_pushnumber(L, MRSOCK_CLOSED);
    mrp_rawset(L, -3);
    mrp_pop(L, 1);
    to_mr_pushnumber(L, (mrp_Number)ret);
    return 1;
}

int _mr_TestCom(mrp_State* L, int input0, int input1) {
    int ret = 0;

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
        case 402:
#ifdef MR_SOCKET_SUPPORT
        {
            const char* mode;
            if (mrp_isnumber(L, 2)) {
                mode = "cmnet";
            } else {
                mode = (const char*)to_mr_tostring(L, 2, "cmnet");
            }
            return mropen_socket(L, mode);
            //mrp_settop(L, 0);  /* discard any results */
        }
#endif
        break;
        case 403:
            mrp_setgcthreshold(L, input1);
            break;
        case 404:
            ret = mr_newSIMInd((int16)input1, NULL);
            break;
        case 405:
            ret = mr_closeNetwork();
            mrp_pushstring(L, "socket");
            mrp_rawget(L, MRP_GLOBALSINDEX); /* get traceback function */

            //add this for nil socket obj protect.
            if (!mrp_istable(L, -1)) {
                mrp_pop(L, 1);
                MRDBGPRINTF("Socket IDLE!");
                break;
            }
            //end

            mrp_pushstring(L, "state");
            mrp_pushnumber(L, MRSOCK_CLOSED);
            mrp_rawset(L, -3);
            mrp_pop(L, 1);
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
        case 501:
#ifdef MR_SM_SURPORT
        {
            int len = ((int)to_mr_tonumber(L, 3, 0));
            const char* buf = MR_MALLOC(len);
            if (buf) {
                _mr_smsGetBytes(input1, (char*)buf, len);
                mrp_pushlstring(L, (const char*)buf, len);
                MR_FREE((void*)buf, len);
            }
            return 1;
        }
#endif
        break;
        case 502:
#ifdef MR_SM_SURPORT
        {
            int len = ((int)to_mr_tonumber(L, 3, 0));
            const char* buf = mrp_tostring(L, 4);
            if (buf) {
                ret = _mr_smsSetBytes(input1, (char*)buf, len);
            }
        }
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

    if (L) {
        to_mr_pushnumber(L, (mrp_Number)ret);
        return 1;
    } else {
        return 0;
    }
}

static int MRF_TestCom(mrp_State* L) {
    int input0 = ((int)to_mr_tonumber(L, 1, 0));
    int input1 = ((int)to_mr_tonumber(L, 2, 0));
    return _mr_TestCom(L, input0, input1);
}

int _mr_pcall(int nargs, int nresults) {
    int status;

#ifdef MR_TRACE
    int errfunc = 0;
    mrp_getglobal(vm_state, "_trace");
    if (mrp_isfunction(vm_state, -1)) {
        mrp_insert(vm_state, -5);
        errfunc = -5;
    } else {                  /* no trace function */
        mrp_pop(vm_state, 1); /* remove _trace */
        errfunc = 0;
    }
    status = mrp_pcall(vm_state, nargs, nresults, errfunc); /* call main */
    if (errfunc) {
        if (status != 0) {
            mr_state = MR_STATE_ERROR;
            _mr_showErrorInfo(mrp_tostring(vm_state, -1));
            mrp_pop(vm_state, 1); /* remove error message*/
        }
        mrp_pop(vm_state, 1); /* remove errfunc*/
    } else if (status != 0) {
        mr_state = MR_STATE_ERROR;
        _mr_showErrorInfo(mrp_tostring(vm_state, -1));
        mrp_pop(vm_state, 1); /* remove error message*/
    }
#else

    status = mrp_pcall(vm_state, nargs, nresults, 0); /* call main */
    //MRDBGPRINTF("mr_read_asyn_cb 4");
    if (status != 0) {
#ifndef MR_APP_IGNORE_EXCEPTION
        if (mr_state == MR_STATE_STOP) {
            if (mr_exit_cb) {
                mr_stop();
                mr_exit_cb(mr_exit_cb_data);
                mr_exit_cb = NULL;
            } else {
                mr_stop();
            }
            //mr_state = MR_STATE_IDLE;
        } else {
            if (!(bi & MR_FLAGS_EI) && (MR_SCREEN_MAX_W * MR_SCREEN_H > 1024)) {  //添加对没有屏幕缓存的保护
                mr_state = MR_STATE_ERROR;

                //1948 add exception set
                if (mr_exception_str) {
                    _mr_showErrorInfo(mr_exception_str);
                    mr_exception_str = NULL;
                } else {
                    _mr_showErrorInfo(mrp_tostring(vm_state, -1));
                }
                //1948 add exception set

                mrp_pop(vm_state, 1); /* remove error message*/
            } else {
                old_pack_filename[0] = 0;
                mr_state = MR_STATE_ERROR;
                //MRDBGPRINTF(mrp_tostring(vm_state, -1));
                mr_exit();
            }
        }
#else
        MRDBGPRINTF(mrp_tostring(vm_state, -1));
        mrp_pop(vm_state, 1); /* remove error message*/
#endif
    }

#endif
    return 0;
}

#ifdef MR_SOCKET_SUPPORT

static int32 mr_get_host_cb(int32 ip) {
    if (!((mr_state == MR_STATE_RUN) || (mr_state == MR_STATE_PAUSE))) {
        MRDBGPRINTF("VM is IDLE!");
        return MR_FAILED;
    }
    mrp_getglobal(vm_state, (char*)"socket");
    mrp_pushstring(vm_state, "ip");
    mrp_pushnumber(vm_state, ip);
    mrp_rawset(vm_state, -3);
    mrp_pop(vm_state, 1); /* remove socket */
    return MR_SUCCESS;
}

#endif

int32 _mr_getHost(mrp_State* L, char* host) {
    int32 ret;
    ret = mythroad_getHostByName(host, mr_get_host_cb);
    mrp_getglobal(L, (char*)"socket");
    mrp_pushstring(L, "ip");
    mrp_pushnumber(L, ret);
    mrp_rawset(L, -3);
    mrp_pop(L, 1); /* remove socket */
    return ret;
}

int32 _mr_c_function_new(MR_C_FUNCTION f, int32 len) {
    if (mr_c_function_P) {
        MR_FREE(mr_c_function_P, mr_c_function_P_len);
    }
    mr_c_function_P = MR_MALLOC(len);
    if (!mr_c_function_P) {
        mrp_pushfstring(vm_state, "c_function:No memory!");
        mrp_error(vm_state);
        return MR_FAILED;
    }
    mr_c_function_P_len = len;
    MEMSET(mr_c_function_P, 0, mr_c_function_P_len);
    mr_c_function = f;
    mr_printf("_mr_c_function_new(%p, %d)  mr_c_function_P:%p", f, len, mr_c_function_P);
    if (mr_c_function_fix_p) {
        *((void**)(mr_c_function_fix_p) + 1) = mr_c_function_P;
    } else {
        *((void**)(mr_load_c_function)-1) = mr_c_function_P;
    }
    return MR_SUCCESS;
}

// _strCom(int,str)
int _mr_TestCom1(mrp_State* L, int input0, char* input1, int32 len) {
    int ret = 0;

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
            uint8* start_filename = ((uint8*)mr_L_optstring(L, 3, MR_START_FILE));
            MEMSET(old_pack_filename, 0, sizeof(old_pack_filename));
            if (input1) {
                STRNCPY(old_pack_filename, input1, sizeof(old_pack_filename) - 1);
            }
            MEMSET(old_start_filename, 0, sizeof(old_start_filename));
            STRNCPY(old_start_filename, start_filename, sizeof(old_start_filename) - 1);
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

        case 9:
            mr_cacheSync((void*)((uint32)(input1) & (~0x0000001F)), ((len + 0x0000001F * 3) & (~0x0000001F)));
            return 0;

        case 100:
#ifdef MR_SOCKET_SUPPORT
            ret = _mr_getHost(L, input1);
#endif
            break;
        case 200:
            mr_updcrc(NULL, 0); /* initialize crc */
            mr_updcrc((unsigned char*)input1, len);
            ret = mr_updcrc((unsigned char*)input1, 0);
            break;
        case 300: {
            uint32 unzip_len;
            mr_gzInBuf = (uint8*)input1;
            LG_gzoutcnt = 0;
            LG_gzinptr = 0;

            ret = mr_get_method(len);
            if (ret < 0) {
                mrp_pushlstring(L, input1, len);
                return 1;
            }

#ifdef MR_PKZIP_MAGIC
            if (mr_zipType == PACKED) {
                unzip_len = LG(mr_gzInBuf + LOCLEN);
                mr_gzOutBuf = MR_MALLOC(unzip_len);
            } else {
                //unzip_len  = *(uint32*)(input1 + len - 4);
                MEMCPY(&unzip_len, (input1 + len - 4), 4);
                //MRDBGPRINTF("unzip_len1 = %d", unzip_len);

                mr_gzOutBuf = MR_MALLOC(unzip_len);
            }
#else
            //unzip_len  = *(uint32*)(input1 + len - 4);
            MEMCPY(&unzip_len, (input1 + len - 4), 4);
            //MRDBGPRINTF("unzip_len1 = %d", unzip_len);

            mr_gzOutBuf = MR_MALLOC(unzip_len);
#endif

            if (mr_gzOutBuf == NULL) {
                //MR_FREE(mr_gzInBuf, oldlen);
                //MR_FREE(mr_gzOutBuf, ret);
                MRDBGPRINTF("unzip  Not memory unzip!");
                return 0;
            }
            if (mr_unzip() != 0) {
                MR_FREE(mr_gzOutBuf, unzip_len);
                MRDBGPRINTF("unzip:  Unzip err1!");
                return 0;
            }

            mrp_pushlstring(L, (const char*)mr_gzOutBuf, unzip_len);
            MR_FREE(mr_gzOutBuf, unzip_len);
            return 1;

            break;
        }
        case 500: {
            md5_state_t state;
            md5_byte_t digest[16];

            mr_md5_init(&state);
            mr_md5_append(&state, (const md5_byte_t*)input1, len);
            mr_md5_finish(&state, digest);
            mrp_pushlstring(L, (const char*)digest, 16);
            return 1;
        } break;
        case 501: {
            int32 outlen = len * 4 / 3 + 8;
            uint8* buf = MR_MALLOC(outlen);
            if (!buf) {
                return 0;
            }
            ret = _mr_encode((uint8*)input1, (uint32)len, (uint8*)buf);
            if (ret == MR_FAILED) {
                MR_FREE(buf, outlen);
                return 0;
            }
            mrp_pushlstring(L, (const char*)buf, ret);
            MR_FREE(buf, outlen);
            return 1;
        } break;
        case 502: {
            uint8* buf = MR_MALLOC(len);
            if (!buf) {
                return 0;
            }
            ret = _mr_decode((uint8*)input1, (uint32)len, (uint8*)buf);
            if (ret == MR_FAILED) {
                MR_FREE(buf, len);
                return 0;
            }
            mrp_pushlstring(L, (const char*)buf, ret);
            MR_FREE(buf, len);
            return 1;
        } break;
        case 600: {
            char* mr_m0_file;
            if (input1[0] == '*') { /*m0 file?*/
                int32 index = input1[1] - 0x41;
                if ((index >= 0) && (index < (sizeof(mr_m0_files) / sizeof(const unsigned char*)))) {
                    mr_m0_file = (char*)mr_m0_files[index];  //这里定义文件名为*A即是第一个m0文件 *B是第二个.........
                } else {
                    mr_m0_file = NULL;
                }
            } else {
                mr_m0_file = mr_ram_file;
            }

            if (mr_m0_file) {
                int32 offset = ((int32)to_mr_tonumber(L, 3, 0));
                int32 buflen = ((int32)to_mr_tonumber(L, 4, 0));
                if ((buflen == -1) && (input1[0] == '$')) {
                    buflen = mr_ram_file_len;
                }
                mrp_pushlstring(L, (const char*)mr_m0_file + offset, buflen);
                return 1;
            } else {
                return 0;
            }
        } break;

        case 601: {
            char* filebuf = _mr_readFile((const char*)input1, &ret, 0);
            if (filebuf) {
                mrp_pushlstring(L, filebuf, ret);
                MR_FREE(filebuf, ret);
            } else {
                mrp_pushnil(L);
            }
            return 1;
        } break;
        case 602: {
            if (_mr_readFile((const char*)input1, &ret, 1) == NULL) {
                mrp_pushnil(L);
            } else {
                mrp_pushnumber(L, MR_SUCCESS);
            }
            return 1;
        } break;
        case 603: {
            char* filebuf;
            filebuf = _mr_readFile((const char*)input1, &ret, 2);
            if (filebuf) {
                mrp_pushnumber(L, (mrp_Number)filebuf);
                mrp_pushnumber(L, (mrp_Number)ret);
                return 2;
            } else {
                mrp_pushnil(L);
                return 1;
            }
        } break;
        case 700: {
            int type = ((int)to_mr_tonumber(L, 3, 0));
            ret = mr_newSIMInd(type, (uint8*)input1);
            break;
        }
        case 701: {
            uint8* pNum = ((uint8*)mrp_tostring(L, 3));
            int32 type = ((int32)mr_L_optnumber(L, 4, MR_ENCODE_ASCII));
            ret = mr_smsIndiaction((uint8*)input1, len, pNum, type);
            break;
        }
        case 800: {
            int code = ((int)mr_L_optint(L, 3, 0));
            mr_load_c_function = (MR_LOAD_C_FUNCTION)(input1 + 8);
            *((void**)(input1)) = (void*)_mr_c_function_table;
            mr_cacheSync((void*)((uint32)(input1) & (~0x0000001F)), ((len + 0x0000001F * 3) & (~0x0000001F)));

            MRDBGPRINTF("--- ext: @%p", input1);
            fixR9_saveMythroad();
            ret = mr_load_c_function(code);
            mrp_pushnumber(L, ret);
            MRDBGPRINTF("--- r9: mr_c_function_P.start_of_ER_RW = @%p", mr_c_function_P->start_of_ER_RW);
            return 1;
        } break;
        case 801: {  // 发送事件给ext
            int32 output_len, ret;
            int code = ((int)to_mr_tonumber(L, 3, 0));
            // int32 input_len;
            // uint8* input = (uint8*)mr_L_checklstring(L,4,(size_t*)&input_len);
            uint8* output = NULL;
            output_len = 0;

            // mr_printf("before mr_c_function------r9:%p  r10:%p code:%d %p---",  getR9(),getR10(), code, input1);
            fixR9_saveMythroad();
            // mr_printf("801 mr_c_function");
            ret = mr_c_function(mr_c_function_P, code, (uint8*)input1, len, (uint8**)&output, &output_len);
            // mr_printf("after mr_c_function------r9:%p r10:%p---",  getR9(),getR10());

            if (output && output_len) {
                mrp_pushlstring(L, (const char*)output, output_len);
            } else {
                mrp_pushstring(L, "");
            }
            mrp_pushnumber(L, ret);
            return 2;
        } break;
        case 802: {
            int32 ret;
            int code = ((int)mr_L_optint(L, 3, 0));
            mr_c_function_fix_p = ((int32*)mr_L_optint(L, 4, 0));
            mr_load_c_function = (MR_LOAD_C_FUNCTION)(input1 + 8);
            *((void**)(mr_c_function_fix_p)) = (void*)_mr_c_function_table;
            mr_cacheSync((void*)((uint32)(input1) & (~0x0000001F)), ((len + 0x0000001F * 3) & (~0x0000001F)));
            fixR9_saveMythroad();
            // mr_printf("802 mr_load_c_function");
            ret = mr_load_c_function(code);
            mrp_pushnumber(L, ret);
            return 1;
        } break;
        case 900:
            ret = mr_platEx(200001, (uint8*)_mr_c_port_table, sizeof(_mr_c_port_table), NULL, NULL, NULL);
            break;
    }

    if (L) {
        to_mr_pushnumber(L, (mrp_Number)ret);
        return 1;
    } else {
        return 0;
    }
}

static int TestCom1(mrp_State* L) {
    int32 len = 0;
    int input0 = ((int)to_mr_tonumber(L, 1, 0));
    char* input1 = ((char*)mr_L_checklstring(L, 2, (size_t*)&len));
    return _mr_TestCom1(L, input0, input1, len);
}

static mr_L_reg phonelib[5];

static int32 _mr_intra_start(char* appExName, const char* entry) {
    int i, ret;

    if (_mr_mem_init() != MR_SUCCESS) {
        return MR_FAILED;
    }
    MRDBGPRINTF("Total memory:%d", LG_mem_len);
    dsm_prepare();

    mr_event_function = NULL;
    mr_timer_function = NULL;
    mr_stop_function = NULL;
    mr_pauseApp_function = NULL;
    mr_resumeApp_function = NULL;
    mr_ram_file = NULL;
    mr_c_function_P = NULL;
    mr_c_function_P_len = 0;
    mr_c_function_fix_p = NULL;
    mr_exception_str = NULL;

#ifdef MR_SECOND_BUF
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
#else
    mr_screenBuf = (uint16*)MR_MALLOC(MR_SCREEN_MAX_W * MR_SCREEN_H * MR_SCREEN_DEEP);
    mr_bitmap[BITMAPMAX].type = MR_SCREEN_FIRST_BUF;
    mr_bitmap[BITMAPMAX].buflen = MR_SCREEN_MAX_W * MR_SCREEN_H * MR_SCREEN_DEEP;
#endif

    mr_bitmap[BITMAPMAX].p = mr_screenBuf;
    mr_bitmap[BITMAPMAX].h = mr_screen_h;
    mr_bitmap[BITMAPMAX].w = mr_screen_w;

    LUADBGPRINTF("mr_intra_start entry");
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

    vm_state = mrp_open();
    if (!vm_state) {
        return MR_FAILED;
    }
    LUADBGPRINTF("mr init ok");
    mrp_open_base(vm_state);
    mrp_open_string(vm_state);
    mrp_open_table(vm_state);
    mrp_open_file(vm_state);

#ifdef COMPATIBILITY01
    mr_store_open(vm_state);
    //to_mr_mythroad_open(vm_state);
    mrp_register(vm_state, "SaveTable", SaveTable);
    mrp_register(vm_state, "LoadTable", LoadTable);
    mrp_register(vm_state, "GetSysInfo", _mr_GetSysInfo);
    mrp_register(vm_state, "GetDatetime", _mr_GetDatetime);

    mrp_register(vm_state, "Call", Call);
    mrp_register(vm_state, "SendSms", SendSms);
    mrp_register(vm_state, "GetNetworkID", GetNetworkID);
    mrp_register(vm_state, "ConnectWAP", ConnectWAP);

    mrp_register(vm_state, "LoadPack", LoadPack);
    mrp_register(vm_state, "RunFile", MRF_RunFile);
    mrp_register(vm_state, "c2u", mr_Gb2312toUnicode);

    mrp_register(vm_state, "GetRand", MRF_GetRand);
    mrp_register(vm_state, "mod", MRF_mod);

    mrp_register(vm_state, "DrawText", MRF_DrawText);
    mrp_register(vm_state, "DrawRect", MRF_DrawRect);
    mrp_register(vm_state, "DrawLine", MRF_DrawLine);
    mrp_register(vm_state, "DrawPoint", MRF_DrawPoint);

    mrp_register(vm_state, "BgMusicSet", MRF_BgMusicSet);
    mrp_register(vm_state, "BgMusicStart", MRF_BgMusicStart);
    mrp_register(vm_state, "BgMusicStop", MRF_BgMusicStop);

    mrp_register(vm_state, "SoundSet", MRF_SoundSet);
    mrp_register(vm_state, "SoundPlay", MRF_SoundPlay);
    mrp_register(vm_state, "SoundStop", MRF_SoundStop);

    mrp_register(vm_state, "BitmapLoad", MRF_BitmapLoad);
    mrp_register(vm_state, "BitmapShow", MRF_BitmapShow);
    mrp_register(vm_state, "BitmapNew", MRF_BitmapNew);
    mrp_register(vm_state, "BitmapDraw", MRF_BitmapDraw);
    mrp_register(vm_state, "BmGetScr", MRF_BmGetScr);

    mrp_register(vm_state, "Exit", MRF_Exit);
    mrp_register(vm_state, "EffSetCon", MRF_EffSetCon);
    mrp_register(vm_state, "TestCom", MRF_TestCom);
    mrp_register(vm_state, "TestCom1", TestCom1);

    mrp_register(vm_state, "DispUpEx", MRF_DispUpEx);

    mrp_register(vm_state, "TimerStart", MRF_TimerStart);
    mrp_register(vm_state, "TimerStop", MRF_TimerStop);

    mrp_register(vm_state, "SpriteSet", MRF_SpriteSet);
    mrp_register(vm_state, "SpriteDraw", MRF_SpriteDraw);
    mrp_register(vm_state, "SpriteDrawEx", MRF_SpriteDrawEx);
    mrp_register(vm_state, "SpriteCheck", MRF_SpriteCheck);

    mrp_register(vm_state, "ClearScreen", MRF_ClearScreen);

    mrp_register(vm_state, "TileSet", MRF_TileSet);
    mrp_register(vm_state, "TileSetRect", MRF_TileSetRect);
    mrp_register(vm_state, "TileDraw", MRF_TileDraw);
    mrp_register(vm_state, "GetTile", MRF_GetTile);
    mrp_register(vm_state, "SetTile", MRF_SetTile);
    mrp_register(vm_state, "TileShift", MRF_TileShift);
    mrp_register(vm_state, "TileLoad", MRF_TileLoad);
#endif

    LUADBGPRINTF("register");
    mr_L_openlib(vm_state, MRP_PHONELIBNAME, phonelib, 0);
    LUADBGPRINTF("lib loaded");

    mrp_register(vm_state, "_loadPack", LoadPack);
    mrp_register(vm_state, "_runFile", MRF_RunFile);

    mrp_register(vm_state, "_rand", MRF_GetRand);
    mrp_register(vm_state, "_mod", MRF_mod);
    mrp_register(vm_state, "_and", MRF_and);
    mrp_register(vm_state, "_or", MRF_or);
    mrp_register(vm_state, "_not", MRF_not);
    mrp_register(vm_state, "_xor", MRF_xor);

    mrp_register(vm_state, "_drawText", MRF_DrawText);
    mrp_register(vm_state, "_drawTextEx", MRF_DrawTextEx);

    mrp_register(vm_state, "_drawRect", MRF_DrawRect);
    mrp_register(vm_state, "_drawLine", MRF_DrawLine);
    mrp_register(vm_state, "_drawPoint", MRF_DrawPoint);
    mrp_register(vm_state, "_clearScr", MRF_ClearScreen);
    mrp_register(vm_state, "_dispUpEx", MRF_DispUpEx);
    mrp_register(vm_state, "_dispUp", MRF_DispUp);
    mrp_register(vm_state, "_textWidth", MRF_TextWidth);

    mrp_register(vm_state, "_bmpLoad", MRF_BitmapLoad);
    mrp_register(vm_state, "_bmpShow", MRF_BitmapShow);
    mrp_register(vm_state, "_bmpShowEx", MRF_BitmapShowEx);
    mrp_register(vm_state, "_bmpNew", MRF_BitmapNew);
    mrp_register(vm_state, "_bmpDraw", MRF_BitmapDraw);
    mrp_register(vm_state, "_bmpGetScr", MRF_BmGetScr);
    mrp_register(vm_state, "_bmpInfo", MRF_BitmapInfo);

    mrp_register(vm_state, "_exit", MRF_Exit);
    mrp_register(vm_state, "_effSetCon", MRF_EffSetCon);
    mrp_register(vm_state, "_com", MRF_TestCom);
    mrp_register(vm_state, "_strCom", TestCom1);
    mrp_register(vm_state, "_plat", MRF_plat);
    mrp_register(vm_state, "_platEx", MRF_platEx);

    mrp_register(vm_state, "_initNet", MRF_initNet);
    mrp_register(vm_state, "_closeNet", MRF_closeNet);
    mrp_register(vm_state, "_timerStart", MRF_TimerStart);
    mrp_register(vm_state, "_timerStop", MRF_TimerStop);

#ifdef MR_TRACE
    {
        char temp_pack_filename[MR_MAX_FILENAME_SIZE];
        MEMCPY(temp_pack_filename, pack_filename, sizeof(pack_filename));
        STRCPY(pack_filename, "dbg.mrp");
        mrp_open_debug(vm_state);
        mrp_dofile(vm_state, "trace.mr");
        MEMCPY(pack_filename, temp_pack_filename, sizeof(pack_filename));
    }
#endif
    //入口变量
    if (!entry) {
        entry = "_dsm";
    }
    mrp_pushstring(vm_state, entry);
    mrp_setglobal(vm_state, "_mr_entry");

    STRNCPY(mr_entry, entry, sizeof(mr_entry) - 1);
    //入口变量

    mrp_pushstring(vm_state, start_fileparameter);
    mrp_setglobal(vm_state, "_mr_param");

    LUADBGPRINTF("Before VM do file");
    MRDBGPRINTF("Used by VM(include screen buffer):%d bytes", LG_mem_len - LG_mem_left);

    mr_state = MR_STATE_RUN;

#ifdef LUADEC
    if (luadec(vm_state, pack_filename, "luadec.txt")) {
        return MR_FAILED;
    }
#endif
    ret = mrp_dofile(vm_state, appExName);

    //这里需要完善
    if (ret != 0) {
        /*
        mrp_close(vm_state);
        mr_mem_free(LG_mem_base, LG_mem_len);
        mr_state = MR_STATE_IDLE;
        */
        MRDBGPRINTF(mrp_tostring(vm_state, -1));
        mrp_pop(vm_state, 1); /* remove error message*/
        mr_stop();
        MRDBGPRINTF("init failed");
        mr_connectWAP(MR_ERROR_WAP);
        return MR_FAILED;
    }

    //MRDBGPRINTF("before gc %d", mr_getTime());
    //mrp_setgcthreshold(vm_state, 0);
    //MRDBGPRINTF("after gc %d", mr_getTime());

    MRDBGPRINTF("After app init, memory left:%d", LG_mem_left);
    LUADBGPRINTF("After VM do file");
    return MR_SUCCESS;
}

/*当启动DSM应用的时候，应该调用DSM的初始化函数， 用以对DSM平台进行初始化*/
int32 mr_start_dsm(char* filename, char* ext, char* entry) {
    mr_screeninfo screeninfo;
    if (mr_getScreenInfo(&screeninfo) != MR_SUCCESS) {
        return MR_FAILED;
    }
    mr_screen_w = screeninfo.width;
    mr_screen_h = screeninfo.height;
    mr_screen_bit = screeninfo.bit;

    MEMSET(pack_filename, 0, sizeof(pack_filename));
    if (filename && (*filename == '*')) {
        STRCPY(pack_filename, filename);
        //以后%的方式要从VM 中去掉
    } else if (filename && (*filename == '%')) {
        char* loc = (char*)strchr2(filename, ',');
        if (loc != NULL) {
            *loc = 0;
            STRCPY(pack_filename, filename + 1);
            *loc = ',';
        } else {
            STRCPY(pack_filename, filename + 1);
        }
    } else if (filename && (*filename == '#') && (*(filename + 1) == '<')) {
        STRCPY(pack_filename, filename + 2);
    } else {
        STRCPY(pack_filename, filename);
    }
    //strcpy(pack_filename,"*A");
    MRDBGPRINTF(pack_filename);

    MEMSET(old_pack_filename, 0, sizeof(old_pack_filename));
    MEMSET(old_start_filename, 0, sizeof(old_start_filename));

    MEMSET(start_fileparameter, 0, sizeof(start_fileparameter));
    if (!ext) {
        ext = MR_START_FILE;
    }
    // return _mr_intra_start(ext, filename);
    return _mr_intra_start(ext, entry);
}

int32 mr_stop_ex(int16 freemem) {
    if (mr_state == MR_STATE_IDLE) {
        return MR_IGNORE;
    }

    if ((mr_state == MR_STATE_RUN) || (mr_state == MR_STATE_PAUSE)) {
        mrp_getglobal(vm_state, "dealevent");
        if (mrp_isfunction(vm_state, -1)) {
            mrp_pushnumber(vm_state, MR_EXIT_EVENT);
            _mr_pcall(1, 0);

        } else { /* no dealevent function */
            MRDBGPRINTF("exit de is nil!");
            mrp_pop(vm_state, 1); /* remove dealevent */
        }
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

#ifdef MR_EXIT_RELEASE_ALL
    if (!(bi & MR_FLAGS_RI)) {
        //MRDBGPRINTF("clean all!");

        //socket cann`t be release at exit
        mrp_pushstring(vm_state, "socket");
        mrp_rawget(vm_state, MRP_GLOBALSINDEX); /* get traceback function */

        if (mrp_istable(vm_state, -1)) {
            mr_closeNetwork();
            mrp_pop(vm_state, 1);
        }
        //end

        mrp_close(vm_state);
    }
#endif

    if (freemem) {
        mr_mem_free(Origin_LG_mem_base, Origin_LG_mem_len);
    }
    //mr_timerStop();
    return MR_SUCCESS;
}

int32 mr_stop(void)  //int16 freemem)
{
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

    mrp_getglobal(vm_state, "suspend");
    if (mrp_isfunction(vm_state, -1)) {
#if 0
      int status;
      status = mrp_pcall(vm_state, 0, 0, 0);  /* call main */
      if (status != 0) {
#ifndef MR_APP_IGNORE_EXCEPTION
         mr_state = MR_STATE_ERROR;
         _mr_showErrorInfo(mrp_tostring(vm_state, -1));
         mrp_pop(vm_state, 1);  /* remove error message*/
#else
         MRDBGPRINTF(mrp_tostring(vm_state, -1));
         mrp_pop(vm_state, 1);  /* remove error message*/
#endif
      }
#else
        _mr_pcall(0, 0);
#endif
        //MRDBGPRINTF("%s\n", mrp_tostring(vm_state, -1));
        //mrp_pop(vm_state, 1);  /* remove error message*/
    } else {                  /* no suspend function */
        mrp_pop(vm_state, 1); /* remove suspend */
    }
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

    mrp_getglobal(vm_state, "resume");
    if (mrp_isfunction(vm_state, -1)) {
#if 0
      int status;
      status = mrp_pcall(vm_state, 0, 0, 0);  /* call main */
      if (status != 0) {
#ifndef MR_APP_IGNORE_EXCEPTION
         mr_state = MR_STATE_ERROR;
         _mr_showErrorInfo(mrp_tostring(vm_state, -1));
         mrp_pop(vm_state, 1);  /* remove error message*/
#else
         MRDBGPRINTF(mrp_tostring(vm_state, -1));
         mrp_pop(vm_state, 1);  /* remove error message*/
#endif
      }
#else
        _mr_pcall(0, 0);
#endif
        //MRDBGPRINTF("%s\n", mrp_tostring(vm_state, -1));
        //mrp_pop(vm_state, 1);  /* remove error message*/
    } else {                  /* no resume function */
        mrp_pop(vm_state, 1); /* remove resume */
    }
    if (mr_timer_state == MR_TIMER_STATE_SUSPENDED) {
        MR_TIME_START(300);
        //mr_timer_state = MR_TIMER_STATE_RUNNING;
    }
    return MR_SUCCESS;
}

int32 mr_event(int16 type, int32 param1, int32 param2) {
    //MRDBGPRINTF("mr_event %d %d %d", type, param1, param2);

    if ((mr_state == MR_STATE_RUN) || ((mr_timer_run_without_pause) && (mr_state == MR_STATE_PAUSE))) {
        if (mr_event_function) {
            int status = mr_event_function(type, param1, param2);
            if (status != MR_IGNORE)
                return status;
        }

        mrp_getglobal(vm_state, "dealevent");
        if (mrp_isfunction(vm_state, -1)) {
            mrp_pushnumber(vm_state, type);
            mrp_pushnumber(vm_state, param1);
            mrp_pushnumber(vm_state, param2);
#if 0
         status = mrp_pcall(vm_state, 3, 0, 0);  /* call main */
         if (status != 0) {
#ifndef MR_APP_IGNORE_EXCEPTION
            mr_state = MR_STATE_ERROR;
            _mr_showErrorInfo(mrp_tostring(vm_state, -1));
            mrp_pop(vm_state, 1);  /* remove error message*/
#else
            MRDBGPRINTF(mrp_tostring(vm_state, -1));
            mrp_pop(vm_state, 1);  /* remove error message*/
#endif
         }
#else
            _mr_pcall(3, 0);
#endif

        } else { /* no dealevent function */
            MRDBGPRINTF("dealevent is nil!");
            mrp_pop(vm_state, 1); /* remove dealevent */
        }
        //mrp_setgcthreshold(vm_state, 0);

        //MRDBGPRINTF("type = %d", mrp_type(vm_state, -1));
        return MR_SUCCESS;  //deal
    }
    return MR_IGNORE;  //didnot deal
}

int32 mr_timer(void) {
    //MRDBGPRINTF("timer %d,%d",mr_state, mr_timer_state);
    if (mr_timer_state != MR_TIMER_STATE_RUNNING) {
        MRDBGPRINTF("warning:mr_timer event unexpected!");
        return MR_IGNORE;
    }
    mr_timer_state = MR_TIMER_STATE_IDLE;

    if ((mr_state == MR_STATE_RUN) || ((mr_timer_run_without_pause) && (mr_state == MR_STATE_PAUSE))) {
    } else if (mr_state == MR_STATE_RESTART) {
        mr_stop();  //1943 修改为mr_stop
        //mr_stop_ex(TRUE);      //1943
        _mr_intra_start(start_filename, NULL);
        return MR_SUCCESS;
    } else {
        return MR_IGNORE;
    };

    //MRDBGPRINTF("before timer");

    if (mr_timer_function) {
        int status = mr_timer_function();

        if (status != MR_IGNORE)
            return status;
    }

    mrp_getglobal(vm_state, (char*)mr_timer_p);
    if (mrp_isfunction(vm_state, -1)) {
#if 0
      int status;
      status = mrp_pcall(vm_state, 0, 0, 0);  /* call main */
      //MRDBGPRINTF("after timer call ret =%d", status);
      if (status != 0) {
#ifndef MR_APP_IGNORE_EXCEPTION
         mr_state = MR_STATE_ERROR;
         _mr_showErrorInfo(mrp_tostring(vm_state, -1));
         mrp_pop(vm_state, 1);  /* remove error message*/
#else
         MRDBGPRINTF(mrp_tostring(vm_state, -1));
         mrp_pop(vm_state, 1);  /* remove error message*/
#endif
      }
#else
        _mr_pcall(0, 0);
#endif
        //MRDBGPRINTF(mrp_tostring(vm_state, -1));
        //mrp_pop(vm_state, 1);  /* remove error message*/
    } else { /* no dealevent function */
        //MRDBGPRINTF("timer %s function is nil!", (char*)p);
        MRDBGPRINTF("timer function \"%s\"is nil!", (char*)mr_timer_p);
        mrp_pop(vm_state, 1); /* remove dealevent */
    }

    //MRDBGPRINTF("after timer");
    //mrp_setgcthreshold(vm_state, 0);
    return MR_SUCCESS;
}

int32 mr_registerAPP(uint8* p, int32 len, int32 index) {
    if (index < (sizeof(mr_m0_files) / sizeof(uint8*))) {
        mr_m0_files[index] = p;
    } else {
        MRDBGPRINTF("mr_registerAPP err!");
        return MR_FAILED;
    }
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

    //MRDBGPRINTF("mr_save_sms_cfg begin!");
    //if((f == MR_FAILED)){
    //   return MR_FAILED;
    //}

    //MRDBGPRINTF("mr_save_sms_cfg before check!");
    if (mr_sms_cfg_need_save) {
        mr_sms_cfg_need_save = FALSE;
        //MRDBGPRINTF("mr_save_sms_cfg before mr_seek!");

#ifdef MR_CFG_USE_A_DISK
        _mr_change_to_root();
#endif
        f = mr_open(DSM_CFG_FILE_NAME, MR_FILE_WRONLY | MR_FILE_CREATE);
#ifdef MR_CFG_USE_A_DISK
        _mr_change_to_current();
#endif
        if (f == 0) {
            return MR_FAILED;
        }
        ret = mr_seek(f, 0, MR_SEEK_SET);
        if (ret == MR_FAILED) {
            //MRDBGPRINTF("mr_save_sms_cfg mr_seek err!");
            mr_close(f);
            return MR_FAILED;
        }
        //MRDBGPRINTF("mr_save_sms_cfg before mr_write!");
        ret = mr_write(f, mr_sms_cfg_buf, MR_SMS_CFG_BUF_LEN);
        if (ret == MR_FAILED) {
            //MRDBGPRINTF("mr_save_sms_cfg mr_write err!");
            mr_close(f);
            return MR_FAILED;
        }
        mr_close(f);
    }
    //MRDBGPRINTF("mr_save_sms_cfg end!");
    return MR_SUCCESS;
}

//#endif

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
            return MR_FAILED;
        }
        ret = mr_read(f, mr_sms_cfg_buf, MR_SMS_CFG_BUF_LEN);
        mr_close(f);
        if (ret != MR_SMS_CFG_BUF_LEN) {
            f = mr_open(DSM_CFG_FILE_NAME, MR_FILE_WRONLY | MR_FILE_CREATE);
            if (f == 0) {
#ifdef MR_CFG_USE_A_DISK
                _mr_change_to_current();
#endif
                return MR_FAILED;
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
}

int32 _mr_smsGetBytes(int32 pos, char* p, int32 len) {
    //MRDBGPRINTF("_mr_smsGetBytes");

    //memset(p, 0, len);

    //nTmp = mr_seek(filehandle, pos, 0);
    //nTmp = mr_read(filehandle, p, len);      //write the num in the end of the sms

    if ((pos >= MR_SMS_CFG_BUF_LEN) || (pos < 0) || ((pos + len) >= MR_SMS_CFG_BUF_LEN)) {
        return MR_FAILED;
    }
    MEMCPY(p, mr_sms_cfg_buf + pos, len);
    return MR_SUCCESS;
}

int32 _mr_smsSetBytes(int32 pos, char* p, int32 len) {
    //memset(p, 0, len);

    //nTmp = mr_seek(filehandle, pos, 0);
    //nTmp = mr_read(filehandle, p, len);      //write the num in the end of the sms

    if ((pos >= MR_SMS_CFG_BUF_LEN) || (pos < 0) || ((pos + len) >= MR_SMS_CFG_BUF_LEN)) {
        return MR_FAILED;
    }
    mr_sms_cfg_need_save = TRUE;
    MEMCPY(mr_sms_cfg_buf + pos, p, len);
    //MRDBGPRINTF("mr_smsSetBytes %d", *p);
    return MR_SUCCESS;
}

int32 _mr_smsGetNum(int32 index, char* pNum) {
    //   int nTmp;
    //   int32 filehandle;
    char num[MR_MAX_NUM_LEN];
    uint32 len;

    //MRDBGPRINTF("_mr_smsGetNum");
    //_mr_smsGetBytes(MR_MAX_NUM_LEN * index + MR_SECTION_LEN, pNum, MR_MAX_NUM_LEN);
    _mr_smsGetBytes(MR_MAX_NUM_LEN * index + MR_SECTION_LEN, num, MR_MAX_NUM_LEN);
    len = _mr_decode((uint8*)num, STRNLEN(num, MR_MAX_NUM_LEN - 1), (uint8*)pNum);
    if ((len == 0) || (len >= MR_MAX_NUM_LEN)) {
        pNum[0] = 0;
        return MR_FAILED;
    }
    pNum[len] = 0;

    /*
   memset(pNum, 0, MR_MAX_NUM_LEN);

   filehandle = mr_open(DSM_CFG_FILE_NAME,  MR_FILE_RDONLY);//这里先不考虑create 文件
   
   if (filehandle == 0)
   {
      mr_printf("mr_open1 %d", filehandle);
      return MR_FAILED;
   }

   nTmp = mr_seek(filehandle, MR_MAX_NUM_LEN * index + MR_SECTION_LEN, 0);
   nTmp = mr_read(filehandle, pNum, MR_MAX_NUM_LEN);      //write the num in the end of the sms
   nTmp = mr_close(filehandle);
*/
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
*name:        _mr_smsCheckNum
*description: check whether the sms was send by cmd num form the ffs
*input:
*                  pNum---pointer to the Num address
*return:     
*                  MR_SUCCESS---success, it is cmd number
*                  MR_FAILED--failed, it is not cmd number
*Note: 
***********************************************/
int32 _mr_smsCheckNum(uint8* pNum) {
    int i;
    //const char mrDYpath[] = "num_sms";      //current dir is "downdata/mr", just add file name to the discreption is ok
    char num[MR_MAX_NUM_LEN];  //, filebuf[MR_MAX_NUM_LEN  * MR_CMD_NUM];
    char buf[MR_MAX_NUM_LEN];
    int32 find = MR_FAILED;

    MRDBGPRINTF("_mr_smsCheckNum");

    //init
    MEMSET(num, 0, sizeof(num));

    //need ??? disable "+86" or "0086" from the number
    if (pNum[0] == '+') {
        if (pNum[1] == '8' && pNum[2] == '6')
            STRCPY(num, (char*)pNum + 3);
        else
            STRCPY(num, (char*)pNum);
    } else {
        if (pNum[0] == '8' && pNum[1] == '6')
            STRCPY((char*)num, (char*)pNum + 2);
        else {
            STRCPY((char*)num, (char*)pNum);
        }
    }
    //strcpy((char *)num,(char *)pNum);

#ifdef MR_DEBUG

    mr_printf("pNum %d", strlen((char*)pNum));

    for (i = 0; i < STRLEN((char*)pNum); i++) {
        mr_printf("pNum %x", pNum[i]);
    }

    mr_printf("num %d", STRLEN((char*)num));

    for (i = 0; i < STRLEN((char*)num); i++) {
        mr_printf("num %x", num[i]);
    }

    MRDBGPRINTF("pNum %s", (char*)pNum);

#endif

    for (i = 0; i < 7; i++) {
        MEMSET(buf, 0, sizeof(buf));
        //_mr_smsGetBytes(MR_SECTION_LEN + i * MR_MAX_NUM_LEN, buf, MR_MAX_NUM_LEN);
        _mr_smsGetNum(i, buf);
        if (buf[0] != 0) {
            //MRDBGPRINTF("buf != 0");
            //MRDBGPRINTF(buf);

            if (STRCMP(buf, num) == 0) {
                //find this num already exist, return
                find = MR_SUCCESS;
                break;
            }
        }
    }

    return find;
}

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
    //int nTmp;
    //const char mrDYpath[] = "num_sms";      //current dir is "downdata/mr", just add file name to the discreption is ok
    int32 len = STRLEN(pNum);
    char num[MR_MAX_NUM_LEN];
    //char* buf;
    if (len > (((MR_MAX_NUM_LEN - 1) / 4 * 3))) {
        MRDBGPRINTF("num too long");
        return MR_FAILED;
    }

    //   MRDBGPRINTF("_mr_smsAddNum");
    MEMSET(num, 0, MR_MAX_NUM_LEN);

    _mr_encode((uint8*)pNum, len, (uint8*)num);
    //STRNCPY(num, pNum, MR_MAX_NUM_LEN-1);

    //nTmp = mr_seek(filehandle, MR_MAX_NUM_LEN * index + MR_SECTION_LEN, 0);

    //nTmp = mr_write(filehandle, num, MR_MAX_NUM_LEN);      //write the num in the end of the sms
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
    //int nTmp;
    char num[MR_MAX_NUM_LEN];

    //MRDBGPRINTF("_mr_smsDelNum");

    MEMSET(num, 0, MR_MAX_NUM_LEN);

    //nTmp = mr_seek(filehandle, MR_MAX_NUM_LEN * index + MR_SECTION_LEN, 0);

    //nTmp = mr_write(filehandle, num, MR_MAX_NUM_LEN);      //write the num in the end of the sms
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
    //int nTmp;
    //int32 len = STRLEN(pURL);
    uint8 flag = 128;
    uint8 out[MR_SECTION_LEN];

    //MRDBGPRINTF("_mr_smsUpdateURL");
    if (len > (((MR_SECTION_LEN - 1) / 4 * 3))) {
        MRDBGPRINTF("url too long");
        return MR_FAILED;
    }

    //*(pURL+len) = 0; //保证字符串最后是\0

    //nTmp = mr_seek(filehandle, CFG_USE_URL_UPDATE_OFFSET, 0);      //find the file end . moth: 0 , from the begining, 1 : from the current status. 2: from the end.

    //nTmp = mr_write(filehandle, &flag , 1);      //SMS更新flag
    _mr_smsSetBytes(CFG_USE_URL_UPDATE_OFFSET, (char*)&flag, 1);

    //nTmp = mr_seek(filehandle, MR_SECTION_LEN*3, 0);

    //nTmp = mr_write(filehandle, pURL, len);      //write the num in the end of the sms
    MEMSET(out, 0, sizeof(out));
    len = _mr_encode(pURL, len, out);
    _mr_smsSetBytes(MR_SECTION_LEN * 3, (char*)out, MR_SECTION_LEN);

    //_mr_smsSetBytes(MR_SECTION_LEN*3, (char*)pURL, len);

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
    //int nTmp;
    //const char mrDYpath[] = "dm_sms";      //current dir is "downdata/mr", just add file name to the discreption is ok
    uint8 contnet[MR_SECTION_LEN];
    uint8 flag = 128;
    int32 index;

    MRDBGPRINTF("_mr_smsDsmSave");

    MEMSET(contnet, 0, MR_SECTION_LEN);

    MEMCPY((char*)contnet, (char*)pSMSContent, len);
    index = contnet[2];  //取得消息的位置号

    if ((index > 31)) {
        return MR_FAILED;
    }

    //nTmp = mr_seek(filehandle, CFG_USE_SM_UPDATE_OFFSET, 0);      //find the file end . moth: 0 , from the begining, 1 : from the current status. 2: from the end.
    //nTmp = mr_write(filehandle, &flag , 1);      //SMS更新flag
    _mr_smsSetBytes(CFG_USE_SM_UPDATE_OFFSET, (char*)&flag, 1);

    //nTmp = mr_seek(filehandle, CFG_SM_FLAG_OFFSET+index, 0);      //find the file end . moth: 0 , from the begining, 1 : from the current status. 2: from the end.
    //nTmp = mr_write(filehandle, &flag , 1);      //SMS消息指示
    _mr_smsSetBytes(CFG_SM_FLAG_OFFSET + index, (char*)&flag, 1);

    //nTmp = mr_seek(filehandle, MR_SECTION_LEN * (index+4), 0);      //find the file end . moth: 0 , from the begining, 1 : from the current status. 2: from the end.
    //目前直接更新消息，版本暂时不做考虑。
    //nTmp = mr_write(filehandle, contnet , MR_SECTION_LEN);      //write the sms message content in the end of the sms, including this message len.
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
    // uint32 i;
    //int32 f;

    if (mr_getUserInfo(&info) != MR_SUCCESS) {
        return MR_FAILED;
    }

    MEMSET(smsstring, 0, sizeof(smsstring));

    sms[0] = 0xFA;
    sms[1] = 0xF1;
    offset = offset + 2;

    /*
   //长度4+32+1
   sms[offset] = 37;
   offset = offset + 1;
   //手机的DSM版本信息
   sms[offset] = 1;
   offset = offset + 1;
   //dsm版本号
   //mr_read(f, &sms[offset], 4);


   
   //    _mr_smsGetBytes(0, (char*)&sms[offset], 4);
   //     *((uint32*)&sms[offset]) = htonl(*((uint32*)&sms[offset]));
   _mr_smsGetBytes(0, (char*)&i, 4);
   i = htonl(i);
   MEMCPY((char*)&sms[offset], (char*)&i, 4);

   
   offset = offset + 4;
   
   //32个消息版本号
   for(i=0;i<32;i++)
   {
      //int32 ret;
      //ret = mr_seek(f, 3 + MR_SECTION_LEN * (i + 4), 0);//找到版本号位置
      //ret = mr_read(f, &sms[offset], 1);
      _mr_smsGetBytes(3 + MR_SECTION_LEN * (i + 4), (char*)&sms[offset], 1);
      offset = offset + 1;
   }//for
*/

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

/*
int32 _mr_checkSMSFile(void)
{
   int32 f;
   int32 i,ret;

   f = _mr_load_sms_cfg();
   return f;
}
*/

static int32 _mr_smsIndiaction(uint8* pContent, int32 nLen, uint8* pNum, int32 type)  //nLen 变为 int32，方便以后扩展
{
    uint8 outbuf[160];
    int32 memlen;

    if ((mr_state == MR_STATE_RUN) || ((mr_timer_run_without_pause) && (mr_state == MR_STATE_PAUSE))) {
        // int status;
        mrp_getglobal(vm_state, "dealevent");
        if (mrp_isfunction(vm_state, -1)) {
            mrp_pushnumber(vm_state, MR_SMS_INDICATION);
            mrp_pushlstring(vm_state, (const char*)pContent, nLen);
            mrp_pushstring(vm_state, (const char*)pNum);
            mrp_pushnumber(vm_state, type);
#if 0
         status = mrp_pcall(vm_state, 3, 0, 0);  /* call main */
         if (status != 0) {

#ifndef MR_APP_IGNORE_EXCEPTION
            mr_state = MR_STATE_ERROR;
            _mr_showErrorInfo(mrp_tostring(vm_state, -1));
            mrp_pop(vm_state, 1);  /* remove error message*/
#else
            MRDBGPRINTF(mrp_tostring(vm_state, -1));
            mrp_pop(vm_state, 1);  /* remove error message*/
#endif
         }
#else
            _mr_pcall(4, 0);
#endif

        } else { /* no dealevent function */
            MRDBGPRINTF("ind de is nil!");
            mrp_pop(vm_state, 1); /* remove dealevent */
        }
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

    //这里放宽了要求
    //if( (_mr_smsCheckNum(pNum) == MR_SUCCESS))
    MEMSET(outbuf, 0, sizeof(outbuf));
    switch (type) {
        case MR_ENCODE_ASCII:
            if ((pContent[0] == 'M') && (pContent[1] == 'R') && (pContent[2] == 'P') && (pContent[3] == 'G')) {
                //这里放宽了要求
                memlen = _mr_decode(pContent + 4, nLen - 4, outbuf);
            } else {
                //mr_printf("mr_sms not  cmd num");
                const char* s1 = _mr_memfind((const char*)pContent, nLen, (const char*)"~#^~", 4);
                const char* s2;
                if (s1) {
                    s2 = _mr_memfind((const char*)s1, nLen - ((uint8*)s1 - pContent), (const char*)"&^", 2);
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
            const char* s1 = _mr_memfind((const char*)pContent, nLen, (const char*)"\0~\0#\0^\0~", 8);
            const char* s2;
            if (s1) {
                s2 = _mr_memfind((const char*)s1, nLen - ((uint8*)s1 - pContent), (const char*)"\0&\0^", 4);
                if (s2) {
                    char inbuf[70];
                    int32 inlen;
                    inlen = _mr_u2c((char*)s1 + 8, (s2 - s1 - 8), inbuf, sizeof(inbuf));
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
    //int32 f;
    //_mr_mem_init(MR_MEM_EXCLUSIVE);
    //f = _mr_checkSMSFile();
    mr_sms_return_flag = 0;
    ret = _mr_smsIndiaction(pContent, nLen, pNum, type);
    if (mr_sms_return_flag == 1)
        ret = mr_sms_return_val;
    //_mr_save_sms_cfg(f);
    //mr_mem_free(LG_mem_base, LG_mem_len, MR_MEM_EXCLUSIVE);
    return ret;
}

int32 _mr_newSIMInd(int16 type, uint8* old_IMSI) {
    int32 id = mr_getNetworkID();
    uint8 flag;
    char num[MR_MAX_NUM_LEN];
    int32 f;

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
                        return MR_FAILED;
                    break;
                case MR_NET_ID_CN:
                case MR_NET_ID_CDMA:
                    if (_mr_smsGetNum(MR_NET_ID_CN, num) == MR_FAILED)
                        return MR_FAILED;
                    break;
                default:
                    return MR_FAILED;
                    break;
            }
        }
        _mr_smsReplyServer(num, old_IMSI);
    }
    return MR_SUCCESS;
}

int32 mr_newSIMInd(int16 type, uint8* old_IMSI) {
    //#ifdef MR_USE_V1_SIM_IND
    int32 ret;
    //_mr_mem_init(MR_MEM_EXCLUSIVE);
    ret = _mr_newSIMInd(type, old_IMSI);
    //mr_mem_free(LG_mem_base, LG_mem_len, MR_MEM_EXCLUSIVE);
    return ret;
    //#else
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
    } else {
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

    if ((this_packname[0] == '*') || (this_packname[0] == '$')) { /*read file from m0*/
        uint32 pos = 0;
        uint32 m0file_len;

        if (this_packname[0] == '*') {                                 /*m0 file?*/
            mr_m0_file = (char*)mr_m0_files[this_packname[1] - 0x41];  //这里定义文件名为*A即是第一个m0文件 *B是第二个.........
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

        MEMCPY(&_v[0], &mr_m0_file[pos], 4);
    } else { /*read file from efs , EFS 中的文件*/
        f = mr_open(this_packname, MR_FILE_RDONLY);
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
                return 0;
            }

            nTmp = mr_seek(f, file_pos, MR_SEEK_SET);
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

void mythroad_init(void) {
    memset2(_mr_c_port_table, 0, sizeof(_mr_c_port_table));
    memset2(mr_m0_files, 0, sizeof(mr_m0_files));

    phonelib[0].name = "call", phonelib[0].func = Call;
    phonelib[1].name = "sendSms", phonelib[1].func = SendSms;
    phonelib[2].name = "getNetID", phonelib[2].func = GetNetworkID;
    phonelib[3].name = "wap", phonelib[3].func = ConnectWAP;
    phonelib[4].name = NULL, phonelib[4].func = NULL;

    _mr_c_internal_table_init();
    _mr_c_function_table_init();
}
