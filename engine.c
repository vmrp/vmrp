#include <signal.h>
#include <malloc.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <sys/mman.h>
#endif

#include "engine.h"
#include "mr_helper.h"
#include "dsm.h"
#include "fileLib.h"
#include "tsf_font.h"


void engine_init();
void engine_free();

//引擎全局变量
MR_C_FUNCTION		mr_helper;

mr_table			func_table;
mr_c_function_st	cfunction_table;
mrc_extChunk_st		extChunk_table;


uint16			screenBuf[SCNBUF_COUNT][SCNW*SCNH];
uint16			*mr_screenBuf;
int32 mr_screen_w, mr_screen_h, mr_screen_bit;
mr_bitmapSt		mr_bmps[BITMAPMAX];
mr_tileSt		mr_tiles[TILEMAX];
mr_soundSt		mr_sounds[SOUNDMAX];
mr_spriteSt		mr_sprits[SPRITEMAX];
uint16			*mr_map;
char			pack_filename[128];
char			start_filename[32];
char			old_pack_filename[128];
char			old_start_filename[32];
char			*mr_ram_file;
int32			mr_ram_file_len;
int8			mr_soundOn;
int8			mr_shakeOn;
char*			LG_mem_base;	//VM 内存基址
int32			LG_mem_len;	//VM 内存大小
char*			LG_mem_end;	//VM 内存终止
int32			LG_mem_left;	//VM 剩余内存
uint32			LG_mem_min;	//VM 剩余内存
uint32			LG_mem_top;	//VM 剩余内存
uint8			mr_sms_cfg_buf[120*10];


//Linux处理错误
#define handle_error(msg) \
	do { perror(msg); exit(EXIT_FAILURE); } while (0)




void mr_getScreenSize( int32 *w, int32 *h ) {
	if(w) *w = *func_table.mr_screen_w;
	if(h) *h = *func_table.mr_screen_h;
}

uint16 * w_getScreenBuffer( void ){
	return *func_table.mr_screenBuf;
}

const char * mr_getPackName(){
	return func_table.pack_filename;
}

void mr_setPackName(const char* name){
	strcpy(func_table.pack_filename, name);
}

void mr_setStartFileName(const char *name){
	strcpy(func_table.start_filename, name);
}

//这个函数被 MRP 调用，传 mr_helper 函数指针进来
int32 mr_c_function_new(MR_C_FUNCTION f, int32 len) {
	LOG("mr_c_function_new invoked ! mr_helper: addr:0x%08x len:%d", (unsigned int)f, len);
	mr_helper = f;
	extChunk_table.event = f;
	return MR_SUCCESS;
}

/*定时器到期时调用定时器事件，Mythroad平台将对之进行处理。
p是启动定时器时传入的Mythroad定时器数据*/
int32 mr_timer(void){
	return mr_helper(&cfunction_table, 2, NULL, 0, NULL, NULL);
}

/*在Mythroad平台中对按键事件进行处理，press	= MR_KEY_PRESS按键按下，
= MR_KEY_RELEASE按键释放，key	对应的按键编码*/
int32 mr_event(int16 type, int32 param1, int32 param2){
	int32 input[5] = {0};

	input[0] = type;
	input[1] = param1;
	input[2] = param2;
	return mr_helper(&cfunction_table, 1, (uint8*)input, sizeof(input), NULL, NULL);
}

/*退出Mythroad并释放相关资源*/
int32 mr_stop(void){
	engine_free();

	return mr_event(MR_EVENT_EXIT, 0, 0);
}

int32 mr_extLoad(void *addr, int32 len) {
#ifndef _WIN32
	char  *buffer;
    int pagesize, pagecount;
	mrc_extChunk_st *ext = &extChunk_table;

    pagesize = sysconf(_SC_PAGE_SIZE);
    if (pagesize == -1)
        handle_error("sysconf");

    /* 分配一个对齐到页边缘的缓冲区；
        初始的保护属性是 PROT_READ | PROT_WRITE */
	pagecount = len/pagesize;
	if(len%pagesize != 0)
		pagecount++;
    buffer = memalign(pagesize, pagecount * pagesize);
    if (buffer == NULL)
        handle_error("memalign");

	printf("pagesize:%d pagecount:%d\n", pagesize, pagecount);
	printf("ext new addr: 0x%08x\n", (unsigned int)buffer);

	//复制ext代码到内存
	memset(buffer, 0, pagecount*pagesize);
	memcpy(buffer, addr, len);

	//设置内存可执行权限
    if (mprotect(buffer, pagecount*pagesize, PROT_EXEC|PROT_WRITE|PROT_READ) == -1){
		//设置失败，释放他
		free(buffer);
        handle_error("mprotect");
	}

	ext->check = 0x7FD854EB;
	ext->code_buf =(uint8*)buffer;
	ext->code_len = len;
	ext->init_func = (MR_LOAD_C_FUNCTION)(buffer + 8);
	//设置ext函数表
	*((int32*)buffer) = (int32)&func_table;
	*((int32*)buffer+1) = (int32)&cfunction_table;
	return MR_SUCCESS;
#else
	return MR_FAILED;
#endif
}

int32 mr_extFree(){
	return MR_FAILED;
}

int32 mr_c_function_load(){
	LOG("try to invoked mrc_c_function_load addr:0x%08x", (unsigned int)extChunk_table.init_func);
	return extChunk_table.init_func(1);
}

int32 mr_init(){
	LOG("try to invoked mrc_init");
	mr_helper(&cfunction_table, 0, NULL, 0, NULL, NULL);
	return MR_SUCCESS;
}

/*当启动DSM应用的时候，应该调用DSM的初始化函数，
用以对DSM平台进行初始化*/
int32 mr_start_dsm(const char* entry){
	int32 *ext, extLen;
	

	if(!entry) return MR_FAILED;

	LOG("mr_start_dsm entry: %s", entry);
	
	//初始化引擎
	engine_init();

	mr_setPackName(entry);
	mr_setStartFileName(START_FILE_NAME);
	ext = mr_readFileFromMrp(START_FILE_NAME, &extLen, 0);
	if(ext == NULL) {
		LOG("read ext err!");
		return MR_FAILED;
	}

	LOG("read ext suc! addr:0x%08x len:%d", (uint)ext, extLen);

	//设置 mr_table 表

	//load进可执行内存
	mr_extLoad(ext, extLen);
	free(ext);

	mr_c_function_load();
	mr_init();
	return MR_SUCCESS;
}

/*暂停应用*/
int32 mr_pauseApp(void){
	return mr_helper(&cfunction_table, 4, NULL, 0, NULL, NULL);
}

/*恢复应用*/
int32 mr_resumeApp(void){
	return mr_helper(&cfunction_table, 5, NULL, 0, NULL, NULL);
}

/*当手机收到短消息时调用该函数*/
int32 mr_smsIndiaction(uint8 *pContent, int32 nLen, uint8 *pNum, int32 type){
	int32 input[5];

	input[0] = MR_SMS_INDICATION;
	input[1] = (int32)pContent;
	input[2] = (int32)pNum;
	input[3] = type;
	input[4] = nLen;
	//这里应该调用 mrc_eventEx 的
	return mr_helper(&cfunction_table, 1, (uint8*)input, sizeof(input), NULL, NULL);
}

int32 mr_smsIndiactionEx(uint8 *pContent, int32 nLen, uint8 *pNum, int32 type){
	int32 input[5];

	input[0] = MR_SMS_INDICATION;
	input[1] = (int32)pContent;
	input[2] = (int32)pNum;
	input[3] = type;
	input[4] = nLen;
	//这里应该调用 mrc_eventEx 的
	return mr_helper(&cfunction_table, 1, (uint8*)input, sizeof(input), NULL, NULL);
}

/*对下载内容（保存在内存区中的一个下载的文件）进行判断，
若下载文件是DSM菜单，由DSM引擎对下载文件进行保存。使用
本函数时，下载文件应该已经下载完全，并且全部内容保存在
所给的内存中。*/
int32 mr_save_mrp(void *p,uint32 l){
	return MR_FAILED;
}

/*功能同mr_save_mrp，但传入的是一个打开的文件句柄，文件由
调用者关闭。该函数目前尚未实现，若需要使用，请联系ouli*/
int32 mr_save_mrp_with_handle(MR_FILE_HANDLE f){

	return MR_FAILED;
}

/*用户SIM卡变更*/
int32 mr_newSIMInd(int16  type, uint8* old_IMSI){

	return MR_FAILED;
}


/****************************************************************************
 函数名:int32 mr_mem_get (char** mem_base, uint32* mem_len)
 描  述:为dsm申请运行需要的内存
 参  数:mem_base:dsm运行要内存的指针的指针
 mem_len :内存的大小
 返  回:MR_SUCCESS,MR_FAILED
 ****************************************************************************/
int32 mr_mem_get(char** mem_base, uint32* mem_len)
{
	*mem_base = malloc(DSM_MEM_SIZE);
	*mem_len = DSM_MEM_SIZE;

	return MR_SUCCESS;
}

/****************************************************************************
 函数名:int32 mr_mem_free (char* mem, uint32 mem_len)
 描  述:dsm退出后释放由mr_mem_get申请到的内存
 参  数:meme   :要释放的内存的指针
 mem_len:要释放的内存大小
 返  回:MR_SUCCESS,MR_FAILED
 ****************************************************************************/
int32 mr_mem_free(char* mem, uint32 mem_len)
{
	free(mem);

	return MR_SUCCESS;
}

void engine_init() {
	mr_screenBuf = screenBuf[0];
	mr_screen_w = SCNW, mr_screen_h = SCNH, mr_screen_bit = SCNBIT;
	memset(start_filename, 0, sizeof(start_filename));
	memset(pack_filename, 0, sizeof(pack_filename));

	memset(&func_table, 0, sizeof(mr_table));
	memset(&extChunk_table, 0, sizeof(mrc_extChunk_st));
	memset(&cfunction_table, 0, sizeof(mr_c_function_st));

	//设置 mr_table 表
	memcpy(&func_table, &mr_sys_table, sizeof(mr_table));

	func_table._mr_c_function_new = mr_c_function_new;
	func_table.mr_screenBuf = &mr_screenBuf;
	func_table.mr_screen_w = &mr_screen_w;
	func_table.mr_screen_h = &mr_screen_h;
	func_table.mr_screen_bit = &mr_screen_bit;
	func_table.start_filename = start_filename;
	func_table.pack_filename = pack_filename;

	func_table._mr_c_internal_table = NULL;
	func_table._mr_c_port_table = NULL;

	func_table.mr_sms_cfg_buf = malloc(120*20);
	memset(func_table.mr_sms_cfg_buf, 0, 120*20);

	//分配内存
	mr_mem_get(&LG_mem_base, (uint32*)&LG_mem_len);
	LG_mem_end = LG_mem_base + LG_mem_len;
	LG_mem_left = LG_mem_len;
	LG_mem_top = DSM_MEM_SIZE;
	LG_mem_min = DSM_MEM_SIZE_MIN;
	func_table.LG_mem_base = &LG_mem_base;
	func_table.LG_mem_len = &LG_mem_len;
	func_table.LG_mem_end = &LG_mem_end;
	func_table.LG_mem_left = &LG_mem_left;
	func_table.LG_mem_top = &LG_mem_top;
	func_table.LG_mem_min = &LG_mem_min;

	//extChunk_table 表
	extChunk_table.extMrTable = &func_table;
	extChunk_table.global_p_buf = &cfunction_table;
	extChunk_table.global_p_len = sizeof(mr_c_function_st);

	//设置 mr_c_function_st 表
	cfunction_table.mrc_extChunk = &extChunk_table;
	cfunction_table.ext_type = 1;

	//其他组件
	tsf_init();

	LOG("engine init scnbuf:0x%08x", (uint)*func_table.mr_screenBuf);
}

void engine_free(){

	mr_mem_free(LG_mem_base, LG_mem_len);
	free(extChunk_table.code_buf);

	LOG("engine free");
}

void *mr_readFileFromMrp(const char *filename, int32 *filelen, int32 lookfor)
{
	int32 ret;

	if (0 == lookfor)
	{
		int32 len;
		uint8 *out = NULL;

		ret = readMrpFileEx(mr_getPackName(), filename, NULL, &len, &out);
		if (ret != MR_SUCCESS) {
			if (NULL != out)
				mr_free(out, len);
			return NULL;
		}
		if (NULL != filelen)
			*filelen = len;
		return out;
	}
	else
	{
		ret = readMrpFileEx(pack_filename, filename, NULL, NULL, NULL);
		if (ret != MR_SUCCESS) {
			return NULL;
		} else {
			return (void*)1;
		}
	}
}

int32 mr_getScreenInfo(mr_screeninfo * screeninfo){
	screeninfo->width = *func_table.mr_screen_w;
	screeninfo->height = *func_table.mr_screen_h;
	screeninfo->bit = *func_table.mr_screen_bit;
	return MR_SUCCESS;
}


/////////////////////////////////////////////////////////
#include "dsm.h"
#include "mrporting.h"

const mr_internal_table mr_sys_internal_tabl = { NULL, };

const mr_c_port_table mr_sys_c_port_table = { NULL, };

//虚拟机 默认的函数表
const mr_table mr_sys_table = {
	mr_malloc,
	mr_free,
	mr_realloc,
	mr_memcpy,
	mr_memmove,
	mr_strcpy,
	mr_strncpy,
	mr_strcat,
	mr_strncat,
	mr_memcmp,
	mr_strcmp,
	mr_strncmp,
	mr_strcoll,
	mr_memchr,
	mr_memset,
	mr_strlen,
	mr_strstr,
	mr_sprintf,
	mr_atoi,
	mr_strtoul,
	mr_rand,

	NULL,
	NULL,

	NULL,//&mr_sys_internal_tabl,
	NULL,//&mr_sys_c_port_table,

	mr_c_function_new,

	mr_printf,
	mr_mem_get,
	mr_mem_free,
	mr_drawBitmap,
	mr_getCharBitmap,
	mr_timerStart,
	mr_timerStop,
	mr_getTime,
	mr_getDatetime,
	mr_getUserInfo,
	mr_sleep,

	mr_plat,
	mr_platEx,

	//file io
	mr_ferrno,
	mr_open,
	mr_close,
	mr_info,
	mr_write,
	mr_read,
	mr_seek,
	mr_getLen,
	mr_remove,
	mr_rename,
	mr_mkDir,
	mr_rmDir,
	mr_findStart,
	mr_findGetNext,
	mr_findStop,


	mr_exit,
	mr_startShake,
	mr_stopShake,
	mr_playSound,
	mr_stopSound,

	mr_sendSms,
	mr_call,
	mr_getNetworkID,
	mr_connectWAP,

	mr_menuCreate,
	mr_menuSetItem,
	mr_menuShow,
	NULL, //rev
	mr_menuRelease,
	mr_menuRefresh,

	mr_dialogCreate,
	mr_dialogRelease,
	mr_dialogRefresh,

	mr_textCreate,
	mr_textRelease,
	mr_textRefresh,

	mr_editCreate,
	mr_editRelease,
	mr_editGetText,

	mr_winCreate,
	mr_winRelease,

	mr_getScreenInfo,

	mr_initNetwork,
	mr_closeNetwork,
	mr_getHostByName,
	mr_socket,
	mr_connect,
	mr_closeSocket,
	mr_recv,
	mr_recvfrom,
	mr_send,
	mr_sendto,

	NULL, //&(mr_screenBuf[0]),
	NULL, //&mr_screen_w,
	NULL, //&mr_screen_h,
	NULL, //&mr_screen_bit,
	mr_bmps,
	mr_tiles,
	NULL,//&mr_map,
	mr_sounds,
	mr_sprits,

	//pack
	pack_filename,
	start_filename,
	old_pack_filename,
	old_start_filename,

	&mr_ram_file,
	&mr_ram_file_len,

	&mr_soundOn,
	&mr_shakeOn,

	&LG_mem_base,
	&LG_mem_len,
	&LG_mem_end,
	&LG_mem_left,

	mr_sms_cfg_buf,
	mr_md5_init,
	mr_md5_append,
	mr_md5_finish,
	mr_load_sms_cfg,
	mr_save_sms_cfg,
	mr_DispUpEx,

	mr_DrawPoint,
	mr_DrawBitmap,
	mr_DrawBitmapEx,
	mr_DrawRect,
	mr_DrawText,
	mr_BitmapCheck,
	mr_readFile,
	mr_wstrlen,
	NULL,
	mr_DrawTextEx,
	mr_EffSetCon,
	mr_TestCom,
	mr_TestCom1,
	mr_c2u,

	mr_div,
	mr_mod,

	&LG_mem_min,
	&LG_mem_top,
	mrc_updcrc,
	start_filename,
	NULL,
	NULL,
	mr_unzip,
	NULL,
	NULL,
	NULL,
	NULL
};
