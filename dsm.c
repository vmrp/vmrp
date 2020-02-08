#include <dirent.h>
#include <fcntl.h>
#include <malloc.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

#include "./header/dsm.h"
#include "./header/engine.h"
#include "./header/fileLib.h"
#include "./header/mr_helper.h"
#include "./header/mrporting.h"

#include "./header/tsf_font.h"

extern int gbToUCS2BE(unsigned char *gbCode, unsigned char *unicode,
                      int bufSize);
static int32 dsmSwitchPath(uint8 *input, int32 input_len, uint8 **output,
                           int32 *output_len);

int showApiLog = TRUE;

/////////////// 类C库 ///////////////////////
void *mr_malloc(uint32 len) { return malloc(len); }

void mr_free(void *p, uint32 len) { free(p); }

void *mr_realloc(void *p, uint32 oldlen, uint32 newlen) {
    return realloc(p, newlen);
}

void *mr_memcpy(void *dst, const void *src, int len) {
    return memcpy(dst, src, (size_t)len);
}

void *mr_memmove(void *dst, const void *src, int len) {
    return memmove(dst, src, (size_t)len);
}

char *mr_strcpy(char *dst, const char *src) { return strcpy(dst, src); }

char *mr_strncpy(char *dst, const char *src, int len) {
    return strncpy(dst, src, (size_t)len);
}

char *mr_strcat(char *dst, const char *src) { return strcat(dst, src); }

char *mr_strncat(char *dst, const char *src, int len) {
    return strncat(dst, src, (size_t)len);
}

int mr_memcmp(const void *dst, const void *src, int len) {
    return memcmp(dst, src, (size_t)len);
}

int mr_strcmp(const char *dst, const char *src) { return strcmp(dst, src); }

int mr_strncmp(const char *dst, const char *src, int len) {
    return strncmp(dst, src, (size_t)len);
}

int mr_strcoll(const char *dst, const char *src) { return strcoll(dst, src); }

void *mr_memchr(const void *s, int c, int len) {
    return memchr(s, c, (size_t)len);
}

void *mr_memset(void *s, int c, int len) { return memset(s, c, (size_t)len); }

int mr_strlen(const char *s) { return strlen(s); }

char *mr_strstr(const char *s1, const char *s2) { return strstr(s1, s2); }

int mr_sprintf(char *buf, const char *fmt, ...) {
    va_list vars;
    int ret;

    va_start(vars, fmt);
    ret = vsprintf(buf, fmt, vars);
    va_end(vars);

    return ret;
}

int mr_atoi(const char *s) { return atoi(s); }

unsigned long mr_strtoul(const char *nptr, char **endptr, int base) {
    return strtoul(nptr, endptr, base);
}

void mr_sand(uint32 seed) { return srand(seed); }

int mr_rand(void) { return rand(); }

void mr_printf(const char *format, ...) {
    va_list params;

    va_start(params, format);
    printf(format, params);
    va_end(params);
}

#ifndef _WIN32
static void sigroutine(int signo) {
    switch (signo) {
        case SIGALRM:
            mr_timer();
            break;
    }
}
#endif

/****************************************************************************
 函数名:int32 mr_timerStart(uint16 t)
 描  述:启动dsm定时器
 参  数:t:定时器溢出时间(ms)
 返  回:MR_SUCCESS,MR_FAILED
 ****************************************************************************/
int32 mr_timerStart(uint16 t) {
#ifndef _WIN32
    struct itimerval tick;

    /*当setitimer()所执行的timer时间到了会呼叫SIGALRM signal，
      用signal()将要执行的 function 指定给SIGALRM。*/
    signal(SIGALRM, sigroutine);

    memset(&tick, 0, sizeof(tick));
    // itimerval.it_value设定第一次执行function所延迟的秒数
    // tick.it_value.tv_sec = t/1000;
    tick.it_value.tv_usec = t;

    //以下2个参数 用于 第一次执行后，每隔多久再执行，不需要重复则不用设置
    // tick.it_interval.tv_sec = 1; //定时器启动后，每隔1秒将执行相应的函数
    // tick.it_interval.tv_usec = t;

    // ITIMER_REAL，表示以real-time方式减少timer，在timeout时会送出SIGALRM
    // signal
    if (setitimer(ITIMER_REAL, &tick, NULL) == -1) {
        LOG("setitimer err!");
        return MR_FAILED;
    }

    if (showApiLog) LOG("mr_timerStart(t:%d)", t);

    return MR_SUCCESS;
#else
    return MR_FAILED;
#endif
}

/*停止定时器。*/
int32 mr_timerStop(void) { return MR_SUCCESS; }

/*取得时间，单位ms*/
uint32 mr_getTime(void) {
    struct timeval t;
    int ret = gettimeofday(&t, NULL);

    return (ret == 0 ? t.tv_usec : 0);
}

/*获取系统日期时间。*/
int32 mr_getDatetime(mr_datetime *datetime) {
    struct tm *time;
    time_t tt = 0;

    if (!datetime) return MR_FAILED;

    time = localtime(&tt);
    datetime->year = time->tm_year;
    datetime->month = time->tm_mon;
    datetime->day = time->tm_mday;
    datetime->hour = time->tm_hour;
    datetime->minute = time->tm_min;
    datetime->second = time->tm_sec;

    return MR_SUCCESS;
}

/*取得手机相关信息。*/
int32 mr_getUserInfo(mr_userinfo *info) {
    if (!info) return MR_FAILED;

    memset(info, 0, sizeof(mr_userinfo));
    memcpy(info->IMEI, "\x1\x2\x3\x4\x5", 5);
    memcpy(info->IMSI, "\x2\x3\x4\x5", 5);
    strcpy(info->manufactory, "mrpej");
    memcpy(info->spare, "E界开发团队", 11);
    strcpy(info->type, "android");
    info->ver = 2012;

    return MR_SUCCESS;
}

/*任务睡眠，单位ms*/
int32 mr_sleep(uint32 ms) {
    if (showApiLog) LOG("mr_sleep(%d)", ms);
    sleep(ms);

    return MR_SUCCESS;
}

/*平台扩展接口*/
int32 mr_plat(int32 code, int32 param) {
    if (showApiLog) LOG("mr_plat(code:%d, param:%d)", code, param);

    switch (code) {
        case MR_SET_ACTIVE_SIM:  //设置激活的sim卡
        {
            return MR_IGNORE;
            break;
        }

        case MR_GET_SCENE:  //获取前景模式
        {
            int32 ret = 0;
            // extern U8 gactivatedprofile;

            /*switch(gactivatedprofile)
                    {
                    case MMI_PROFILE_GENERAL:
                            ret = MR_SCENE_NORMAL;
                            break;
                    case MMI_PROFILE_MEETING:
                            ret = MR_SCENE_MEETING;
                            break;
                    case MMI_PROFILE_INDOOR:
                            ret = MR_SCENE_INDOOR;
                            break;
                    case MMI_PROFILE_OUTDOOR:
                            ret = MR_SCENE_OUTDOOR;
                            break;
                    default:
                            return MR_FAILED;
                            break;
                    }*/
            return (ret + MR_PLAT_VALUE_BASE);

            break;
        }

        case MR_GET_FILE_POS:  //获取文件读写指针
        {
            /*UINT pos = 0;
                    int ret = tell(param, &pos);

                    if(ret == FS_NO_ERROR)
                            return (pos+MR_PLAT_VALUE_BASE);
                    else
                            return MR_FAILED;*/
            break;
        }

        case MR_GET_CELL_ID_START: {
#ifdef MMI_ON_HARDWARE_P

            dsm_initBSID();
            return MR_SUCCESS;
#else
            return MR_FAILED;
#endif
            break;
        }

        case MR_GET_CELL_ID_STOP: {
#ifdef MMI_ON_HARDWARE_P
            dsm_unInitBSID();
            return MR_SUCCESS;
#else
            return MR_FAILED;
#endif
            break;
        }

        case MR_STOP_SHOW_PIC:  //停止GIF动画显示
        {
            //			if(dsmPicShow.appid > 0)
            ///*防止没有调用画，就停止*/
            //			{
            //				memset(&dsmPicShow,0,sizeof(dsmPicShow));
            //				StopTimer(DSM_GLANCE_TIMER);
            //
            //				if(GetActiveScreenId() ==
            //IDLE_SCREEN_ID)
            //				{
            //#ifdef __GDI_MEMORY_PROFILE_2__
            //					gdi_draw_solid_rect(DSM_IDLE_POS_X, DSM_IDLE_POS_Y,
            //DSM_IDLE_POS_X+DSM_IDLE_MAX_WIDTH-1,DSM_IDLE_POS_Y+DSM_IDLE_MAX_HEIGHT-1,
            //GDI_COLOR_TRANSPARENT); #else
            //					pixtel_UI_fill_rectangle(DSM_IDLE_POS_X, DSM_IDLE_POS_Y,
            //DSM_IDLE_POS_X+DSM_IDLE_MAX_WIDTH-1,DSM_IDLE_POS_Y+DSM_IDLE_MAX_HEIGHT-1,
            //GDI_COLOR_TRANSPARENT ); #endif
            //					gdi_layer_blt_previous(DSM_IDLE_POS_X, DSM_IDLE_POS_Y,
            //DSM_IDLE_POS_X+DSM_IDLE_MAX_WIDTH-1,
            //DSM_IDLE_POS_Y+DSM_IDLE_MAX_HEIGHT-1);
            //				}
            //			}

            return MR_SUCCESS;
        }

        case MR_ACTIVE_APP:  //激活后台运行 程序
        {
            /*if((dsmState != DSM_BACK_RUN)||(param != dsmBackStage.appid))
                            return MR_FAILED;

                    return EntryDsmScreenByActiveApp();*/

            break;
        }

        case MR_NES_GET_READ_ADDR:  //获取NES读取地址
        {
            // return dsmReadAddr;
            break;
        }
        case MR_NES_SET_WRITE_ADDR:  //设置NES写入地址
        {
            // dsmWriteAddr = param;
            return MR_SUCCESS;
        }

        case MR_GOTO_BASE_WIN:  //返回 home
        {
            break;
        }

        case MR_SET_KEY_END:  //设置屏蔽挂机键
        {
            return MR_SUCCESS;
        }

            /*case  MR_CONNECT:
            {
                    if(socStat[param].socStat == DSM_SOC_CONNECTED)
                    {
                            return MR_SUCCESS;
                    }
                    else if(socStat[param].socStat == DSM_SOC_CONNECTING)
                    {
                            SetProtocolEventHandler(dsm_soc_socket_notify,
    MSG_ID_APP_SOC_NOTIFY_IND); return MR_WAITING;
                    }
                    else
                    {
                            return MR_FAILED;
                    }
            }
    case  MR_SET_SOCTIME:
            {
                    return MR_SUCCESS;
            }*/

        case MR_GET_RAND:  // 1211
        {
            srand(mr_getTime());
            return MR_PLAT_VALUE_BASE + rand() % param;
        }

        case MR_CHECK_TOUCH:  //是否支持触屏
        {
            return MR_NORMAL_SCREEN;
        }

        case MR_GET_HANDSET_LG:  //获取语言
        {
            /*extern U16 gCurrLangIndex;
                    if(gCurrLangIndex == 0)
                            return MR_ENGLISH;
                    else*/
            return MR_CHINESE;
        }

        case MR_SET_VOL:  //设置音量
        {
            // dsm_set_vol(param);
            return MR_SUCCESS;
        }
    }

    return MR_IGNORE;
}

/*增强的平台扩展接口*/
int32 mr_platEx(int32 code, uint8 *input, int32 input_len, uint8 **output,
                int32 *output_len, MR_PLAT_EX_CB *cb) {
    if (showApiLog) LOG("mr_platEx(code:%d, il:%d)", code, input_len);

    switch (code) {
        case MR_TUROFFBACKLIGHT:  //关闭背光常亮
        {
            break;
        }
        case MR_TURONBACKLIGHT:  //开启背光常亮
        {
            break;
        }
        case MR_SWITCHPATH:  //切换跟目录
        {
            return dsmSwitchPath(input, input_len, output, output_len);
            break;
        }
    }

    return MR_FAILED;
}

///////////////////////// 文件操作接口 //////////////////////////////////////
/**
 * 协议：SDCARD 作为跟目录 以 /结尾
 *		dsmWorkPath 以 / 结尾，切换到跟路径后为空
 */
#define DSM_ROOT_PATH "mythroad/"
// #define SDCARD_PATH "/mnt/sdcard/"
#define SDCARD_PATH "./"

static char dsmWorkPath[DSM_MAX_FILE_LEN + 1] =
    DSM_ROOT_PATH; /*路径都是gb 编码*/
static char dsmLaunchPath[DSM_MAX_FILE_LEN + 1] =
    DSM_ROOT_PATH; /*路径都是gb 编码*/
static char filenamebuf[DSM_MAX_FILE_LEN + 5] = {
    0};  //因为要连接其它几个路径，所以长度要更长

static void SetDsmWorkPath(char *path) {
    memcpy(dsmWorkPath, path, strlen(path) + 1);
}

char *GetDsmWorkPath(void) { return dsmWorkPath; }

/****************************************************************************
 函数名:static void dsmRestoreRootDir(void)
 描  述:返回VM根目录
 参  数:无
 返  回:无
 ****************************************************************************/
void dsmRestoreRootDir(void) {
    memcpy(dsmWorkPath, DSM_ROOT_PATH, strlen(DSM_ROOT_PATH) + 1);
}

/****************************************************************************
 函数名:static void dsmToLaunchDir(void)
 描  述:将操作路径返回到刚启动时候的路径
 参  数:无
 返  回:无
 ****************************************************************************/
static void dsmToLaunchDir(void) {
    memcpy(dsmWorkPath, dsmLaunchPath, strlen(dsmLaunchPath) + 1);
}

/**
 * 格式化路径字符串
 * 例：/aa//bb/c/ 得到 aa/bb/c （最标准的路径字符串）
 *
 * 返回格式化后的字符串
 */
int32 formatPathString(char *str) {
    char *p, *pb;
    int32 len;

    //空字符串 *str=='\0'
    if (!str || *str == '\0') return -1;

    len = strlen(str);
    p = (PSTR)str;
    while (*p == '/') {
        p++;
        len--;
    }

    if (!p || !*p) {
        return -1;  //全是 /// 的情况在这里就可以返回
    }
    memmove(str, p, len + 1);

    pb = str;
    len = 0;
    p = str;
    while (*p) {
        PCSTR pp = strchr((PSTR)p, '/');
        int l = pp - p + 1;
        memmove(pb, p, l);
        pb += l;
        len += l;
        while (*pp == '/') pp++;
        p = (PSTR)pp;
    }

    if (str[len - 1] == '/') {
        str[--len] = '\0';
    }

    return len;
}

/****************************************************************************
函数名:static int32 dsmSwitchPath(uint8* input, int32 input_len, uint8** output,
int32* output_len) 描  述:VM 对路径操作的接口 参  数: 返  回:
****************************************************************************/
static int32 dsmSwitchPath(uint8 *input, int32 input_len, uint8 **output,
                           int32 *output_len) {
    if (input == NULL) return MR_FAILED;

    if (strlen((char *)input) > (DSM_MAX_FILE_LEN - 3)) return MR_FAILED;

    switch (input[0]) {
        case 'Z':  //返回刚启动时路径
        case 'z':
            dsmToLaunchDir();
            break;

        case 'Y':  //获取当前工作绝对路径
        case 'y': {
            memset(filenamebuf, 0, sizeof(filenamebuf));
            sprintf(filenamebuf, "%s%s", SDCARD_PATH, GetDsmWorkPath());

            *output = (uint8 *)filenamebuf;
            *output_len = strlen(filenamebuf);
            break;
        }

        case 'X':  //进入DSM根目录
        case 'x': {
            dsmRestoreRootDir();
            break;
        }

        default: {
            input_len = strlen((char *)input);

            if (input_len > DSM_MAX_FILE_LEN) return MR_FAILED;

            if (input_len <= 3) {  // c:/
                SetDsmWorkPath("");
            } else {  // c:/app
                LOG("input:%s", input);

                memset(filenamebuf, 0, sizeof(filenamebuf));
                // sprintf(filenamebuf, "%s", input+3);
                // formatPathString(filenamebuf);
                // strcat(filenamebuf, "/");

                if (showApiLog)
                    LOG("dsm workpath has change to:%s", filenamebuf);

                sprintf(filenamebuf, "%s", input);
                SetDsmWorkPath(filenamebuf);
            }

            break;
        }
    }

    return MR_SUCCESS;
}

/****************************************************************************
 函数名:char* get_filename(char* outputbuf,const char *filename)
 描  述:由相对路径的文件名接成绝对路径名
 参  数:filename:相对路径的文件名
 outputbuf:转换好的绝对路径文件名(outputbuf的大小要大于等于DSM_MAX_FILE_LEN *
 ENCODING_LENGTH) 返  回:绝对路径的文件名
 ****************************************************************************/
char *get_filename(char *outputbuf, const char *filename) {
    char *p = outputbuf;

    sprintf(p, "%s%s%s", SDCARD_PATH, GetDsmWorkPath(), filename);

    // if (strlen((char *) GetDsmWorkPath()) == 0) //根目录 /
    //	p += sprintf(p, "/mnt/sdcard");
    // else
    //	p += sprintf(p, "/mnt/sdcard/%s", GetDsmWorkPath());

    // if (strlen(filename) > 0)
    //	p += sprintf(p, "/%s", filename);
    LOG("get_filename():%s", outputbuf);
    return outputbuf;
}
/****************************************************************************
 函数名:MR_FILE_HANDLE mr_open(const char* filename,  uint32 mode)
 描  述:打开一个文件
 参  数:filename:文件名
 mode:打开方式
 返  回:文件句柄
 ****************************************************************************/
///
MR_FILE_HANDLE mr_open(const char *filename, uint32 mode) {
    int f;
    int new_mode = 0;
    char *fullpathname[DSM_MAX_FILE_LEN] = {0};

    if (mode & MR_FILE_RDONLY) new_mode = O_RDONLY;
    if (mode & MR_FILE_WRONLY) new_mode = O_WRONLY;
    if (mode & MR_FILE_RDWR) new_mode = O_RDWR;
    if (mode & MR_FILE_CREATE) new_mode |= O_CREAT;
    // if(mode & MR_FILE_COMMITTED)
    //	new_mode |= FS_COMMITTED;
    // if(mode & MR_FILE_SHARD)
    //	new_mode  |= FS_OPEN_SHARED;
    get_filename((char *)fullpathname, filename);
    if (new_mode & O_CREAT) {
        f = open((char *)fullpathname, new_mode | O_RAW, S_IRWXU | S_IRWXG | S_IRWXO);
    } else {
        f = open((char *)fullpathname, new_mode | O_RAW);
    }
    if (f < 0) {
        LOG("mr_open fail.");
        return MR_FAILED;
    }

    return (MR_FILE_HANDLE)f;
}

/****************************************************************************
 函数名:int32 mr_close(MR_FILE_HANDLE f)
 描  述:关闭一个文件
 参  数:f:要关闭得文件得句柄
 返  回:NR_SUCCESS,MR_FAILED
 ****************************************************************************/
int32 mr_close(MR_FILE_HANDLE f) {
    int ret = close(f);
    if (ret == -1) {
        LOG("mr_close fail.");
        return MR_FAILED;
    }

    return MR_SUCCESS;
}

/****************************************************************************
 函数名:int32 mr_read(MR_FILE_HANDLE f,void *p,uint32 l)
 描  述:读取文件中得数据
 参  数:f:要读得文件得句柄
 p:缓存得指针
 l:缓存得大小
 返  回:
 ****************************************************************************/
int32 mr_read(MR_FILE_HANDLE f, void *p, uint32 l) {
    size_t readnum;

    readnum = read(f, p, (size_t)l);

    if (readnum < 0) {
        LOG("mr_read fail.");
        return MR_FAILED;
    }

    return (int32)readnum;
}

/****************************************************************************
 函数名:int32 mr_write(MR_FILE_HANDLE f,void *p,uint32 l)
 描  述:往一个文件中写入数据
 参  数:f:要写入得文件得句柄
 p:缓存得指针
 l:要写入数据得大小
 返  回:
 ****************************************************************************/
int32 mr_write(MR_FILE_HANDLE f, void *p, uint32 l) {
    size_t writenum = 0;

    writenum = write(f, p, (size_t)l);

    if (writenum < 0) {
        LOG("mr_write fail.");
        return MR_FAILED;
    }

    return writenum;
}

/****************************************************************************
 函数名:int32 mr_seek(MR_FILE_HANDLE f, int32 pos, int method)
 描  述:偏移文件读写指针
 参  数:f     :文件句柄
 pos   :要偏移得数量
 method:偏移起算的位置
 返  回:MR_SUCCESS,MR_FAILED
 ****************************************************************************/
int32 mr_seek(MR_FILE_HANDLE f, int32 pos, int method) {
    off_t ret;

    ret = lseek(f, (off_t)pos, method);

    if (ret < 0)
        return MR_FAILED;
    else
        return MR_SUCCESS;
}

/****************************************************************************
 函数名:int32 mr_info(const char* filename)
 描  述:得到一个文件信息
 参  数:filename
 返  回:是文件:MR_IS_FILE
 是目录:MR_IS_DIR
 无效:  MR_IS_INVALID
 ****************************************************************************/
int32 mr_info(const char *filename) {
    char fullpathname[DSM_MAX_FILE_LEN] = {0};
    struct stat s1;
    int ret;

    //返回 0 成功
    ret = stat(get_filename(fullpathname, filename), &s1);

    if (ret != 0) return MR_IS_INVALID;

    if (S_ISDIR(s1.st_mode))
        return MR_IS_DIR;
    else if (S_ISREG(s1.st_mode))
        return MR_IS_FILE;
    else
        return MR_IS_INVALID;
}

/****************************************************************************
 函数名:int32 mr_remove(const char* filename)
 描  述:删除一个文件
 参  数:filename:要被删除的文件的文件名
 返  回:MR_SUCCESS,MR_FAILED
 ****************************************************************************/
int32 mr_remove(const char *filename) {
    char fullpathname[DSM_MAX_FILE_LEN] = {0};
    int ret;

    ret = remove(get_filename(fullpathname, filename));

    if (ret == 0)
        return MR_SUCCESS;
    else
        return MR_FAILED;
}

/****************************************************************************
 函数名:int32 mr_rename(const char* oldname, const char* newname)
 描  述:对一个文件进行重命名
 参  数:oldname:原文件名
 newname:新文件名
 返  回:MR_SUCCESS,MR_FAILED
 ****************************************************************************/
int32 mr_rename(const char *oldname, const char *newname) {
    char fullpathname_1[DSM_MAX_FILE_LEN] = {0};
    char fullpathname_2[DSM_MAX_FILE_LEN] = {0};
    int ret;

    ret = rename(get_filename(fullpathname_1, oldname),
                 get_filename(fullpathname_2, newname));

    if (ret == 0)
        return MR_SUCCESS;
    else
        return MR_FAILED;
}

/****************************************************************************
 函数名:int32 mr_mkDir(const char* name)
 描  述:创建一个目录
 参  数:name:目录名
 返  回:MR_SUCCESS,MR_FAILED
 ****************************************************************************/
int32 mr_mkDir(const char *name) {
    char fullpathname[DSM_MAX_FILE_LEN] = {0};
    int ret;

#ifndef _WIN32
    ret = mkdir(get_filename(fullpathname, name), 0777);
#else
    ret = mkdir(get_filename(fullpathname, name));
#endif

    if (ret == 0)
        return MR_SUCCESS;
    else
        return MR_FAILED;
}

/****************************************************************************
 函数名:int32 mr_rmDir(const char* name)
 描  述:删除一个目录
 参  数:name:被删除的目录名
 返  回:MR_SUCCESS,MR_FAILED
 ****************************************************************************/
int32 mr_rmDir(const char *name) {
    char fullpathname[DSM_MAX_FILE_LEN] = {0};
    int ret;

    ret = rmdir(get_filename(fullpathname, name));

    if (ret == 0)
        return MR_SUCCESS;
    else
        return MR_FAILED;
}

/****************************************************************************
 函数名:MR_FILE_HANDLE mr_findStart(const char* name, char* buffer, uint32 len)
 描  述:初始化一个文件目录的搜索，并返回第一搜索。
 参  数:name	 :要搜索的目录名
 buffer:保存第一个搜索结果的buf
 len   :buf的大小
 返  回:成功:第一个搜索结果的句柄
 失败:MR_FAILED
 ****************************************************************************/
typedef struct {
    DIR *pDir;
} T_MR_SEARCHDIR, *PT_MR_SEARCHDIR;

MR_FILE_HANDLE mr_findStart(const char *name, char *buffer, uint32 len) {
    PT_MR_SEARCHDIR t = malloc(sizeof(T_MR_SEARCHDIR));
    char fullpathname[DSM_MAX_FILE_LEN] = {0};

    if (!t) return MR_FAILED;

    memset(t, 0, sizeof(T_MR_SEARCHDIR));
    memset(buffer, 0, len);
    t->pDir = opendir(get_filename(fullpathname, name));
    if (!t->pDir) {
        free(t);
        return MR_FAILED;
    }

    return (MR_FILE_HANDLE)t;
}

/****************************************************************************
 函数名:int32 mr_findGetNext(MR_FILE_HANDLE search_handle, char* buffer, uint32
 len) 描  述:搜索目录的下一个结果 参  数:search_handle :目录的句柄 buffer
 :存放搜索结果的buf len           :buf的大小 返  回:MR_SUCCESS,MR_FAILED
 ****************************************************************************/
int32 mr_findGetNext(MR_FILE_HANDLE search_handle, char *buffer, uint32 len) {
    PT_MR_SEARCHDIR t = (PT_MR_SEARCHDIR)search_handle;
    struct dirent *pDt;

    if (!t) return MR_FAILED;

    memset(buffer, 0, len);
    pDt = readdir(t->pDir);
    if (!pDt) return MR_FAILED;
    strcpy(buffer, pDt->d_name);

    return MR_SUCCESS;
}

/****************************************************************************
 函数名:int32 mr_findStop(MR_SEARCH_HANDLE search_handle)
 描  述:停止当前的搜索
 参  数:search_handle:搜索句柄
 返  回:MR_SUCCESS,MR_FAILED
 ****************************************************************************/
int32 mr_findStop(MR_SEARCH_HANDLE search_handle) {
    PT_MR_SEARCHDIR t = (PT_MR_SEARCHDIR)search_handle;

    if (!t) return MR_FAILED;

    closedir(t->pDir);
    free(t);

    return MR_SUCCESS;
}

/****************************************************************************
 函数名:int32 mr_ferrno(void)
 描  述:该函数用于调试使用，返回的是最后一次操作文件失败的错误信息，返回的错误
 信息具体含义与平台上使用的文件系统有关。
 参  数:无
 返  回:MR_SUCCESS,MR_FAILED
 ****************************************************************************/
int32 mr_ferrno(void) { return (int32)MR_FAILED; }

/****************************************************************************
 函数名:int32 mr_getLen(const char* filename)
 描  述:得到指定文件得大小
 参  数:filename:所指定得文件名
 返  回:成功返回文件大小
 失败返回:MR_FAILED
 ****************************************************************************/
int32 mr_getLen(const char *filename) {
    char fullpathname[DSM_MAX_FILE_LEN] = {0};
    struct stat s1;
    int ret;

    ret = stat(get_filename(fullpathname, filename), &s1);

    if (ret != 0) return -1;

    return s1.st_size;
}

/****************************************************************************
 函数名:int32 mr_exit(void)
 描  述:dsm退出通知主机
 参  数:无
 返  回:无
 ****************************************************************************/
int32 mr_exit(void) {
    exit(0);

    // StopTimer(DSM_TIMER_MAX);
    // ClearAllKeyHandler();
    // StartTimer(DSM_TIMER_MAX, 50, ExitDsmScr);

    return MR_SUCCESS;
}

// 2012/9/11
void mr_md5_init(md5_state_t *pms) {}

void mr_md5_append(md5_state_t *pms, const md5_byte_t *data, int nbytes) {}

void mr_md5_finish(md5_state_t *pms, md5_byte_t digest[16]) {}

int32 mr_load_sms_cfg(void) {
    if (showApiLog) LOG("mr_load_sms_cfg");
    return MR_FAILED;
}

int32 mr_save_sms_cfg(int32 f) {
    if (showApiLog) LOG("mr_save_sms_cfg(f:%d)", f);
    return MR_FAILED;
}

void mr_drawBitmap(uint16 *bmp, int16 x, int16 y, uint16 w, uint16 h) {
    // if(showApiLog) printf("mr_drawBitmap(bmp:0x%08x, x:%d, y:%d, w:%d,
    // h:%d)", bmp, x, y, w, h);
}

const char *mr_getCharBitmap(uint16 ch, uint16 fontSize, int *width,
                             int *height) {
    int32 w, h;

    // if(showApiLog) printf("mr_getCharBitmap(ch:%04x)", ch);

    tsf_charWidthHeight(ch, &w, &h);
    if (width) *width = w;
    if (height) *height = h;
    //第一个字节 字宽 第二个字节 字字节数
    return (char *)(tsf_getCharBitmap(ch) + 2);
}

int32 mr_DispUpEx(int16 x, int16 y, uint16 w, uint16 h) { return MR_SUCCESS; }

void mr_DrawPoint(int16 x, int16 y, uint16 nativecolor) {
    uint16 *p = w_getScreenBuffer();
    int32 w, h;

    mr_getScreenSize(&w, &h);
    if (x < 0 || y < 0 || x > w - 1 || y > h - 1) return;
    *(p + w * y + x) = nativecolor;
}

void mr_DrawBitmap(uint16 *p, int16 x, int16 y, uint16 w, uint16 h, uint16 rop,
                   uint16 transcoler, int16 sx, int16 sy, int16 mw) {}

void mr_DrawBitmapEx(mr_bitmapDrawSt *srcbmp, mr_bitmapDrawSt *dstbmp, uint16 w,
                     uint16 h, mr_transMatrixSt *pTrans, uint16 transcoler) {}

void mr_DrawRect(int16 sx, int16 sy, int16 w, int16 h, uint8 cr, uint8 cg,
                 uint8 cb) {
}

int32 mr_DrawText(char *pcText, int16 x, int16 y, uint8 r, uint8 g, uint8 b,
                  int is_unicode, uint16 font) {
    mr_colourSt c;

    c.r = r, c.g = g, c.b = b;
    if (!is_unicode) {
        uint8 *out = (uint8 *)mr_c2u(pcText, NULL, NULL);
        tsf_drawText(out, x, y, c);
        mr_free(out, 0);
    } else {
        tsf_drawText((uint8 *)pcText, x, y, c);
    }

    // if(showApiLog) printf("mr_DrawText(text:%s, x:%d, y:%d, )",
    //	pcText, x, y);

    return MR_SUCCESS;
}

int mr_BitmapCheck(uint16 *p, int16 x, int16 y, uint16 w, uint16 h,
                   uint16 transcoler, uint16 color_check) {
    return MR_SUCCESS;
}

int mr_wstrlen(char *str) {
    int lenth = 0;
    unsigned char *ss = (unsigned char *)str;

    while (((*ss << 8) + *(ss + 1)) != 0) {
        lenth += 2;
        ss += 2;
    }

    return lenth;
}

int32 mr_DrawTextEx(char *pcText, int16 x, int16 y, mr_screenRectSt rect,
                    mr_colourSt colorst, int flag, uint16 font) {
    int f = 0;

    if (flag & DRAW_TEXT_EX_IS_AUTO_NEWLINE)
        f |= TSF_AUTONEWLINE | TSF_CRLFNEWLINE;

    if (flag & DRAW_TEXT_EX_IS_UNICODE) {
        tsf_drawTextLeft((uint8 *)pcText, x, y, rect, colorst, f);
    } else {
        uint8 *out = (uint8 *)mr_c2u(pcText, NULL, NULL);
        tsf_drawTextLeft((uint8 *)out, x, y, rect, colorst, f);
        mr_free(out, 0);
    }

    return MR_SUCCESS;
}

int32 mr_EffSetCon(int16 x, int16 y, int16 w, int16 h, int16 perr, int16 perg,
                   int16 perb) {
    return MR_SUCCESS;
}

int32 mr_TestCom(int32 L, int input0, int input1) {
    if (showApiLog) LOG("mr_TestCom(l%d, p0:%d, p1:%d)", L, input0, input1);
    return MR_SUCCESS;
}

int32 mr_TestCom1(int32 L, int input0, char *input1, int32 len) {
    if (showApiLog)
        LOG("mr_TestCom1(l%d, p0:%d, p1:%s, lp1:%d)", L, input0, input1, len);
    return MR_SUCCESS;
}

uint16 *mr_c2u(char *cp, int32 *err, int32 *size) {
    int l = strlen(cp) * 2 + 2;
    char *out = malloc(l);
    l = gbToUCS2BE((unsigned char *)cp, (unsigned char *)out, l);
    if (size) *size = l;
    return (uint16 *)out;
}

int32 mr_div(int32 a, int32 b) { return a / b; }

int32 mr_mod(int32 a, int32 b) { return a % b; }

int32 mr_unzip(uint8 *inputbuf, int32 inputlen, uint8 **outputbuf,
               int32 *outputlen) {
    int ret;
    uint8 *data_org = inputbuf;
    uint8 *data_out;
    uint32 size_out;

    if (!inputbuf || inputlen <= 0 || !outputbuf || inputbuf[0] != 0x1f ||
        inputbuf[1] != 0x8b)
        return MR_FAILED;

    size_out = *(uint32 *)(data_org + inputlen - 4);
    data_out = mr_malloc(size_out);

    ret = ungzipdata(data_out, &size_out, data_org, inputlen);
    if (Z_OK == ret) {
        *outputbuf = data_out;
        if (outputlen) *outputlen = size_out;

        return MR_SUCCESS;
    } else {
        mr_free(data_out, size_out);
    }

    return MR_FAILED;
}

uint32 mrc_updcrc(uint8 *s, uint32 n) { return 0; }

void *mr_readFile(const char *filename, int *filelen, int lookfor) {
    int32 len;
    uint8 *data = mr_readFileFromMrp(filename, &len, lookfor);
    if (filelen) *filelen = len;
    return (void *)data;
}

int32 mr_startShake(int32 ms) { return MR_FAILED; }
int32 mr_stopShake() { return MR_FAILED; }
int32 mr_playSound(int type, const void *data, uint32 dataLen, int32 loop) {
    return MR_FAILED;
}
int32 mr_stopSound(int type) { return MR_FAILED; }
int32 mr_sendSms(char *pNumber, char *pContent, int32 encode) {
    return MR_FAILED;
}
void mr_call(char *number) {}
int32 mr_getNetworkID(void) { return MR_FAILED; }
void mr_connectWAP(char *wap) {}
int32 mr_menuCreate(const char *title, int16 num) { return MR_FAILED; }
int32 mr_menuSetItem(int32 menu, const char *text, int32 index) {
    return MR_FAILED;
}
int32 mr_menuShow(int32 menu) { return MR_FAILED; }
int32 mr_menuSetFocus(int32 menu, int32 index) { return MR_FAILED; }
int32 mr_menuRelease(int32 menu) { return MR_FAILED; }
int32 mr_menuRefresh(int32 menu) { return MR_FAILED; }
int32 mr_dialogCreate(const char *title, const char *text, int32 type) {
    return MR_FAILED;
}
int32 mr_dialogRelease(int32 dialog) { return MR_FAILED; }
int32 mr_dialogRefresh(int32 dialog, const char *title, const char *text,
                       int32 type) {
    return MR_FAILED;
}

int32 mr_textCreate(const char *title, const char *text, int32 type) {
    return MR_FAILED;
}
int32 mr_textRelease(int32 text) { return MR_FAILED; }
int32 mr_textRefresh(int32 handle, const char *title, const char *text) {
    return MR_FAILED;
}

int32 mr_editCreate(const char *title, const char *text, int32 type,
                    int32 max_size) {
    return MR_FAILED;
}
int32 mr_editRelease(int32 edit) { return MR_FAILED; }
const char *mr_editGetText(int32 edit) { return NULL; }
int32 mr_winCreate(void) { return MR_FAILED; }
int32 mr_winRelease(int32 win) { return MR_FAILED; }

int32 mr_initNetwork(MR_INIT_NETWORK_CB cb, const char *mode) {
    return MR_FAILED;
}
int32 mr_closeNetwork(void) { return MR_FAILED; }
int32 mr_getHostByName(const char *name, MR_GET_HOST_CB cb) {
    return MR_FAILED;
}
int32 mr_socket(int32 type, int32 protocol) { return MR_FAILED; }
int32 mr_connect(int32 s, int32 ip, uint16 port, int32 type) {
    return MR_FAILED;
}
int32 mr_closeSocket(int32 s) { return MR_FAILED; }
int32 mr_recv(int32 s, char *buf, int len) { return MR_FAILED; }
int32 mr_recvfrom(int32 s, char *buf, int len, int32 *ip, uint16 *port) {
    return MR_FAILED;
}
int32 mr_send(int32 s, const char *buf, int len) { return MR_FAILED; }
int32 mr_sendto(int32 s, const char *buf, int len, int32 ip, uint16 port) {
    return MR_FAILED;
}