#include "../include/dsm.h"

extern int (*MR_SPRINTF)(char *s, const char *format, ...);
#define mrc_sprintf MR_SPRINTF
int32 mrc_drawText(char *pcText, int16 x, int16 y, uint8 r, uint8 g, uint8 b, int is_unicode, uint16 font);
void mrc_clearScreen(int32 r, int32 g, int32 b);
extern void *mrc_malloc(int size);
extern void mrc_free(void *address);
int32 mrc_timerCreate(void);
void mrc_timerDelete(int32 t);
void mrc_timerStop(int32 t);
typedef void (*mrc_timerCB)(int32 data);
int32 mrc_timerStart(int32 t, int32 time, int32 data, mrc_timerCB f, int32 loop);
int32 mrc_getDatetime(mr_datetime *datetime);
int32 mrc_getUptime(void);
int32 mrc_sleep(uint32 ms);
int32 mrc_read(int32 f, void *p, uint32 l);
int32 mrc_open(const char *filename, uint32 mode);
int32 mrc_close(int32 f);
int32 mrc_write(int32 f, void *p, uint32 l);
int32 mrc_fileState(const char *filename);
int32 mrc_rename(const char *oldname, const char *newname);
int32 mrc_mkDir(const char *name);
int32 mrc_rmDir(const char *name);
int32 mrc_seek(int32 f, int32 pos, int method);
int32 mrc_remove(const char *filename);
void mrc_exit(void);
extern void (*mrc_printf)(const char *format, ...);
uint32 mrc_getMemoryRemain(void);
void *mrc_malloc(int size);
void mrc_free(void *address);
void mrc_drawPoint(int16 x, int16 y, uint16 nativecolor);
void mrc_sand(uint32 seed);
uint32 mrc_rand(void);
int32 mrc_getLen(const char *filename);
int32 mrc_getHostByName(const char *name, MR_GET_HOST_CB cb);
int32 mrc_initNetwork(MR_INIT_NETWORK_CB cb, const char *mode);
int32 mrc_closeNetwork(void);
int32 mrc_socket(int32 type, int32 protocol);
int32 mrc_connect(int32 s, int32 ip, uint16 port, int32 type);
int32 mrc_getSocketState(int32 s);
int32 mrc_closeSocket(int32 s);
int32 mrc_recv(int32 s, char *buf, int len);
int32 mrc_send(int32 s, const char *buf, int len);
int32 mrc_recvfrom(int32 s, char *buf, int len, int32 *ip, uint16 *port);
int32 mrc_sendto(int32 s, const char *buf, int len, int32 ip, uint16 port);
int32 mrc_startShake(int32 ms);
int32 mr_playSoundEx(int type, const void *data, uint32 dataLen, int32 loop);
int32 mr_stopSoundEx(int type);
int32 mrc_dialogCreate(const char *title, const char *text, int32 type);
int32 mrc_dialogRelease(int32 dialog);
int32 mrc_dialogRefresh(int32 dialog, const char *title, const char *text, int32 type);
int32 mrc_textCreate(const char *title, const char *text, int32 type);
int32 mrc_textRelease(int32 text);
int32 mrc_textRefresh(int32 handle, const char *title, const char *text);
int32 mrc_editCreate(const char *title, const char *text, int32 type, int32 max_size);
int32 mrc_editRelease(int32 edit);
const char *mrc_editGetText(int32 edit);
int32 mrc_findStart(const char *name, char *buffer, uint32 len);
int32 mrc_findGetNext(int32 h, char *buffer, uint32 len);
int32 mrc_findStop(int32 h);
void mrc_refreshScreen(int16 x, int16 y, uint16 w, uint16 h);

///////////////////////////////////////////////////////////////////////////////////////////////////////
DSM_REQUIRE_FUNCS *funcs;
int32 timer;

void show(char *str) {
    mrc_clearScreen(0, 0, 0);
    mrc_drawText(str, 0, 0, 255, 255, 0, 0, 0);
    mrc_refreshScreen(0, 0, 240, 320);
    mrc_sleep(1000);
}

void vmrp_drawBitmap(uint16 *data, int16 x, int16 y, uint16 w, uint16 h) {
    int32 i, j, xx, yy;
    uint16 color;
    for (i = 0; i < w; i++) {
        for (j = 0; j < h; j++) {
            xx = x + i;
            yy = y + j;
            if (xx < 0 || yy < 0 || xx >= SCREEN_WIDTH || yy >= SCREEN_HEIGHT) {
                continue;
            }
            color = *(data + (xx + yy * SCREEN_WIDTH));
            mrc_drawPoint(xx, yy, color);
            mrc_refreshScreen(xx, yy, 1, 1);  //可优化
        }
    }
}

void vmrp_log(char *msg) {
    mrc_printf("%s", msg);
}

int32 vmrp_stopShake() {
    return MR_SUCCESS;
}

static void *getHostByNameUserData;
static NETWORK_CB getHostByNameCb;

static int32 vmrp_get_host_cb(int32 ip) {
    int32 ret = getHostByNameCb(ip, getHostByNameUserData);
    getHostByNameCb = NULL;
    getHostByNameUserData = NULL;
    return ret;
}

int32 vmrp_getHostByName(const char *ptr, NETWORK_CB cb, void *userData) {
    if ((getHostByNameUserData != NULL) || (getHostByNameCb != NULL)) {
        mrc_printf("err vmrp_getHostByName");
        return MR_FAILED;
    }
    getHostByNameUserData = userData;
    getHostByNameCb = cb;
    return mrc_getHostByName(ptr, vmrp_get_host_cb);
}

static void *initNetWorkUserData;
static NETWORK_CB initNetWorkCb;

static int32 vmrp_init_network_cb(int32 result) {
    int32 ret = initNetWorkCb(result, initNetWorkUserData);
    initNetWorkCb = NULL;
    initNetWorkUserData = NULL;
    return ret;
}

int32 vmrp_initNetwork(NETWORK_CB cb, const char *mode, void *userData) {
    if ((initNetWorkUserData != NULL) || (initNetWorkCb != NULL)) {
        mrc_printf("err vmrp_initNetwork");
        return MR_FAILED;
    }
    initNetWorkUserData = userData;
    initNetWorkCb = cb;
    return mrc_initNetwork(vmrp_init_network_cb, mode);
}

int32 vmrp_mem_get(char **mem_base, uint32 *mem_len) {
    int32 len = mrc_getMemoryRemain();
    int32 step = 1024 * 10;
    do {
        len -= step;
        *mem_base = mrc_malloc(len);
        if (*mem_base != NULL) {
            char buf[128];
            mrc_sprintf(buf, "mem_get:%d", len);
            show(buf);
            *mem_len = len;
            return MR_SUCCESS;
        }
    } while (len > step);
    show("mem_get err");
    return MR_FAILED;
}

int32 vmrp_mem_free(char *mem, uint32 mem_len) {
    mrc_free(mem);
    return MR_SUCCESS;
}

void timerCB(int32 data) {
    mr_timer();
}

int32 vmrp_timerStart(uint16 t) {
    return mrc_timerStart(timer, t, 0, timerCB, 0);
}

int32 vmrp_timerStop(void) {
    mrc_timerStop(timer);
    return MR_SUCCESS;
}

int32 mrc_init(void) {
    initNetWorkCb = NULL;
    initNetWorkUserData = NULL;
    getHostByNameCb = NULL;
    getHostByNameUserData = NULL;

    funcs = mrc_malloc(sizeof(DSM_REQUIRE_FUNCS));
    timer = mrc_timerCreate();

    funcs->log = vmrp_log;
    funcs->exit = mrc_exit;
    funcs->srand = mrc_sand;
    funcs->rand = (int32(*)())mrc_rand;
    funcs->mem_get = vmrp_mem_get;
    funcs->mem_free = vmrp_mem_free;
    funcs->timerStart = vmrp_timerStart;
    funcs->timerStop = vmrp_timerStop;
    funcs->get_uptime_ms = (uint32(*)())mrc_getUptime;
    funcs->getDatetime = mrc_getDatetime;
    funcs->sleep = mrc_sleep;
    funcs->open = mrc_open;
    funcs->close = mrc_close;
    funcs->read = mrc_read;
    funcs->write = mrc_write;
    funcs->seek = mrc_seek;
    funcs->info = mrc_fileState;
    funcs->remove = mrc_remove;
    funcs->rename = mrc_rename;
    funcs->mkDir = mrc_mkDir;
    funcs->rmDir = mrc_rmDir;
#ifdef USE_FINDDIR
    funcs->mrc_findStart = mrc_findStart;
    funcs->mrc_findGetNext = mrc_findGetNext;
    funcs->mrc_findStop = mrc_findStop;
#else
    // int32 (*opendir)(const char *name);
    // char *(*readdir)(int32 f);
    // int32 (*closedir)(int32 f);
#endif
    funcs->getLen = mrc_getLen;
    funcs->drawBitmap = vmrp_drawBitmap;
    funcs->getHostByName = vmrp_getHostByName;
    funcs->initNetwork = vmrp_initNetwork;
    funcs->mr_closeNetwork = mrc_closeNetwork;
    funcs->mr_socket = mrc_socket;
    funcs->mr_connect = mrc_connect;
    funcs->mr_getSocketState = mrc_getSocketState;
    funcs->mr_closeSocket = mrc_closeSocket;
    funcs->mr_recv = mrc_recv;
    funcs->mr_send = mrc_send;
    funcs->mr_recvfrom = mrc_recvfrom;
    funcs->mr_sendto = mrc_sendto;
    funcs->mr_startShake = mrc_startShake;
    funcs->mr_stopShake = vmrp_stopShake;
    funcs->mr_playSound = mr_playSoundEx;
    funcs->mr_stopSound = mr_stopSoundEx;
    funcs->mr_dialogCreate = mrc_dialogCreate;
    funcs->mr_dialogRelease = mrc_dialogRelease;
    funcs->mr_dialogRefresh = mrc_dialogRefresh;
    funcs->mr_textCreate = mrc_textCreate;
    funcs->mr_textRelease = mrc_textRelease;
    funcs->mr_textRefresh = mrc_textRefresh;
    funcs->mr_editCreate = mrc_editCreate;
    funcs->mr_editRelease = mrc_editRelease;
    funcs->mr_editGetText = mrc_editGetText;
    funcs->flags = 0;
    dsm_init(funcs);
    {
        uint32 len = mrc_getMemoryRemain();
        char buf[1024];
        mrc_sprintf(buf, "mem left:%d", len);
        show(buf);
    }
    return mr_start_dsm("start.mrp", "start.mr", NULL);
}

int32 mrc_exitApp(void) {
    return MR_SUCCESS;
}

int32 mrc_event(int32 code, int32 p0, int32 p1) {
    // return mr_event(code, p0, p1);
    return MR_SUCCESS;
}

int32 mrc_pause() {
    return mr_pauseApp();
}

int32 mrc_resume() {
    return mr_resumeApp();
}

int32 mrc_extRecvAppEventEx(int32 code, int32 param0, int32 param1) {
    return MR_SUCCESS;
}

int32 mrc_extRecvAppEvent(int32 app, int32 code, int32 param0, int32 param1) {
    return MR_SUCCESS;
}
