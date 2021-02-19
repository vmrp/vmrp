#ifndef _DSM_H
#define _DSM_H

#include "types.h"

#define SCREEN_WIDTH 240
#define SCREEN_HEIGHT 320

#define VMRP_VER 20210101

#ifdef LOG
#undef LOG
#endif

#ifdef DEBUG
#define LOG(format, ...) printf("   -> bridge: " format, ##__VA_ARGS__)
#define LOGI(format, ...) printf("   -> LOGI: " format, ##__VA_ARGS__)
#define LOGE(format, ...) printf("   -> LOGE: " format, ##__VA_ARGS__)
#define LOGW(format, ...) printf("   -> LOGE: " format, ##__VA_ARGS__)
#else
#define LOG(format, ...)
#define LOGI(format, ...)
#define LOGE(format, ...)
#define LOGW(format, ...)
#endif

// 需要平台实现的函数
typedef struct {
    void (*test)(void);
    void (*log)(char *msg);  // msg末尾不带\n
    void (*exit)(void);
    void (*srand)(uint32 seed);
    int32 (*rand)(void);
    int32 (*mem_get)(char **mem_base, uint32 *mem_len);
    int32 (*mem_free)(char *mem, uint32 mem_len);
    int32 (*timerStart)(uint16 t);
    int32 (*timerStop)(void);
    uint32 (*get_uptime_ms)(void);
    int32 (*getDatetime)(mr_datetime *datetime);
    int32 (*sleep)(uint32 ms);
    int32 (*open)(const char *filename, uint32 mode);
    int32 (*close)(int32 f);
    int32 (*read)(int32 f, void *p, uint32 l);
    int32 (*write)(int32 f, void *p, uint32 l);
    int32 (*seek)(int32 f, int32 pos, int method);
    int32 (*info)(const char *filename);
    int32 (*remove)(const char *filename);
    int32 (*rename)(const char *oldname, const char *newname);
    int32 (*mkDir)(const char *path);
    int32 (*rmDir)(const char *path);
    int32 (*opendir)(const char *name);
    char *(*readdir)(int32 f);
    int32 (*closedir)(int32 f);
    int32 (*getLen)(const char *filename);
    void (*drawBitmap)(uint16 *bmp, int16 x, int16 y, uint16 w, uint16 h);
    int32 (*mr_initNetwork)(MR_INIT_NETWORK_CB cb, const char *mode);
    int32 (*mr_closeNetwork)();
    int32 (*mr_getHostByName)(const char *ptr, MR_GET_HOST_CB cb);
    int32 (*mr_socket)(int32 type, int32 protocol);
    int32 (*mr_connect)(int32 s, int32 ip, uint16 port, int32 type);
    int32 (*mr_getSocketState)(int32 s);
    int32 (*mr_closeSocket)(int32 s);
    int32 (*mr_recv)(int32 s, char *buf, int len);
    int32 (*mr_send)(int32 s, const char *buf, int len);
    int32 (*mr_recvfrom)(int32 s, char *buf, int len, int32 *ip, uint16 *port);
    int32 (*mr_sendto)(int32 s, const char *buf, int len, int32 ip, uint16 port);
    int32 (*mr_startShake)(int32 ms);
    int32 (*mr_stopShake)();
    int32 (*mr_playSound)(int type, const void *data, uint32 dataLen, int32 loop);
    int32 (*mr_stopSound)(int type);
    int32 (*mr_dialogCreate)(const char *title, const char *text, int32 type);
    int32 (*mr_dialogRelease)(int32 dialog);
    int32 (*mr_dialogRefresh)(int32 dialog, const char *title, const char *text, int32 type);
    int32 (*mr_textCreate)(const char *title, const char *text, int32 type);
    int32 (*mr_textRelease)(int32 text);
    int32 (*mr_textRefresh)(int32 handle, const char *title, const char *text);
    int32 (*mr_editCreate)(const char *title, const char *text, int32 type, int32 max_size);
    int32 (*mr_editRelease)(int32 edit);
    const char *(*mr_editGetText)(int32 edit);

} DSM_REQUIRE_FUNCS;

// 平台可以调用的函数
typedef struct {
    int32 version;
    int32 (*mr_start_dsm)(char *filename, char *ext, char *entry);
    int32 (*mr_pauseApp)(void);
    int32 (*mr_resumeApp)(void);
    int32 (*mr_timer)(void);
    int32 (*mr_event)(int16 type, int32 param1, int32 param2);
} DSM_EXPORT_FUNCS;

DSM_EXPORT_FUNCS *dsm_init(DSM_REQUIRE_FUNCS *inFuncs);

#endif
