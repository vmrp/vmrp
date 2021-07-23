#include "../include/dsm.h"

int32 mrc_init(void) {
    return VMRP_VER;
}

int32 mrc_exitApp(void) {
    return MR_SUCCESS;
}

int32 mrc_event(int32 code, int32 param0, int32 param1) {
    switch (code) {
        case DSM_INIT:
            return dsm_init((DSM_REQUIRE_FUNCS *)param0);
        case MR_START_DSM: {
            start_t *p = (start_t *)param0;
            return mr_start_dsm(p->filename, p->ext, p->entry);
        }
        case MR_PAUSEAPP:
            return mr_pauseApp();
        case MR_RESUMEAPP:
            return mr_resumeApp();
        case MR_TIMER:
            return mr_timer();
        case MR_EVENT: {
            event_t *p = (event_t *)param0;
            return mr_event(p->code, p->p0, p->p1);
        }
        default:
            break;
    }
    return MR_SUCCESS;
}

int32 mrc_pause() {
    return MR_SUCCESS;
}

int32 mrc_resume() {
    return MR_SUCCESS;
}

int32 mrc_extRecvAppEventEx(int32 code, int32 param0, int32 param1) {
    return MR_SUCCESS;
}

int32 mrc_extRecvAppEvent(int32 app, int32 code, int32 param0, int32 param1) {
    return MR_SUCCESS;
}
