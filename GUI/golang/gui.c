#include "gui.h"
#include "../../header/bridge.h"
#include "../../header/fileLib.h"
#include "../../header/vmrp.h"

void guiSetPixel(int32_t x, int32_t y, uint16_t color) {
    setPixel(x, y, PIXEL565R(color), PIXEL565G(color), PIXEL565B(color));
}

void guiRefreshScreen(int32_t x, int32_t y, uint32_t w, uint32_t h) {
    // todo
    refresh();
}

static uc_engine *uc;

int init() {
    listMrpFiles("asm.mrp");

    uc = initVmrp();
    if (uc == NULL) {
        printf("initVmrp() fail.\n");
        return 1;
    }

    bridge_mr_init(uc);

    // bridge_mr_pauseApp(uc);
    // bridge_mr_resumeApp(uc);

    // mrc_exitApp() 可能由MR_EVENT_EXIT event之后自动调用
    // bridge_mr_event(uc, MR_EVENT_EXIT, 0, 0);

    // freeVmrp(uc);
    // printf("exit.\n");
    return 0;
}

void event(int code, int p1, int p2) {
    if (uc) {
        bridge_mr_event(uc, code, p1, p2);
    }
    // switch (code) {
    //     case MOUSE_DOWN:
    //         printf("MOUSE_DOWN x:%d y:%d\n", p1, p2);
    //         break;
    //     case MOUSE_UP:
    //         printf("MOUSE_UP x:%d y:%d\n", p1, p2);
    //         break;
    //     case MOUSE_MOVE:
    //         printf("MOUSE_MOVE x:%d y:%d\n", p1, p2);
    //         break;
    // }
    // setPixel(p1, p2, 255, 255, 0);
    // refresh();
}
