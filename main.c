#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "./header/bridge.h"
#include "./header/fileLib.h"
#include "./header/vmrp.h"

#ifdef _WIN32
// #ifdef __x86_64__
// #include "./windows/SDL2-2.0.10/x86_64-w64-mingw32/include/SDL2/SDL.h"
// #elif __i386__
#include "./windows/SDL2-2.0.10/i686-w64-mingw32/include/SDL2/SDL.h"
// #endif
#else
#include <SDL2/SDL.h>
#endif

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#endif

#define MOUSE_DOWN 2
#define MOUSE_UP 3
#define MOUSE_MOVE 12

// http://wiki.libsdl.org/Tutorials
// http://lazyfoo.net/tutorials/SDL/index.php

static SDL_TimerID timeId = 0;
static SDL_Window *window;
static uc_engine *uc;
static void (*eventFunc)(int code, int p1, int p2);

void guiDrawBitmap(uint16_t *bmp, int32_t x, int32_t y, int32_t w, int32_t h) {
    SDL_Surface *surface = SDL_GetWindowSurface(window);
    if (SDL_MUSTLOCK(surface)) {
        if (SDL_LockSurface(surface) != 0) printf("SDL_LockSurface err\n");
    }
    for (int32_t j = 0; j < h; j++) {
        for (int32_t i = 0; i < w; i++) {
            int32_t xx = x + i;
            int32_t yy = y + j;
            if (xx < 0 || yy < 0 || xx >= SCREEN_WIDTH || yy >= SCREEN_HEIGHT) {
                continue;
            }
            uint16_t color = *(bmp + (xx + yy * SCREEN_WIDTH));
            Uint32 *p = (Uint32 *)(((Uint8 *)surface->pixels) + surface->pitch * yy) + xx;
            *p = SDL_MapRGB(surface->format, PIXEL565R(color), PIXEL565G(color), PIXEL565B(color));
        }
    }
    if (SDL_MUSTLOCK(surface)) SDL_UnlockSurface(surface);
    if (SDL_UpdateWindowSurface(window) != 0)
        printf("SDL_UpdateWindowSurface err\n");
}

static void eventFuncV1(int code, int p1, int p2) {
    if (uc) {
        bridge_mr_event(uc, code, p1, p2);
    }
}

static void eventFuncV2(int code, int p1, int p2) {
    if (uc) {
        bridge_dsm_mr_event(uc, code, p1, p2);
    }
}

#ifdef __EMSCRIPTEN__
EMSCRIPTEN_KEEPALIVE
int32_t c_event(int code, int p1, int p2) {
    if (uc) {
        return bridge_dsm_mr_event(uc, code, p1, p2);
    }
    return MR_FAILED;
}

EMSCRIPTEN_KEEPALIVE
void setEventEnable(int v) {
    int state = v ? SDL_ENABLE : SDL_DISABLE;
    SDL_EventState(SDL_TEXTINPUT, state);
    SDL_EventState(SDL_KEYDOWN, state);
    SDL_EventState(SDL_KEYUP, state);
    SDL_EventState(SDL_MOUSEMOTION, state);
    SDL_EventState(SDL_MOUSEBUTTONDOWN, state);
    SDL_EventState(SDL_MOUSEBUTTONUP, state);
}
#endif

uint32_t th2(uint32_t interval, void *param) {
    SDL_RemoveTimer(timeId);
    timeId = 0;
    bridge_dsm_mr_timer(uc);
    return 0;
}

int32_t timerStart(uint16_t t) {
    if (!timeId) {
        timeId = SDL_AddTimer(t, th2, NULL);
    } else {
        SDL_RemoveTimer(timeId);
        timeId = SDL_AddTimer(t, th2, NULL);
    }
    return MR_SUCCESS;
}

int32_t timerStop() {
    if (timeId) {
        SDL_RemoveTimer(timeId);
        timeId = 0;
    }
    return MR_SUCCESS;
}

static int startMrp(char *f) {
    fileLib_init();
    eventFunc = eventFuncV1;

    uc = initVmrp(f);
    if (uc == NULL) {
        printf("initVmrp() fail.\n");
        return 1;
    }

    int32_t ret = bridge_mr_init(uc);
    if (ret > CODE_ADDRESS) {
        printf("bridge_mr_init:0x%X try vmrp loader\n", ret);

        if (bridge_dsm_init(uc, ret) == MR_SUCCESS) {
            eventFunc = eventFuncV2;
            printf("bridge_dsm_init success\n");
            dumpREG(uc);

            char *filename = "dsm_gm.mrp";
            // char *filename = "winmine.mrp";
            char *extName = "start.mr";
            // char *extName = "cfunction.ext";

            uint32_t ret = bridge_dsm_mr_start_dsm(uc, filename, extName, NULL);
            printf("bridge_dsm_mr_start_dsm('%s','%s',NULL): 0x%X\n", filename, extName, ret);
        }
    }

    // bridge_mr_pauseApp(uc);
    // bridge_mr_resumeApp(uc);

    // mrc_exitApp() 可能由MR_EVENT_EXIT event之后自动调用
    // bridge_mr_event(uc, MR_EVENT_EXIT, 0, 0);

    // freeVmrp(uc);
    // printf("exit.\n");
    return 0;
}

static void keyEvent(int16 type, SDL_Keycode code) {
    if (code >= SDLK_0 && code <= SDLK_9) {
        int32_t key = MR_KEY_0 + (code - SDLK_0);
        eventFunc(type, key, 0);  // 按键 0-9
        return;
    }
    switch (code) {
        case SDLK_KP_0:
            eventFunc(type, MR_KEY_0, 0);
            break;
        case SDLK_KP_1:
            eventFunc(type, MR_KEY_1, 0);
            break;
        case SDLK_KP_2:
            eventFunc(type, MR_KEY_2, 0);
            break;
        case SDLK_KP_3:
            eventFunc(type, MR_KEY_3, 0);
            break;
        case SDLK_KP_4:
            eventFunc(type, MR_KEY_4, 0);
            break;
        case SDLK_KP_5:
            eventFunc(type, MR_KEY_5, 0);
            break;
        case SDLK_KP_6:
            eventFunc(type, MR_KEY_6, 0);
            break;
        case SDLK_KP_7:
            eventFunc(type, MR_KEY_7, 0);
            break;
        case SDLK_KP_8:
            eventFunc(type, MR_KEY_8, 0);
            break;
        case SDLK_KP_9:
            eventFunc(type, MR_KEY_9, 0);
            break;
        case SDLK_KP_ENTER:
        case SDLK_RETURN:                       // 回车键
            eventFunc(type, MR_KEY_SELECT, 0);  // 确认/选择/ok
            break;
        case SDLK_EQUALS:                      // 等号
            eventFunc(type, MR_KEY_POUND, 0);  // 按键 #
            break;
        case SDLK_MINUS:                      // 减号
            eventFunc(type, MR_KEY_STAR, 0);  // 按键 *
            break;
        case SDLK_w:
        case SDLK_UP:  // 上
            eventFunc(type, MR_KEY_UP, 0);
            break;
        case SDLK_s:
        case SDLK_DOWN:  // 下
            eventFunc(type, MR_KEY_DOWN, 0);
            break;
        case SDLK_a:
        case SDLK_LEFT:  // 左
            eventFunc(type, MR_KEY_LEFT, 0);
            break;
        case SDLK_d:
        case SDLK_RIGHT:  // 右
            eventFunc(type, MR_KEY_RIGHT, 0);
            break;
        case SDLK_q:
        case SDLK_LEFTBRACKET:                    // 左中括号
            eventFunc(type, MR_KEY_SOFTLEFT, 0);  // 左功能键
            break;
        case SDLK_e:
        case SDLK_RIGHTBRACKET:                    // 右中括号
            eventFunc(type, MR_KEY_SOFTRIGHT, 0);  // 右功能键
            break;
        case SDLK_TAB:
            eventFunc(type, MR_KEY_SEND, 0);  // 接听键
            break;
        case SDLK_ESCAPE:
            eventFunc(type, MR_KEY_POWER, 0);  // 挂机键
            break;
        default:
            printf("key:%d\n", code);
            break;
    }
}

bool isMouseDown = false;
SDL_Keycode isKeyDown = SDLK_UNKNOWN;

void loop() {
    SDL_Event event;
    bool isLoop = true;

#if defined(__EMSCRIPTEN__)
#else
    while (isLoop)
#endif
    {
#if defined(__EMSCRIPTEN__)
        while (SDL_PollEvent(&event))
#else
        while (SDL_WaitEvent(&event))
#endif
        {
            if (event.type == SDL_QUIT) {
                isLoop = false;
                // emscripten_cancel_main_loop();
                break;
            }
            switch (event.type) {
                case SDL_KEYDOWN:
                    if (isKeyDown == SDLK_UNKNOWN) {
                        isKeyDown = event.key.keysym.sym;
                        keyEvent(MR_KEY_PRESS, event.key.keysym.sym);
                    }
                    break;
                case SDL_KEYUP:
                    if (isKeyDown == event.key.keysym.sym) {
                        isKeyDown = SDLK_UNKNOWN;
                        keyEvent(MR_KEY_RELEASE, event.key.keysym.sym);
                    }
                    break;
                case SDL_MOUSEMOTION:
                    if (isMouseDown) {
                        eventFunc(MR_MOUSE_MOVE, event.motion.x, event.motion.y);
                    }
                    break;
                case SDL_MOUSEBUTTONDOWN:
                    isMouseDown = true;
                    eventFunc(MR_MOUSE_DOWN, event.motion.x, event.motion.y);
                    break;
                case SDL_MOUSEBUTTONUP:
                    isMouseDown = false;
                    eventFunc(MR_MOUSE_UP, event.motion.x, event.motion.y);
                    break;
            }
        }
    }
}

int main(int argc, char *args[]) {
#ifdef __x86_64__
    printf("__x86_64__\n");
#elif __i386__
    printf("__i386__\n");
#endif

    printf("CODE_ADDRESS:0x%X, CODE_SIZE:0x%X\n", CODE_ADDRESS, CODE_SIZE);
    printf("STACK_ADDRESS:0x%X, STACK_SIZE:0x%X\n", STACK_ADDRESS, STACK_SIZE);
    printf("BRIDGE_TABLE_ADDRESS:0x%X, BRIDGE_TABLE_SIZE:0x%X\n", BRIDGE_TABLE_ADDRESS, BRIDGE_TABLE_SIZE);
    printf("MEMORY_MANAGER_ADDRESS:0x%X, MEMORY_MANAGER_SIZE:0x%X\n", MEMORY_MANAGER_ADDRESS, MEMORY_MANAGER_SIZE);
    printf("SCREEN_BUF_ADDRESS:0x%X, SCREEN_BUF_SIZE:0x%X\n", SCREEN_BUF_ADDRESS, SCREEN_BUF_SIZE);
    printf("START_ADDRESS:0x%X, STOP_ADDRESS:0x%X\n", START_ADDRESS, STOP_ADDRESS);
    printf("TOTAL_MEMORY:0x%X(%d)\n", TOTAL_MEMORY, TOTAL_MEMORY);

    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER) < 0) {
        printf("SDL could not initialize! SDL_Error: %s\n", SDL_GetError());
        return -1;
    }

    window = SDL_CreateWindow("vmrp", SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED, SCREEN_WIDTH, SCREEN_HEIGHT, SDL_WINDOW_SHOWN);
    if (window == NULL) {
        printf("Window could not be created! SDL_Error: %s\n", SDL_GetError());
        return -1;
    }

    startMrp("vmrp.mrp");

#if defined(__EMSCRIPTEN__)
    emscripten_set_main_loop(loop, 0, 1);
#else
    loop();
#endif
    return 0;
}
