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

#define MOUSE_DOWN 2
#define MOUSE_UP 3
#define MOUSE_MOVE 12

// http://wiki.libsdl.org/Tutorials
// http://lazyfoo.net/tutorials/SDL/index.php

static char *filename;
static char *extName;
static SDL_TimerID timeId = 0;
static SDL_Renderer *renderer;
static uc_engine *uc;
static void (*eventFunc)(int code, int p1, int p2);

void guiSetPixel(int32_t x, int32_t y, uint16_t color) {
    SDL_SetRenderDrawColor(renderer, PIXEL565R(color), PIXEL565G(color), PIXEL565B(color), 0xFF);
    SDL_RenderDrawPoint(renderer, x, y);
}

void guiRefreshScreen(int32_t x, int32_t y, uint32_t w, uint32_t h) {
    SDL_RenderPresent(renderer);
}

static void runnn() {
    uint32_t ret = bridge_dsm_mr_start_dsm(uc, filename, extName, NULL);
    printf("bridge_dsm_mr_start_dsm('%s','%s',NULL): 0x%X\n", filename, extName, ret);
    SDL_RenderPresent(renderer);
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
static int64_t ttt;

uint32_t th2(uint32_t interval, void *param) {
    SDL_RemoveTimer(timeId);
    timeId = 0;

    int64_t now = get_time_ms();
    printf("th2 %I64d, %I64d\n", now, now - ttt);
    dumpREG(uc);
    int32_t ret = bridge_dsm_mr_timer(uc);
    printf("ret:%d\n", ret);
    dumpREG(uc);
    return 0;
}

int32_t timerStart(uint16_t t) {
    ttt = get_time_ms();
    printf("main_timerStart %d, %I64d\n", t, ttt);
    if (!timeId) {
        timeId = SDL_AddTimer(t, th2, NULL);
    } else {
        SDL_RemoveTimer(timeId);
        timeId = SDL_AddTimer(t, th2, NULL);
    }
    return MR_SUCCESS;
}

int32_t timerStop() {
    printf("main_timerStop\n");
    if (timeId) {
        SDL_RemoveTimer(timeId);
        timeId = 0;
    }
    return MR_SUCCESS;
}

static int startMrp(char *filename) {
    fileLib_init();
    eventFunc = eventFuncV1;

    uc = initVmrp(filename);
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
            runnn();
        }
    }

    // bridge_mr_pauseApp(uc);
    // bridge_mr_resumeApp(uc);

    // mrc_exitApp() 可能由MR_EVENT_EXIT event之后自动调用
    // bridge_mr_event(uc, MR_EVENT_EXIT, 0, 0);

    // freeVmrp(uc);
    // printf("exit.\n");
    SDL_RenderPresent(renderer);
    return 0;
}

static void keyEvent(int16 type, SDL_Keycode code) {
    switch (code) {
        case SDLK_RETURN:
            eventFunc(type, MR_KEY_SELECT, 0);
            break;
        case SDLK_w:
        case SDLK_UP:
            eventFunc(type, MR_KEY_UP, 0);
            break;
        case SDLK_s:
        case SDLK_DOWN:
            eventFunc(type, MR_KEY_DOWN, 0);
            break;
        case SDLK_a:
        case SDLK_LEFT:
            eventFunc(type, MR_KEY_LEFT, 0);
            break;
        case SDLK_d:
        case SDLK_RIGHT:
            eventFunc(type, MR_KEY_RIGHT, 0);
            break;
        case SDLK_q:
        case SDLK_LEFTBRACKET:
            eventFunc(type, MR_KEY_SOFTLEFT, 0);
            break;
        case SDLK_e:
        case SDLK_RIGHTBRACKET:
            eventFunc(type, MR_KEY_SOFTRIGHT, 0);
            break;
        case SDLK_HOME:
            runnn();
            break;
        case SDLK_t:
            bridge_dsm_mr_timer(uc);
            break;
        default:
            printf("key:%d\n", code);
            SDL_RenderPresent(renderer);
            break;
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

    SDL_Window *window = SDL_CreateWindow("vmrp", SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED, SCREEN_WIDTH, SCREEN_HEIGHT, SDL_WINDOW_SHOWN);
    if (window == NULL) {
        printf("Window could not be created! SDL_Error: %s\n", SDL_GetError());
        return -1;
    }
    // renderer = SDL_CreateRenderer(window, -1, SDL_RENDERER_ACCELERATED);
    renderer = SDL_CreateRenderer(window, -1, SDL_RENDERER_SOFTWARE);  // windows xp
    if (renderer == NULL) {
        printf("Renderer could not be created! SDL Error: %s\n", SDL_GetError());
        return -1;
    }

    // SDL_Surface *screenSurface = SDL_GetWindowSurface(window);
    // SDL_FillRect(screenSurface, NULL, SDL_MapRGB(screenSurface->format, 0, 0, 0));
    // SDL_UpdateWindowSurface(window);

    SDL_SetRenderDrawColor(renderer, 0x00, 0x00, 0x00, 0xFF);
    SDL_RenderClear(renderer);
    SDL_RenderPresent(renderer);

    // filename = (argc > 1) ? args[1] : "dsm_gm.mrp";
    // extName = (argc > 2) ? args[2] : "start.mr";

    filename = (argc > 1) ? args[1] : "winmine.mrp";
    extName = (argc > 2) ? args[2] : "cfunction.ext";

    startMrp("vmrp.mrp");

    SDL_Event event;
    bool isLoop = true;
    bool isDown = false;
    while (isLoop) {
        while (SDL_WaitEvent(&event)) {
            if (event.type == SDL_QUIT) {
                isLoop = false;
                break;
            }
            switch (event.type) {
                case SDL_KEYDOWN:
                    keyEvent(MR_KEY_PRESS, event.key.keysym.sym);
                    break;
                case SDL_KEYUP:
                    keyEvent(MR_KEY_RELEASE, event.key.keysym.sym);
                    break;
                case SDL_MOUSEMOTION:
                    if (isDown) {
                        eventFunc(MR_MOUSE_MOVE, event.motion.x, event.motion.y);
                    }
                    break;
                case SDL_MOUSEBUTTONDOWN:
                    isDown = true;
                    eventFunc(MR_MOUSE_DOWN, event.motion.x, event.motion.y);
                    break;
                case SDL_MOUSEBUTTONUP:
                    isDown = false;
                    eventFunc(MR_MOUSE_UP, event.motion.x, event.motion.y);
                    break;
            }
        }
    }
    return 0;
}
