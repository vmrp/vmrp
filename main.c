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
#include <SDL.h>
#endif
#include "header/types.h"

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
SDL_Renderer *renderer_cache;
SDL_Surface *surface_cache;
static uc_engine *uc;
static void (*eventFunc)(int code, int p1, int p2);
#if 1
void guiDrawBitmap(uint16_t *bmp, int32_t x, int32_t y, int32_t w, int32_t h) {
    SDL_Surface *surface = surface_cache;
     SDL_Rect srcrect = {0,0,SCREEN_WIDTH, SCREEN_HEIGHT};
    Uint32 window_w = SCREEN_WIDTH,window_h=SCREEN_HEIGHT;
    SDL_GetWindowSize(window, &window_w, &window_h);
    SDL_Rect dstrect = {0,0,window_w, window_h};
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
    SDL_BlitScaled(surface, &srcrect, SDL_GetWindowSurface(window), &dstrect);
    if (SDL_UpdateWindowSurface(window) != 0)
        printf("SDL_UpdateWindowSurface err\n");
}
#else
void guiDrawBitmap(uint16_t *bmp, int32_t x, int32_t y, int32_t w, int32_t h) {
    // SDL_Surface *surface = SDL_GetWindowSurface(window);
    SDL_Surface *surface = surface_cache;
    SDL_Rect srcrect = {0,0,SCREEN_WIDTH, SCREEN_HEIGHT};
    renderer_cache = SDL_GetRenderer(window);
    Uint32 window_w = SCREEN_WIDTH,window_h=SCREEN_HEIGHT;
    // SDL_GetWindowSize(window, &window_w, &window_h);
    SDL_Rect dstrect = {0,0,window_w, window_h};
    
    // if (SDL_MUSTLOCK(surface)) {
    //     if (SDL_LockSurface(surface) != 0) LOG("SDL_LockSurface err\n");
    // }
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
    // if (SDL_MUSTLOCK(surface)) SDL_UnlockSurface(surface);
    
     SDL_Texture *pTexture = NULL;
        pTexture = SDL_CreateTextureFromSurface(renderer_cache,surface);
        SDL_RenderCopy(renderer_cache, pTexture, &srcrect, &dstrect);
        SDL_RenderDrawLine(renderer_cache, 0,1,300,300);
        SDL_DestroyTexture(pTexture);
    SDL_RenderPresent(renderer_cache);
    // if (SDL_UpdateWindowSurface(window) != 0)
    //     LOG("SDL_UpdateWindowSurface err\n");
}
#endif

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
        LOG("initVmrp() fail.\n");
        return 1;
    }

    int32_t ret = bridge_mr_init(uc);
    if (ret > CODE_ADDRESS) {
        LOG("bridge_mr_init:0x%X try vmrp loader\n", ret);

        if (bridge_dsm_init(uc, ret) == MR_SUCCESS) {
            eventFunc = eventFuncV2;
            LOG("bridge_dsm_init success\n");
            dumpREG(uc);

            // char *filename = "dsm_gm.mrp";
            char *filename = my_getFileName(dsm_getRunName());
            printf("运行mrp %s\n",filename);
            // char *filename = "winmine.mrp";
            char *extName = "start.mr";
            // char *extName = "cfunction.ext";

            uint32_t ret = bridge_dsm_mr_start_dsm(uc, filename, extName, NULL);
            LOG("bridge_dsm_mr_start_dsm('%s','%s',NULL): 0x%X\n", filename, extName, ret);
        }
    }

    // bridge_mr_pauseApp(uc);
    // bridge_mr_resumeApp(uc);

    // mrc_exitApp() 可能由MR_EVENT_EXIT event之后自动调用
    // bridge_mr_event(uc, MR_EVENT_EXIT, 0, 0);

    // freeVmrp(uc);
    // LOG("exit.\n");
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
        case SDLK_HASH:
            eventFunc(type, MR_KEY_POUND, 0);  // 按键 #
            break;
        case SDLK_MINUS:                      // 减号
        case SDLK_ASTERISK:
            eventFunc(type, MR_KEY_STAR, 0);  // 按键 *
            break;
        case SDLK_a:
        case SDLK_b:
        case SDLK_c:
        case SDLK_d:
        case SDLK_e:
        case SDLK_f:
        case SDLK_g:
        case SDLK_h:
        case SDLK_i:
        case SDLK_j:
        case SDLK_k:
        case SDLK_l:
        case SDLK_m:
        case SDLK_n:
        case SDLK_o:
        case SDLK_p:
        case SDLK_q:
        case SDLK_r:
        case SDLK_s:
        case SDLK_t:
        case SDLK_u:
        case SDLK_v:
        case SDLK_w:
        case SDLK_x:
        case SDLK_y:
        case SDLK_z:
        case SDLK_UNDERSCORE:
        case SDLK_BACKQUOTE:
        case SDLK_CARET:
        case SDLK_QUESTION:
        case SDLK_AT:
        case SDLK_SPACE:
            eventFunc(type, code, 0);
            break;
        case SDLK_UP:  // 上
            eventFunc(type, MR_KEY_UP, 0);
            break;
        case SDLK_DOWN:  // 下
            eventFunc(type, MR_KEY_DOWN, 0);
            break;
        case SDLK_LEFT:  // 左
            eventFunc(type, MR_KEY_LEFT, 0);
            break;
        case SDLK_RIGHT:  // 右
            eventFunc(type, MR_KEY_RIGHT, 0);
            break;
        case SDLK_LEFTBRACKET:                    // 左中括号
            eventFunc(type, MR_KEY_SOFTLEFT, 0);  // 左功能键
            break;
        case SDLK_RIGHTBRACKET:                    // 右中括号
            eventFunc(type, MR_KEY_SOFTRIGHT, 0);  // 右功能键
            break;
        case SDLK_TAB:
            eventFunc(type, MR_KEY_SEND, 0);  // 接听键
            break;
        case SDLK_ESCAPE:
            
            // eventFunc(type, MR_KEY_SOFTRIGHT, 0);  // 挂机键
            break;
        case SDLK_DELETE:
            eventFunc(type, MR_KEY_POWER, 0);
            break;
        default:
            LOG("key:%d\n", code);
            break;
    }
}
#define __EMSCRIPTEN__ 1
bool isMouseDown = false;

SDL_Keycode isKeyDown = SDLK_UNKNOWN;

void loop() {
    SDL_Event event;
    bool isLoop = true;


    while (isLoop)
    {
        if(cb_addr != 0 && cb_p0 != 0){
            LOG("run cb_addr %d\n",cb_addr);
            uc_reg_write(uc, UC_ARM_REG_R0, &cb_p0);
            runCode(uc, cb_addr, CODE_ADDRESS,0);
            cb_addr = 0;
            cb_p0 = 0;
        }
#if defined(__EMSCRIPTEN__)
        while (SDL_PollEvent(&event))
#else
        while (SDL_WaitEvent(&event))
#endif
        {
            Uint32 window_w, window_h;
            SDL_GetWindowSize(window, &window_w, &window_h);
            SDL_Texture *pTexture = NULL;
                    SDL_Rect srcrect = {0,0,SCREEN_WIDTH, SCREEN_HEIGHT};
    SDL_Rect dstrect = {0,0,window_w, window_h};
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
                        eventFunc(MR_MOUSE_MOVE, event.motion.x * SCREEN_WIDTH / window_w, event.motion.y * SCREEN_HEIGHT / window_h);
                    }
                    break;
                case SDL_MOUSEBUTTONDOWN:
                    isMouseDown = true;
                    eventFunc(MR_MOUSE_DOWN, event.motion.x * SCREEN_WIDTH / window_w, event.motion.y * SCREEN_HEIGHT / window_h);
                    break;
                case SDL_MOUSEBUTTONUP:
                    isMouseDown = false;
                    eventFunc(MR_MOUSE_UP, event.motion.x * SCREEN_WIDTH / window_w, event.motion.y * SCREEN_HEIGHT / window_h);
                    break;
                case SDL_WINDOWEVENT:
#if defined(WIN32)
                    LOG("window_event %d\n",event.window.event);
                    
                    if(event.window.event == SDL_WINDOWEVENT_MAXIMIZED){

                    }
                    else if(event.window.event == SDL_WINDOWEVENT_SIZE_CHANGED){
                        Uint32 new_w = window_w;
                        Uint32 new_h = window_w * SCREEN_HEIGHT/SCREEN_WIDTH;
                        if(new_h != window_h)
                        SDL_SetWindowSize(window, new_w,new_h);


                    }
                    //
                    // pTexture = SDL_CreateTextureFromSurface(renderer_cache,surface_cache);
                    // SDL_RenderCopy(renderer_cache, pTexture, &srcrect, &dstrect);
                    // SDL_DestroyTexture(pTexture);

                    // SDL_RenderPresent(renderer_cache);
#endif
                    break;
                default:
                LOG("未知事件%d\n", event.type);
            }
        }
    }
}

int main(int argc, char *args[]) {
#ifdef __x86_64__
    LOG("__x86_64__\n");
#elif __i386__
    LOG("__i386__\n");
#endif
    system("CHCP 65001\n");
    dsm_parseArgs(argc, args);

    LOG("CODE_ADDRESS:0x%X, CODE_SIZE:0x%X\n", CODE_ADDRESS, CODE_SIZE);
    LOG("STACK_ADDRESS:0x%X, STACK_SIZE:0x%X\n", STACK_ADDRESS, STACK_SIZE);
    LOG("BRIDGE_TABLE_ADDRESS:0x%X, BRIDGE_TABLE_SIZE:0x%X\n", BRIDGE_TABLE_ADDRESS, BRIDGE_TABLE_SIZE);
    LOG("MEMORY_MANAGER_ADDRESS:0x%X, MEMORY_MANAGER_SIZE:0x%X\n", MEMORY_MANAGER_ADDRESS, MEMORY_MANAGER_SIZE);
    LOG("SCREEN_BUF_ADDRESS:0x%X, SCREEN_BUF_SIZE:0x%X\n", SCREEN_BUF_ADDRESS, SCREEN_BUF_SIZE);
    LOG("START_ADDRESS:0x%X, STOP_ADDRESS:0x%X\n", START_ADDRESS, STOP_ADDRESS);
    LOG("TOTAL_MEMORY:0x%X(%d)\n", TOTAL_MEMORY, TOTAL_MEMORY);

    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER) < 0) {
        LOG("SDL could not initialize! SDL_Error: %s\n", SDL_GetError());
        return -1;
    }

    window = SDL_CreateWindow("vmrp 影子修改版", SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED, SCREEN_WIDTH, SCREEN_HEIGHT, SDL_WINDOW_SHOWN|SDL_WINDOW_RESIZABLE);
    SDL_SetWindowMinimumSize(window, SCREEN_WIDTH,SCREEN_HEIGHT);
    SDL_SetWindowMaximumSize(window, SCREEN_WIDTH*2,SCREEN_HEIGHT*2);
    if (window == NULL) {
        LOG("Window could not be created! SDL_Error: %s\n", SDL_GetError());
        return -1;
    }
       int rmask = 0xFF000000;
    int gmask = 0x00FF0000;
    int bmask = 0x0000FF00;
    int amask = 0x000000FF;  // RGBA8888模式
    surface_cache = SDL_CreateRGBSurface(SDL_PREALLOC, SCREEN_WIDTH, SCREEN_HEIGHT,
                           32, rmask, gmask, bmask, amask);
#if defined(__android__)
    renderer_cache = SDL_CreateRenderer(window, -1, SDL_RENDERER_PRESENTVSYNC | SDL_RENDERER_TARGETTEXTURE);
#else
    renderer_cache = SDL_CreateRenderer(window, -1, SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC | SDL_RENDERER_TARGETTEXTURE);
#endif

    startMrp("vmrp.mrp");


    loop();

    return 0;
}
