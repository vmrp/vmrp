#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "../../header/bridge.h"
#include "../../header/fileLib.h"
#include "../../header/vmrp.h"

#ifdef _WIN32
#ifdef __x86_64__
#include "../lib/SDL2-2.0.10/x86_64-w64-mingw32/include/SDL2/SDL.h"
#elif __i386__
#include "../lib/SDL2-2.0.10/i686-w64-mingw32/include/SDL2/SDL.h"
#endif
#else
#include <SDL2/SDL.h>
#endif

#define MOUSE_DOWN 2
#define MOUSE_UP 3
#define MOUSE_MOVE 12

// http://wiki.libsdl.org/Tutorials
// http://lazyfoo.net/tutorials/SDL/index.php

static SDL_Renderer *renderer;
static uc_engine *uc;

void guiSetPixel(int32_t x, int32_t y, uint16_t color) {
    SDL_SetRenderDrawColor(renderer, PIXEL565R(color), PIXEL565G(color), PIXEL565B(color), 0xFF);
    SDL_RenderDrawPoint(renderer, x, y);
}

void guiRefreshScreen(int32_t x, int32_t y, uint32_t w, uint32_t h) {
    SDL_RenderPresent(renderer);
}

static int init() {
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

static void eventFunc(int code, int p1, int p2) {
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
}

int main(int argc, char *args[]) {
#ifdef __x86_64__
    printf("__x86_64__\n");
#elif __i386__
    printf("__i386__\n");
#endif

    if (SDL_Init(SDL_INIT_VIDEO) < 0) {
        printf("SDL could not initialize! SDL_Error: %s\n", SDL_GetError());
        return -1;
    }

    SDL_Window *window = SDL_CreateWindow("SDL Tutorial", SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED, SCREEN_WIDTH, SCREEN_HEIGHT, SDL_WINDOW_SHOWN);
    if (window == NULL) {
        printf("Window could not be created! SDL_Error: %s\n", SDL_GetError());
        return -1;
    }
    // renderer = SDL_CreateRenderer(window, -1, SDL_RENDERER_ACCELERATED);
    renderer = SDL_CreateRenderer(window, -1, SDL_RENDERER_SOFTWARE); // windows xp
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

    init();

    SDL_Event event;
    bool isLoop = true;
    bool isDown = false;
    while (isLoop) {
        while (SDL_WaitEvent(&event)) {
            if (event.type == SDL_QUIT) {
                isLoop = false;
                break;
            } else if (event.type == SDL_KEYUP) {
                printf("key:%d\n", event.key.keysym.sym);
            } else if (event.type == SDL_MOUSEMOTION) {
                if (isDown) {
                    eventFunc(MOUSE_MOVE, event.motion.x, event.motion.y);
                }
            } else if (event.type == SDL_MOUSEBUTTONDOWN) {
                isDown = true;
                eventFunc(MOUSE_DOWN, event.motion.x, event.motion.y);

            } else if (event.type == SDL_MOUSEBUTTONUP) {
                isDown = false;
                eventFunc(MOUSE_UP, event.motion.x, event.motion.y);
            }
        }
    }
    SDL_DestroyRenderer(renderer);
    SDL_DestroyWindow(window);
    SDL_Quit();
    return 0;
}
