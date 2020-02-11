#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __x86_64__
#include "../lib/SDL2-2.0.10/x86_64-w64-mingw32/include/SDL2/SDL.h"
#elif __i386__
#include "../lib/SDL2-2.0.10/i686-w64-mingw32/include/SDL2/SDL.h"
#endif

// http://wiki.libsdl.org/Tutorials
// http://lazyfoo.net/tutorials/SDL/index.php

const int SCREEN_WIDTH = 240;
const int SCREEN_HEIGHT = 320;

void setPixel(SDL_Renderer *renderer, int x, int y) {
    SDL_SetRenderDrawColor(renderer, 0xFF, 0x00, 0x00, 0xFF);
    SDL_RenderDrawPoint(renderer, x, y);
    SDL_RenderPresent(renderer);
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
    SDL_Renderer *renderer = SDL_CreateRenderer(window, -1, SDL_RENDERER_ACCELERATED);
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
                    printf("SDL_MOUSEMOTION x:%d,y:%d\n", event.motion.x, event.motion.y);
                    setPixel(renderer, event.motion.x, event.motion.y);
                }
            } else if (event.type == SDL_MOUSEBUTTONDOWN) {
                isDown = true;
                printf("SDL_MOUSEBUTTONDOWN x:%d,y:%d\n", event.motion.x, event.motion.y);
                setPixel(renderer, event.motion.x, event.motion.y);

            } else if (event.type == SDL_MOUSEBUTTONUP) {
                isDown = false;
                printf("SDL_MOUSEBUTTONUP x:%d,y:%d\n", event.motion.x, event.motion.y);
                setPixel(renderer, event.motion.x, event.motion.y);
            }
        }
    }
    SDL_DestroyRenderer(renderer);
    SDL_DestroyWindow(window);
    SDL_Quit();
    return 0;
}
