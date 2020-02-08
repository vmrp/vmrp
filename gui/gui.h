#ifndef __MY_API_H__
#define __MY_API_H__

#include <stdio.h>
#include <stdint.h>
#include "gui.h"

#define MOUSE_DOWN 1
#define MOUSE_UP 2
#define MOUSE_MOVE 3

extern void refresh();
extern void setPixel(int32_t x, int32_t y, uint8_t r, uint8_t g, uint8_t b);
void event(int code, int p1, int p2);

#endif
