#ifndef __MY_API_H__
#define __MY_API_H__

#include <stdint.h>
#include <stdio.h>
#include "gui.h"

#define MOUSE_DOWN 2
#define MOUSE_UP 3
#define MOUSE_MOVE 12

extern void refresh();
extern void setPixel(int32_t x, int32_t y, uint8_t r, uint8_t g, uint8_t b);
int init();
void event(int code, int p1, int p2);

#endif
