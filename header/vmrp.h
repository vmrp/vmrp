#ifndef __VMRP__H__
#define __VMRP__H__

#include <ctype.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "utils.h"

#define SCREEN_WIDTH 240
#define SCREEN_HEIGHT 320

#define CODE_ADDRESS 0x80000       // ext开始执行的地址
#define CODE_SIZE 1024 * 1024 * 1  // 为ext分配的内存大小

#define STACK_ADDRESS (CODE_ADDRESS + CODE_SIZE)  // 栈开始地址
#define STACK_SIZE 1024 * 1024 * 1                // 栈大小

#define BRIDGE_TABLE_ADDRESS (STACK_ADDRESS + STACK_SIZE)  // ext文件0x0地址处的值(mr_table指针)
#define BRIDGE_TABLE_SIZE 4096                             // 足够了，只是为了4k对齐

#define MEMORY_MANAGER_ADDRESS (BRIDGE_TABLE_ADDRESS + BRIDGE_TABLE_SIZE)  // 由malloc和free管理的供mrp使用的内存
#define MEMORY_MANAGER_SIZE 1024 * 1024 * 4

#define SCREEN_BUF_ADDRESS (MEMORY_MANAGER_ADDRESS + MEMORY_MANAGER_SIZE)
#define SCREEN_BUF_SIZE (SCREEN_WIDTH * SCREEN_HEIGHT * 2)  //屏幕缓存大小，每像素两字节

#define START_ADDRESS CODE_ADDRESS
#define STOP_ADDRESS (SCREEN_BUF_ADDRESS + SCREEN_BUF_SIZE)
#define TOTAL_MEMORY (STOP_ADDRESS - START_ADDRESS)

extern uint16_t *screenBuf;  // 屏幕缓冲区地址

void *getMrpMemPtr(uint32_t addr);

int vmrp_test();
uc_engine *initVmrp(char *filename);
int freeVmrp();

// 需要外部实现的接口
extern void guiDrawBitmap(uint16_t *bmp, int32_t x, int32_t y, int32_t w, int32_t h);
extern int32_t timerStart(uint16_t t);
extern int32_t timerStop();

#endif
