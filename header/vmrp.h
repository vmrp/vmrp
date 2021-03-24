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

void *getMrpMemPtr(uint32_t addr);
uint32_t toMrpMemAddr(void *ptr);

int32_t event(int32_t code, int32_t p1, int32_t p2);
int32_t timer();
int startVmrp();


#endif
