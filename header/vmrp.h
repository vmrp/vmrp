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

// 代码段的起始地址
#define CODE_ADDRESS 0x80000
// 代码段长度
#define CODE_SIZE 1024 * 1024 * 1

#define STACK_ADDRESS (CODE_ADDRESS + CODE_SIZE)  // 栈开始地址
#define STACK_SIZE 1024 * 1024 * 1                // 栈大小

#define BRIDGE_TABLE_ADDRESS (STACK_ADDRESS + STACK_SIZE)  // 函数表的起始地址
#define BRIDGE_TABLE_SIZE 4096                             // 足够了，只是为了4k对齐

#define MEMORY_MANAGER_ADDRESS (BRIDGE_TABLE_ADDRESS + BRIDGE_TABLE_SIZE)  // 由malloc和free管理的模拟器内存
#define MEMORY_MANAGER_SIZE 1024 * 1024 * 6

#define START_ADDRESS CODE_ADDRESS
#define STOP_ADDRESS (MEMORY_MANAGER_ADDRESS + MEMORY_MANAGER_SIZE)
#define TOTAL_MEMORY (STOP_ADDRESS - START_ADDRESS)

void *getMrpMemPtr(uint32_t addr);
uint32_t toMrpMemAddr(void *ptr);

int32_t event(int32_t code, int32_t p1, int32_t p2);
int32_t timer();
int startVmrp();

#endif
