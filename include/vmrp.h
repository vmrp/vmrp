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

#define CODE_ADDRESS 0x80000       // 代码段的起始地址
#define CODE_SIZE 1024 * 1024 * 1  // 代码段长度

#define STACK_ADDRESS (CODE_ADDRESS + CODE_SIZE)  // 栈开始地址
#define STACK_SIZE 1024 * 1024 * 1                // 栈大小

#define MEMORY_MANAGER_ADDRESS (STACK_ADDRESS + STACK_SIZE)  // 由malloc和free管理的模拟器内存
#define MEMORY_MANAGER_SIZE 1024 * 1024 * 6

#define START_ADDRESS CODE_ADDRESS
#define END_ADDRESS (MEMORY_MANAGER_ADDRESS + MEMORY_MANAGER_SIZE)
#define TOTAL_MEMORY (END_ADDRESS - START_ADDRESS)

// 将vm中的地址值转换为指针，返回的指针禁止用free()释放
void *getMrpMemPtr(uint32_t addr);

// 将指针转换为vm中的地址值
uint32_t toMrpMemAddr(void *ptr);

int32_t vmrp_onEvent(int32_t code, int32_t p1, int32_t p2);
int32_t vmrp_onTimer();
int vmrp_start();
void vmrp_onStop();

#endif
