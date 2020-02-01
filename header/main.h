#ifndef __VMRP_MAIN_H__
#define __VMRP_MAIN_H__

#include <ctype.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include "../windows/include/unicorn/unicorn.h"
#else
#include <unicorn/unicorn.h>
#endif

#define CODE_ADDRESS 0x80000                    // ext开始执行的地址
#define STOP_ADDRESS CODE_ADDRESS               // 代码停止位置
#define CODE_SIZE 1024 * 1024 * 1               // 为ext分配的内存大小
#define STACK_ADDRESS CODE_ADDRESS + CODE_SIZE  // 栈开始地址
#define STACK_SIZE 1024 * 1024 * 1              // 栈大小

// ext文件0x0地址处的值(mr_table指针)
#define BRIDGE_TABLE_ADDRESS STACK_ADDRESS + STACK_SIZE
#define BRIDGE_TABLE_SIZE 4096  // 最小值，实际完全足够，为了4k对齐

// 由malloc和free管理的供mrp使用的内存
#define MEMORY_MANAGER_ADDRESS BRIDGE_TABLE_ADDRESS + BRIDGE_TABLE_SIZE
#define MEMORY_MANAGER_SIZE 1024 * 1024 * 1

#endif
