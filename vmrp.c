#include "./header/vmrp.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "./header/bridge.h"
#include "./header/debug.h"
#include "./header/fileLib.h"
#include "./header/memory.h"
#include "./header/tsf_font.h"
#include "./header/utils.h"

uint16_t *screenBuf;
uint8_t *mrpMem;  // 模拟器的全部内存

// 返回的内存禁止free
void *getMrpMemPtr(uint32_t addr) {
    return mrpMem + (addr - START_ADDRESS);
}

#ifdef DEBUG
static void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    printf(">>> Tracing basic block at 0x%" PRIx64 ", block size = 0x%x\n", address, size);
}
static void hook_mem_valid(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
    printf(">>> Tracing mem_valid mem_type:%s at 0x%" PRIx64 ", size:0x%x, value:0x%" PRIx64 "\n",
           memTypeStr(type), address, size, value);
    if (type == UC_MEM_READ && size <= 4) {
        uint32_t v;
        uc_mem_read(uc, address, &v, size);
        printf("read:0x%X\n", v);
    }
}
#endif

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
#ifdef DEBUG
    hook_code_debug(uc, address, size);
#endif
    if (address >= BRIDGE_TABLE_ADDRESS && address <= BRIDGE_TABLE_ADDRESS + BRIDGE_TABLE_SIZE) {
        bridge(uc, UC_MEM_FETCH, address);
    }
}

static bool hook_mem_invalid(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
    printf(">>> Tracing mem_invalid mem_type:%s at 0x%" PRIx64 ", size:0x%x, value:0x%" PRIx64 "\n",
           memTypeStr(type), address, size, value);
    return false;
}

static int32_t loadCode(uc_engine *uc, char *filename) {
    char *extFilename = "cfunction.ext";
    uint32_t value, length;
    uint8_t *code;
    int32_t ret = readMrpFileEx(filename, extFilename, (int32 *)&value, (int32 *)&length, &code);
    if (ret == MR_FAILED) {
        LOG("load %s failed", extFilename);
        return ret;
    }
    LOG("load %s suc: offset:%d, length:%d", extFilename, value, length);

    uc_mem_write(uc, CODE_ADDRESS, code, length);
    free(code);
    return ret;
}

static bool mem_init(uc_engine *uc, char *filename) {
    mrpMem = malloc(TOTAL_MEMORY);
    screenBuf = getMrpMemPtr(SCREEN_BUF_ADDRESS);

    // unicorn存在BUG，UC_HOOK_MEM_INVALID只能拦截第一次UC_MEM_FETCH_PROT，所以干脆设置成可执行，统一在UC_HOOK_CODE事件中处理
    uc_err err = uc_mem_map_ptr(uc, START_ADDRESS, TOTAL_MEMORY, UC_PROT_ALL, mrpMem);
    if (err) {
        printf("Failed mem map: %u (%s)\n", err, uc_strerror(err));
        return false;
    }

    if (loadCode(uc, filename) == MR_FAILED) {
        return false;
    }

    initMemoryManager(MEMORY_MANAGER_ADDRESS, MEMORY_MANAGER_SIZE);
    return true;
}

int freeVmrp(uc_engine *uc) {
    free(mrpMem);
    uc_close(uc);
    return 0;
}

uc_engine *initVmrp(char *filename) {
    uc_engine *uc;
    uc_err err;
    uc_hook trace;

#ifdef DEBUG
    hook_code_debug_open();
#endif

    err = uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n", err, uc_strerror(err));
        return NULL;
    }

    if (!mem_init(uc, filename)) {
        printf("mem_init() fail\n");
        goto end;
    }

    err = bridge_init(uc);
    if (err) {
        printf("Failed bridge_init(): %u (%s)\n", err, uc_strerror(err));
        goto end;
    }

#ifdef DEBUG
    uc_hook_add(uc, &trace, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);
    uc_hook_add(uc, &trace, UC_HOOK_MEM_VALID, hook_mem_valid, NULL, 1, 0);
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_code, NULL, 1, 0);
#else
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_code, NULL, BRIDGE_TABLE_ADDRESS, BRIDGE_TABLE_ADDRESS + BRIDGE_TABLE_SIZE);
#endif
    uc_hook_add(uc, &trace, UC_HOOK_MEM_INVALID, hook_mem_invalid, NULL, 1, 0);

    // 设置栈
    uint32_t value = STACK_ADDRESS + STACK_SIZE;  // 满递减
    uc_reg_write(uc, UC_ARM_REG_SP, &value);

    // 调用第一个函数
    value = 1;
    uc_reg_write(uc, UC_ARM_REG_R0, &value);  // 传参数值1
    runCode(uc, CODE_ADDRESS + 8, CODE_ADDRESS, false);

    printf("\n ----------------------------init done.--------------------------------------- \n");
    return uc;
end:
    uc_close(uc);
    return NULL;
}
