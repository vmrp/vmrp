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

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#endif

uint8_t *mrpMem;  // 模拟器的全部内存

// 返回的内存不能free
#ifdef __EMSCRIPTEN__
EMSCRIPTEN_KEEPALIVE
#endif
void *getMrpMemPtr(uint32_t addr) {
    return mrpMem + (addr - START_ADDRESS);
}

#ifdef __EMSCRIPTEN__
EMSCRIPTEN_KEEPALIVE
#endif
uint32_t toMrpMemAddr(void *ptr) {
    return ((uint8_t *)ptr - mrpMem) + START_ADDRESS;
}

#ifdef DEBUG
static void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    printf(">>> Tracing basic block at 0x%" PRIx64 ", block size = 0x%x\n", address, size);
}
static void hook_mem_valid(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
    printf(">>> Tracing mem_valid mem_type:%s at 0x%" PRIx64 ", size:0x%x, value:0x%" PRIx64 "\n",
           memTypeStr(type), address, size, value);
    if (type == UC_MEM_READ && size <= 4) {
        uint32_t v, pc;
        uc_mem_read(uc, address, &v, size);
        uc_reg_read(uc, UC_ARM_REG_PC, &pc);
        printf("PC:0x%X,read:0x%X\n", pc, v);
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
    dumpREG(uc);
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
    // uc_hook_add(uc, &trace, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);
    // uc_hook_add(uc, &trace, UC_HOOK_MEM_VALID, hook_mem_valid, NULL, 1, 0);
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_code, NULL, 1, 0);
    // uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_code, NULL, BRIDGE_TABLE_ADDRESS, BRIDGE_TABLE_ADDRESS + BRIDGE_TABLE_SIZE);
#else
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_code, NULL, BRIDGE_TABLE_ADDRESS, BRIDGE_TABLE_ADDRESS + BRIDGE_TABLE_SIZE, 0);
#endif
    uc_hook_add(uc, &trace, UC_HOOK_MEM_INVALID, hook_mem_invalid, NULL, 1, 0, 0);

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

static uc_engine *uc;
static int32_t (*eventFunc)(int32_t code, int32_t p1, int32_t p2);

static int32_t eventFuncV1(int32_t code, int32_t p1, int32_t p2) {
    if (uc) {
        return bridge_mr_event(uc, code, p1, p2);
    }
    return MR_FAILED;
}

static int32_t eventFuncV2(int32_t code, int32_t p1, int32_t p2) {
    if (uc) {
        return bridge_dsm_mr_event(uc, code, p1, p2);
    }
    return MR_FAILED;
}

#ifdef __EMSCRIPTEN__
EMSCRIPTEN_KEEPALIVE
int32_t c_event(int32_t code, int32_t p1, int32_t p2) {
#else
int32_t event(int32_t code, int32_t p1, int32_t p2) {
#endif
    if (eventFunc) {
        return eventFunc(code, p1, p2);
    }
    return MR_FAILED;
}

int32_t timer() {
    if (uc) {
        return bridge_dsm_mr_timer(uc);
    }
    return MR_FAILED;
}

int startVmrp() {
    fileLib_init();
    eventFunc = eventFuncV1;

    uc = initVmrp("vmrp.mrp");
    if (uc == NULL) {
        printf("initVmrp() fail.\n");
        return 1;
    }

    int32_t ret = bridge_mr_init(uc);
    if (ret > CODE_ADDRESS) {
        printf("bridge_mr_init:0x%X try vmrp loader\n", ret);

        if (bridge_dsm_init(uc, ret) == MR_SUCCESS) {
            eventFunc = eventFuncV2;
            printf("bridge_dsm_init success\n");
            dumpREG(uc);

            char *filename = "dsm_gm.mrp";
            // char *filename = "winmine.mrp";
            char *extName = "start.mr";
            // char *extName = "cfunction.ext";

            uint32_t ret = bridge_dsm_mr_start_dsm(uc, filename, extName, NULL);
            printf("bridge_dsm_mr_start_dsm('%s','%s',NULL): 0x%X\n", filename, extName, ret);
        }
    }

    // bridge_mr_pauseApp(uc);
    // bridge_mr_resumeApp(uc);

    // mrc_exitApp() 可能由MR_EVENT_EXIT event之后自动调用
    // bridge_mr_event(uc, MR_EVENT_EXIT, 0, 0);

    // freeVmrp(uc);
    // printf("exit.\n");
    return 0;
}