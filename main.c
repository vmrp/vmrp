#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include "./windows/include/unicorn/unicorn.h"
#else
#include <unicorn/unicorn.h>
#endif

#include "./header/debug.h"
#include "./header/fileLib.h"
#include "./header/mr_helper.h"
#include "./header/mr_table_bridge.h"
#include "./header/utils.h"

// #define MRPFILE "mr.mrp"
#define MRPFILE "asm.mrp"

static void writeFile(const char *filename, void *data, uint32 length) {
    int fh = mr_open(filename, MR_FILE_CREATE | MR_FILE_RDWR);
    mr_write(fh, data, length);
    mr_close(fh);
}

int extractFile() {
    // char *filename = "start.mr";
    char *filename = "cfunction.ext";
    // char *filename = "game.ext";
    int32 offset, length;
    uint8 *data;
    int32 ret = readMrpFileEx(MRPFILE, filename, &offset, &length, &data);
    if (ret == MR_SUCCESS) {
        LOG("red suc: offset:%d, length:%d", offset, length);
        writeFile(filename, data, length);
    } else {
        LOG("red failed");
    }

    return 0;
}

//////////////////////////////////////////////////////////////////////////////////////

#define CODE_ADDRESS 0x80000                    // ext开始执行的地址
#define CODE_SIZE 1024 * 1024 * 1               // 为ext分配的内存大小
#define STACK_ADDRESS CODE_ADDRESS + CODE_SIZE  // 栈开始地址
#define STACK_SIZE 1024 * 1024 * 1              // 栈大小

static void hook_block(uc_engine *uc, uint64_t address, uint32_t size,
                       void *user_data) {
    printf(">>> Tracing basic block at 0x%" PRIx64 ", block size = 0x%x\n",
           address, size);
}

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size,
                      void *user_data) {
    // printf(">>> PC:0x%" PRIX64 ", size:0x%x\n", address, size);
    mr_table_bridge_exec(uc, MR_TABLE_ADDRESS + 0x10, size, user_data);
    hook_code_debug(uc, address, size, user_data);
}

static void hook_mem_valid(uc_engine *uc, uc_mem_type type, uint64_t address,
                           int size, int64_t value, void *user_data) {
    printf(">>> Tracing mem_valid mem_type:%s at 0x%" PRIx64
           ", size:0x%x, value:0x%" PRIx64 "\n",
           memTypeStr(type), address, size, value);
}

static bool hook_mem_invalid(uc_engine *uc, uc_mem_type type, uint64_t address,
                             int size, int64_t value, void *user_data) {
    printf(">>> Tracing mem_invalid mem_type:%s at 0x%" PRIx64
           ", size:0x%x, value:0x%" PRIx64 "\n",
           memTypeStr(type), address, size, value);
    return false;
}

static void emu(BOOL isThumb) {
    uc_engine *uc;
    uc_err err;

    if (isThumb) {
        err = uc_open(UC_ARCH_ARM, UC_MODE_THUMB, &uc);
    } else {
        err = uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);
    }

    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n", err,
               uc_strerror(err));
        return;
    }
    uc_mem_map(uc, CODE_ADDRESS, CODE_SIZE, UC_PROT_ALL);
    uc_mem_map(uc, STACK_ADDRESS, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE);
    {
        char *filename = "cfunction.ext";
        uint32 value, length;
        uint8 *code;
        int32 ret = readMrpFileEx(MRPFILE, filename, (int32 *)&value,
                                  (int32 *)&length, &code);
        if (ret == MR_FAILED) {
            LOG("load %s failed", filename);
            goto end;
        }
        LOG("load %s suc: offset:%d, length:%d", filename, value, length);
        uc_mem_write(uc, CODE_ADDRESS, code, length);
        free(code);

        uc_hook trace1, trace2, traceMemInvalid, traceMemValid;

        uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);
        uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);
        // uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code_debug, NULL, 1, 0);
        uc_hook_add(uc, &traceMemInvalid, UC_HOOK_MEM_INVALID, hook_mem_invalid,
                    NULL, 1, 0);
        uc_hook_add(uc, &traceMemValid, UC_HOOK_MEM_VALID, hook_mem_valid, NULL,
                    1, 0);

        value = STACK_ADDRESS + STACK_SIZE;  // 满递减
        uc_reg_write(uc, UC_ARM_REG_SP, &value);

        value = CODE_ADDRESS;
        uc_reg_write(uc, UC_ARM_REG_LR, &value);  // 当程序执行到这里时停止运行

        value = 1;
        uc_reg_write(uc, UC_ARM_REG_R0, &value);  // 传参数值1

        dumpREG(uc);
        // Note we start at ADDRESS | 1 to indicate THUMB mode.
        value = CODE_ADDRESS + 8;
        value = isThumb ? value | 1 : value;
        err = uc_emu_start(uc, value, CODE_ADDRESS, 0, 0);
        if (err) {
            printf("Failed on uc_emu_start() with error returned: %u (%s)\n",
                   err, uc_strerror(err));
        }
        dumpREG(uc);
    }
end:
    uc_close(uc);
}

int main() {
    // mr_stop();
    // mr_event(MR_MOUSE_DOWN, x, y);
    listMrpFiles(MRPFILE);
    // extractFile();
    // mr_start_dsm(MRPFILE);

    mr_table_bridge_init();
    // printf("thumb:\n");
    // emu(TRUE);
    printf("arm:\n");
    emu(FALSE);
    return 0;
}