#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include "./windows/include/unicorn/unicorn.h"
#else
#include <unicorn/unicorn.h>
#endif

#include "fileLib.h"
#include "mr_helper.h"

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

// memory address where emulation starts
#define ADDRESS 0x80000

static char *memTypeStr(uc_mem_type type) {
    // clang-format off
	switch (type)
	{
    case UC_MEM_READ:return "UC_MEM_READ";
    case UC_MEM_WRITE:return "UC_MEM_WRITE";
    case UC_MEM_FETCH:return "UC_MEM_FETCH";
    case UC_MEM_READ_UNMAPPED:return "UC_MEM_READ_UNMAPPED";
    case UC_MEM_WRITE_UNMAPPED:return "UC_MEM_WRITE_UNMAPPED";
    case UC_MEM_FETCH_UNMAPPED:return "UC_MEM_FETCH_UNMAPPED";
    case UC_MEM_WRITE_PROT:return "UC_MEM_WRITE_PROT";
    case UC_MEM_READ_PROT:return "UC_MEM_READ_PROT";
    case UC_MEM_FETCH_PROT:return "UC_MEM_FETCH_PROT";
    case UC_MEM_READ_AFTER:return "UC_MEM_READ_AFTER";
	}
    // clang-format on
    return "<error type>";
}

static void dumpREG(uc_engine *uc) {
    uint32_t v;

    // clang-format off
    printf("===========REG=============\n");
    uc_reg_read(uc, UC_ARM_REG_R0, &v); printf("R0:0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_R1, &v); printf("R1:0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_R2, &v); printf("R2:0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_R3, &v); printf("R3:0x%08X\n", v);

    uc_reg_read(uc, UC_ARM_REG_R4, &v); printf("R4:0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_R5, &v); printf("R5:0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_R6, &v); printf("R6:0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_R7, &v); printf("R7:0x%08X\n", v);

    uc_reg_read(uc, UC_ARM_REG_R8, &v); printf("R8:0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_R9, &v); printf("R9:0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_R10, &v); printf("R10:0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_R11, &v); printf("R11:0x%08X\n", v);

    uc_reg_read(uc, UC_ARM_REG_R12, &v); printf("R12:0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_SP, &v); printf("SP:0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_LR, &v); printf("LR:0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_PC, &v); printf("PC:0x%08X\n", v);
    printf("===========================\n");
    // clang-format on
}

static void hook_block(uc_engine *uc, uint64_t address, uint32_t size,
                       void *user_data) {
    printf(">>> Tracing basic block at 0x%" PRIx64 ", block size = 0x%x\n",
           address, size);
}

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size,
                      void *user_data) {
    printf(">>> Tracing instruction at 0x%" PRIx64
           ", instruction size = 0x%x\n",
           address, size);
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
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);
    {
        char *filename = "cfunction.ext";
        int32 offset, length;
        uint8 *data;
        int32 ret = readMrpFileEx(MRPFILE, filename, &offset, &length, &data);
        if (ret == MR_FAILED) {
            LOG("load %s failed", filename);
            goto end;
        }
        uc_hook trace1, trace2, traceMemInvalid, traceMemValid;
        int sp = ADDRESS + 1024 * 1024;

        LOG("load %s suc: offset:%d, length:%d", filename, offset, length);
        uc_mem_write(uc, ADDRESS, data, length - 1);

        uc_reg_write(uc, UC_ARM_REG_SP, &sp);

        uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);
        uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);
        uc_hook_add(uc, &traceMemInvalid, UC_HOOK_MEM_INVALID, hook_mem_invalid,
                    NULL, 1, 0);
        uc_hook_add(uc, &traceMemValid, UC_HOOK_MEM_VALID, hook_mem_valid, NULL,
                    1, 0);

        if (isThumb) {
            // Note we start at ADDRESS | 1 to indicate THUMB mode.
            err =
                uc_emu_start(uc, (ADDRESS + 8) | 1, ADDRESS + length - 1, 0, 0);
        } else {
            err = uc_emu_start(uc, ADDRESS + 8, ADDRESS + length - 1, 0, 4);
        }
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

    // printf("thumb:\n");
    // emu(TRUE);

    printf("arm:\n");
    emu(FALSE);
    return 0;
}