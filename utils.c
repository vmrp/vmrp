#include "./header/utils.h"

char *memTypeStr(uc_mem_type type) {
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

void dumpREG(uc_engine *uc) {
    uint32_t v;

    // clang-format off
    printf("===========REG=============\n");
    uc_reg_read(uc, UC_ARM_REG_R0, &v); printf("R0=0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_R1, &v); printf("R1=0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_R2, &v); printf("R2=0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_R3, &v); printf("R3=0x%08X\n", v);

    uc_reg_read(uc, UC_ARM_REG_R4, &v); printf("R4=0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_R5, &v); printf("R5=0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_R6, &v); printf("R6=0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_R7, &v); printf("R7=0x%08X\n", v);

    uc_reg_read(uc, UC_ARM_REG_R8, &v); printf("R8=0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_R9, &v); printf("R9=0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_R10, &v); printf("R10=0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_R11, &v); printf("R11=0x%08X\n", v);

    uc_reg_read(uc, UC_ARM_REG_R12, &v); printf("R12=0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_SP, &v); printf("SP=0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_LR, &v); printf("LR=0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_PC, &v); printf("PC=0x%08X\n", v);
    printf("===========================\n");
    // clang-format on
}