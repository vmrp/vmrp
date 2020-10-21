#include "./header/debug.h"

#include "./header/fileLib.h"
#include "./header/utils.h"
#include "./windows/capstone-4.0.1-win32/include/capstone/capstone.h"

// 获取等号左边的内容，限制长最大长度为maxLen个字符,
// outBuf的容量应该至少maxLen+1字节
static void getEqLeftStr(char *str, int eqPos, char *outBuf, int maxLen) {
    int start = eqPos <= maxLen ? 0 : eqPos - maxLen;
    int end = eqPos;
    int i = 0;
    while (start < end) {
        outBuf[i] = str[start];
        start++;
        i++;
    }
    outBuf[i] = '\0';
}

/*
转换一个全小写的十六进制字符串到32位整数，原理是从字符串末尾开始转换
0x4750524d1a  超过32位长度将只转换低32位
*/
static uint32_t toUint32(const char *str) {
    char *ptr = (char *)str;

    while (*ptr) ptr++;

    uint32_t tmp;
    uint32_t v = 0;
    uint32_t i = 0;
    for (ptr--; ptr >= str && i < 32; ptr--) {
        if (*ptr >= '0' && *ptr <= '9') {
            tmp = *ptr - '0';
        } else if (*ptr >= 'a' && *ptr <= 'f') {
            tmp = *ptr - 'a' + 10;
        } else {
            break;
        }
        v |= tmp << i;
        i += 4;
    }
    return v;
}

static uint32_t brkAddress = 0;
static bool run = false;

void hook_code_debug(uc_engine *uc, uint64_t address, uint32_t size) {
    char str[30];
    char *ptr;
    int eqPos;
    uc_err err;

    if (run) {
        return;
    }
    while (brkAddress == 0 || brkAddress == address) {
        brkAddress = 0;

        uint32_t pc;
        uc_reg_read(uc, UC_ARM_REG_PC, &pc);

        if (size <= 4) {
            cs_insn *insn;
            uint32_t binary;
            size_t count;
            csh handle;
            uint32_t cpsr;
            cs_mode mode;

            uc_reg_read(uc, UC_ARM_REG_CPSR, &cpsr);
            mode = (cpsr & (1 << 5)) ? CS_MODE_THUMB : CS_MODE_ARM;

            if (cs_open(CS_ARCH_ARM, mode, &handle) != CS_ERR_OK) {
                printf("debug cs_open() fail.");
                exit(1);
            }
            uc_mem_read(uc, address, &binary, size);
            count = cs_disasm(handle, (uint8_t *)&binary, size, address, 1, &insn);
            if (count > 0) {
                char cpsrStr[5];
                cpsrToStr(cpsr, cpsrStr);
                for (size_t j = 0; j < count; j++) {
                    printf("[PC:0x%X  %s   %s %s   %s  mem:0x%" PRIX64 "]> ",
                           pc, cpsrStr, insn[j].mnemonic, insn[j].op_str, (mode == CS_MODE_ARM ? "ARM" : "THUMB"), address);
                }
                cs_free(insn, count);
            } else {
                printf("[PC:0x%X, mem:0x%" PRIX64 ", size:%d]> ", pc, address, size);
            }
            cs_close(&handle);
        }

        ptr = fgets(str, sizeof(str), stdin);
        if (ptr == NULL) {
            break;
        }

        eqPos = 0;  // 等号的位置
        ptr = str;  // 转换成全小写
        while (*ptr) {
            if (isalpha(*ptr)) {
                *ptr = tolower(*ptr);
            } else if (*ptr == '\n') {
                *ptr = '\0';
                break;
            }
            if (eqPos == 0 && *ptr == '=') {
                eqPos = ptr - str;
            }
            ptr++;
        }
        if (str[0] == '\0') {
            return;

        } else if (strcmp("reg", str) == 0) {  // 打印所有寄存器内容
            dumpREG(uc);

        } else if (strncmp("run", str, 3) == 0) {  // 停止debug，不中断运行
            run = true;
            return;

        } else if (strncmp("brklr", str, 5) == 0) {  // 执行到lr地址
            uc_reg_read(uc, ARM_REG_LR, &brkAddress);
            printf("-------------> brklr 0x%X\n", brkAddress);

        } else if (strncmp("brk", str, 3) == 0) {  // 执行到断点地址
            brkAddress = toUint32(str);
            printf("-------------> brk 0x%X\n", brkAddress);

        } else if (str[0] == '=' && str[1] == '0' && str[2] == 'x') {  // 打印指定地址处的字符串
            uint32_t addr = toUint32(str);
            uint8_t v;
            printf("==> print 0x%x memory string: ", addr);
            do {
                uc_mem_read(uc, addr, &v, 1);
                putchar(v);
                addr++;
            } while (v);
            putchar('\n');

        } else if (str[0] == '0' && str[1] == 'x') {  // 读写内存
            if (eqPos > 0) {
                char buf[11];  // "0x4750524D".length + 1
                getEqLeftStr(str, eqPos, (char *)buf, 10);
                uint32_t addr = toUint32(buf);
                uint32_t value = toUint32(str);

                err = uc_mem_write(uc, addr, &value, 4);
                if (err) {
                    printf(
                        "==> Failed set memory addr: 0x%x=0x%x err:%u (%s)\n",
                        addr, value, err, uc_strerror(err));
                } else {
                    printf("==> set memory addr: 0x%x=0x%x\n", addr, value);
                }

            } else {
                uint32_t addr = toUint32(str);
                uint32_t value;
                err = uc_mem_read(uc, addr, &value, 4);
                if (err) {
                    printf("==> Failed read memory addr: 0x%x err:%u (%s)\n",
                           addr, err, uc_strerror(err));
                } else {
                    printf("==> read memory addr: 0x%x=0x%x  ", addr, value);
                    dumpMemStr(&value, 4);
                    putchar('\n');
                }
            }

        } else if (strchr(str, '=') != NULL) {  // 修改寄存器值
            char buf[4] = {0};
            getEqLeftStr(str, eqPos, (char *)buf, 3);
            uint32_t value = toUint32(str);

            uc_arm_reg reg = UC_ARM_REG_INVALID;
            if (buf[0] == 'r') {
                if (buf[1] == '1' && buf[2] != '\0') {  // r10-r12
                    if (buf[2] == '0') {
                        reg = UC_ARM_REG_R10;
                    } else if (buf[2] == '1') {
                        reg = UC_ARM_REG_R11;
                    } else if (buf[2] == '2') {
                        reg = UC_ARM_REG_R12;
                    }
                } else if (buf[1] >= '0' && buf[1] <= '9') {  // r0-r9
                    uc_arm_reg arr[10] = {
                        UC_ARM_REG_R0,
                        UC_ARM_REG_R1,
                        UC_ARM_REG_R2,
                        UC_ARM_REG_R3,
                        UC_ARM_REG_R4,
                        UC_ARM_REG_R5,
                        UC_ARM_REG_R6,
                        UC_ARM_REG_R7,
                        UC_ARM_REG_R8,
                        UC_ARM_REG_R9,
                    };
                    reg = arr[buf[1] - '0'];
                }
            } else if (buf[0] == 's' && buf[1] == 'p') {
                reg = UC_ARM_REG_SP;
            } else if (buf[0] == 'l' && buf[1] == 'r') {
                reg = UC_ARM_REG_LR;
            } else if (buf[0] == 'p' && buf[1] == 'c') {
                reg = UC_ARM_REG_PC;
            }
            if (reg != UC_ARM_REG_INVALID) {
                err = uc_reg_write(uc, reg, &value);
                if (err) {
                    printf("==> Failed register assign %s=0x%x err:%u (%s)\n",
                           buf, value, err, uc_strerror(err));
                } else {
                    printf("==> register assign %s=0x%x\n", buf, value);
                }
            } else {
                printf("==> register '%s' invalid\n", buf);
            }

        } else {
            // clang-format off
            printf(
                "    reg                    - print all regs\n"
                "    run                    - run\n"
                "    brk 0x80030            - run code to 0x80030\n"
                "    brklr                  - run code to lr\n"
                "    SP=0x0027FFF0          - set SP register to 0x0027FFF0\n"
                "    0x00080008             - print 0x00080008 memory content\n"
                "    =0x80E34               - print 0x80E34 address string content\n"
                "    0x00080008=0xFFFFFFFF  - set 0x00080008 memory content to 0xFFFFFFFF\n"
            );
            // clang-format on
        }
    }  // while
}
