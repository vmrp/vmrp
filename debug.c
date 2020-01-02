#include "./header/debug.h"
#include "./header/fileLib.h"
#include "./header/mr_helper.h"
#include "./header/utils.h"

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
转换一个全小写的十六进制字符串到32位整数
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

void hook_code_debug(uc_engine *uc, uint64_t address, uint32_t size,
                     void *user_data) {
    char str[30];
    char *ptr;
    int eqPos;

    do {
        printf("debug[PC:0x%" PRIX64 ", size:0x%x] > ", address, size);
        fgets(str, sizeof(str), stdin);

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
        // printf("%s,%d, %d\n", str, str[0], '\n');
        if (str[0] == '\0') {
            break;
        } else if (strcmp("regs", str) == 0) {
            dumpREG(uc);

        } else if (str[0] == '0' && str[1] == 'x') {
            if (eqPos > 0) {
                char buf[11];  // "0x4750524D".length + 1
                getEqLeftStr(str, eqPos, (char *)buf, 10);
                uint32_t addr = toUint32(buf);
                uint32_t value = toUint32(str);

                printf("==> set memory addr: 0x%x=0x%x\n", addr, value);
                uc_mem_write(uc, addr, &value, 4);
            } else {
                uint32_t addr = toUint32(str);
                uint32_t value;
                uc_mem_read(uc, addr, &value, 4);
                printf("==> memory addr: 0x%x=0x%x\n", addr, value);
            }

        } else if (strchr(str, '=') != NULL) {
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
                        UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                        UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5,
                        UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8,
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
                printf("==> register assign %s=0x%x\n", buf, value);
                uc_reg_write(uc, reg, &value);
            }
        } else {
            // clang-format off
            printf(
                "    regs                   - print all regs\n"
                "    SP=0x0027FFF0          - set SP register to 0x0027FFF0\n"
                "    0x00080008             - print 0x00080008 memory content\n"
                "    0x00080008=0xFFFFFFFF  - set 0x00080008 memory content to 0xFFFFFFFF\n"
            );
            // clang-format on
        }
    } while (1);
}