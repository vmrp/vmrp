#include <fcntl.h>
#include <inttypes.h>
#include <io.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "./capstone-4.0.1-win32/include/capstone/capstone.h"

static char *strToLower(char *str) {
    char *ptr = str;
    while (*ptr) {
        if (*ptr >= 'A' && *ptr <= 'Z') {
            *ptr |= 32;  // 转换为小写
        }
        ptr++;
    }
    return str;
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

int main(int argc, char **argv) {
    csh handle;

    if (argc < 3) {
        printf("usage: de.exe filename offset [address]\n");
        printf("       de.exe cfunction.ext 8 0x8000\n");
        return 1;
    }

    if (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &handle) != CS_ERR_OK)
        return -1;

    int offset = atoi(argv[2]);
    char *filename = argv[1];
    struct stat s1;
    stat(filename, &s1);
    int len = s1.st_size;

    printf("offset: %d\n", offset);
    printf("file name: %s\n", filename);
    printf("file len: %d\n", len);

    char *buf = malloc(len);

    int f = open(filename, O_RDONLY | O_RAW);
    lseek(f, offset, SEEK_SET);
    read(f, buf, len);
    close(f);

    int address = 0;
    if (argc == 4) {
        address = toUint32(strToLower(argv[3]));
        printf("address: 0x%X\n", address);
    }
    putchar('\n');

    cs_insn *insn;
    size_t count = cs_disasm(handle, buf, len, address, 0, &insn);
    if (count > 0) {
        for (size_t j = 0; j < count; j++) {
            cs_insn *cur = &insn[j];
            printf("0x%" PRIx64 ": ", cur->address);
            int n = cur->size;
            for (int i = 0; i < n; i++) {
                printf("%02X", cur->bytes[i]);
            }
            printf("\t%s\t%s\n", cur->mnemonic, cur->op_str);
        }
        cs_free(insn, count);
    }
    free(buf);

    cs_close(&handle);
    return 0;
}