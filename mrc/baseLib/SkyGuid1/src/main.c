#include "mrc_base.h"
#include "printf.h"
#include "string.h"

#undef mrc_sprintf
#define mrc_sprintf sprintf_

extern int32 mr_c_function_load(int32 code);

int32 mrc_init(void) {
    char *filename = "sizeof.txt";
    mrc_clearScreen(0, 0, 0);
    mrc_drawText(filename, 0, 0, 255, 255, 255, 0, 1);
    mrc_refreshScreen(0, 0, 240, 320);
    {
        uintptr_tt baseAddr, addr;
        char buf[256];
        int32 f = mrc_open(filename, MR_FILE_CREATE | MR_FILE_WRONLY);
        mrc_sprintf(buf, "sizeof(char):%d\r\n", sizeof(char));
        mrc_write(f, buf, mrc_strlen(buf));

        mrc_sprintf(buf, "sizeof(short):%d\r\n", sizeof(short));
        mrc_write(f, buf, mrc_strlen(buf));

        mrc_sprintf(buf, "sizeof(int):%d\r\n", sizeof(int));
        mrc_write(f, buf, mrc_strlen(buf));

        mrc_sprintf(buf, "sizeof(long):%d\r\n", sizeof(long));
        mrc_write(f, buf, mrc_strlen(buf));

        mrc_sprintf(buf, "sizeof(long int):%d\r\n", sizeof(long int));
        mrc_write(f, buf, mrc_strlen(buf));

        mrc_sprintf(buf, "sizeof(long long):%d\r\n", sizeof(long long));
        mrc_write(f, buf, mrc_strlen(buf));

        mrc_sprintf(buf, "sizeof(void*):%d\r\n", sizeof(void *));
        mrc_write(f, buf, mrc_strlen(buf));

        mrc_sprintf(buf, "sizeof(float):%d\r\n", sizeof(float));
        mrc_write(f, buf, mrc_strlen(buf));

        mrc_sprintf(buf, "sizeof(double):%d\r\n", sizeof(double));
        mrc_write(f, buf, mrc_strlen(buf));

        baseAddr = (uintptr_tt)mr_c_function_load;
        mrc_sprintf(buf, "mr_c_function_load addr:0x%x[%u]\r\n", baseAddr, baseAddr);
        mrc_write(f, buf, mrc_strlen(buf));

        addr = (uintptr_tt)printf_;
        mrc_sprintf(buf, "printf_ addr:%u, pos:0x%x[%u]\r\n", addr, addr - baseAddr, addr - baseAddr);
        mrc_write(f, buf, mrc_strlen(buf));

        addr = (uintptr_tt)sprintf_;
        mrc_sprintf(buf, "sprintf_ addr:%u, pos:0x%x[%u]\r\n", addr, addr - baseAddr, addr - baseAddr);
        mrc_write(f, buf, mrc_strlen(buf));

        addr = (uintptr_tt)set_putchar;
        mrc_sprintf(buf, "set_putchar addr:%u, pos:0x%x[%u]\r\n", addr, addr - baseAddr, addr - baseAddr);
        mrc_write(f, buf, mrc_strlen(buf));

        // string.c
        addr = (uintptr_tt)memcpy2;
        mrc_sprintf(buf, "memcpy2 addr:%u, pos:0x%x[%u]\r\n", addr, addr - baseAddr, addr - baseAddr);
        mrc_write(f, buf, mrc_strlen(buf));

        addr = (uintptr_tt)memmove2;
        mrc_sprintf(buf, "memmove2 addr:%u, pos:0x%x[%u]\r\n", addr, addr - baseAddr, addr - baseAddr);
        mrc_write(f, buf, mrc_strlen(buf));

        addr = (uintptr_tt)strcpy2;
        mrc_sprintf(buf, "strcpy2 addr:%u, pos:0x%x[%u]\r\n", addr, addr - baseAddr, addr - baseAddr);
        mrc_write(f, buf, mrc_strlen(buf));

        addr = (uintptr_tt)strncpy2;
        mrc_sprintf(buf, "strncpy2 addr:%u, pos:0x%x[%u]\r\n", addr, addr - baseAddr, addr - baseAddr);
        mrc_write(f, buf, mrc_strlen(buf));

        addr = (uintptr_tt)strcat2;
        mrc_sprintf(buf, "strcat2 addr:%u, pos:0x%x[%u]\r\n", addr, addr - baseAddr, addr - baseAddr);
        mrc_write(f, buf, mrc_strlen(buf));

        addr = (uintptr_tt)strncat2;
        mrc_sprintf(buf, "strncat2 addr:%u, pos:0x%x[%u]\r\n", addr, addr - baseAddr, addr - baseAddr);
        mrc_write(f, buf, mrc_strlen(buf));

        addr = (uintptr_tt)memcmp2;
        mrc_sprintf(buf, "memcmp2 addr:%u, pos:0x%x[%u]\r\n", addr, addr - baseAddr, addr - baseAddr);
        mrc_write(f, buf, mrc_strlen(buf));

        addr = (uintptr_tt)strcmp2;
        mrc_sprintf(buf, "strcmp2 addr:%u, pos:0x%x[%u]\r\n", addr, addr - baseAddr, addr - baseAddr);
        mrc_write(f, buf, mrc_strlen(buf));

        addr = (uintptr_tt)strncmp2;
        mrc_sprintf(buf, "strncmp2 addr:%u, pos:0x%x[%u]\r\n", addr, addr - baseAddr, addr - baseAddr);
        mrc_write(f, buf, mrc_strlen(buf));

        addr = (uintptr_tt)memchr2;
        mrc_sprintf(buf, "memchr2 addr:%u, pos:0x%x[%u]\r\n", addr, addr - baseAddr, addr - baseAddr);
        mrc_write(f, buf, mrc_strlen(buf));

        addr = (uintptr_tt)memset2;
        mrc_sprintf(buf, "memset2 addr:%u, pos:0x%x[%u]\r\n", addr, addr - baseAddr, addr - baseAddr);
        mrc_write(f, buf, mrc_strlen(buf));

        addr = (uintptr_tt)strlen2;
        mrc_sprintf(buf, "strlen2 addr:%u, pos:0x%x[%u]\r\n", addr, addr - baseAddr, addr - baseAddr);
        mrc_write(f, buf, mrc_strlen(buf));

        addr = (uintptr_tt)strstr2;
        mrc_sprintf(buf, "strstr2 addr:%u, pos:0x%x[%u]\r\n", addr, addr - baseAddr, addr - baseAddr);
        mrc_write(f, buf, mrc_strlen(buf));

        {
            float ff = 3.14f;
            double d = 2.09;

            mrc_sprintf(buf, "%f\r\n", ff * 2);
            mrc_write(f, buf, mrc_strlen(buf));

            mrc_sprintf(buf, "%f\r\n", ff * d);
            mrc_write(f, buf, mrc_strlen(buf));
        }

        mrc_close(f);
    }
    return MR_SUCCESS;
}

int32 mrc_exitApp(void) {
    return MR_SUCCESS;
}

int32 mrc_event(int32 code, int32 param0, int32 param1) {
    return MR_SUCCESS;
}

int32 mrc_pause() {
    return MR_SUCCESS;
}

int32 mrc_resume() {
    return MR_SUCCESS;
}

int32 mrc_extRecvAppEventEx(int32 code, int32 param0, int32 param1) {
    return MR_SUCCESS;
}

int32 mrc_extRecvAppEvent(int32 app, int32 code, int32 param0, int32 param1) {
    return MR_SUCCESS;
}
