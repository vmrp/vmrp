#include "./header/fileLib.h"

#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <malloc.h>
#include <sys/stat.h>
#include <zlib.h>

/////////////////////////////////////////////////////////////////
#define HANDLE_NUM 64

// 因为系统句柄转成int32可能是负数，导致mrp编程不规范只判断是否大于0时出现遍历文件夹为空的bug，需要有一种转换机制避免返回负数
// 0号下标不使用，下标作为mrp使用的句柄，值为系统的句柄，值为-1时表示未使用
static uint32_t handles[HANDLE_NUM + 1];

static void handleInit() {
    for (int i = 1; i <= HANDLE_NUM; i++) {
        handles[i] = -1;
    }
}
// 注意： mrc_open需要返回0表示失败， mrc_findStart需要返回-1表示失败，这里没做区分
static int32_t handle2int32(uint32_t v) {
    for (int i = 1; i <= HANDLE_NUM; i++) {
        if (handles[i] == -1) {
            handles[i] = v;
            return i;
        }
    }
    return -1;  // 失败
}

static uint32_t int32ToHandle(int32_t v) {
    if (v <= 0 || v > HANDLE_NUM) {
        return -1;
    }
    return handles[v];
}

static void handleDel(int32_t v) {
    if (v <= 0 || v > HANDLE_NUM) {
        return;
    }
    handles[v] = -1;
}
/////////////////////////////////////////////////////////////////

int32_t my_open(const char *filename, uint32_t mode) {
    int f;
    int new_mode = 0;

    if (mode & MR_FILE_RDONLY) new_mode = O_RDONLY;
    if (mode & MR_FILE_WRONLY) new_mode = O_WRONLY;
    if (mode & MR_FILE_RDWR) new_mode = O_RDWR;
    if (mode & MR_FILE_CREATE) new_mode |= O_CREAT;

#ifdef _WIN32
    new_mode |= O_RAW;
#endif

    f = open((char *)filename, new_mode, S_IRWXU | S_IRWXG | S_IRWXO);
    if (f == -1) {
        return 0;
    }
    return handle2int32(f);
}

int32_t my_close(int32_t f) {
    if (f == 0)
        return MR_FAILED;

    int ret = close(int32ToHandle(f));
    handleDel(f);
    if (ret != 0) {
        return MR_FAILED;
    }
    return MR_SUCCESS;
}

int32_t my_seek(int32_t f, int32_t pos, int method) {
    off_t ret = lseek(int32ToHandle(f), (off_t)pos, method);
    if (ret < 0) {
        return MR_FAILED;
    }
    return MR_SUCCESS;
}

int32_t my_read(int32_t f, void *p, uint32_t l) {
    int32_t readnum = read(int32ToHandle(f), p, (size_t)l);
    if (readnum < 0) {
        return MR_FAILED;
    }
    return readnum;
}

int32_t my_write(int32_t f, void *p, uint32_t l) {
    int32_t writenum = write(int32ToHandle(f), p, (size_t)l);
    if (writenum < 0) {
        return MR_FAILED;
    }
    return writenum;
}

int32_t my_rename(const char *oldname, const char *newname) {
    int ret = rename(oldname, newname);
    if (ret != 0) {
        return MR_FAILED;
    }
    return MR_SUCCESS;
}

int32_t my_remove(const char *filename) {
    int ret = remove(filename);
    if (ret != 0) {
        return MR_FAILED;
    }
    return MR_SUCCESS;
}

int32_t my_getLen(const char *filename) {
    struct stat s1;
    int ret = stat(filename, &s1);
    if (ret != 0)
        return -1;
    return s1.st_size;
}

int32_t my_mkDir(const char *name) {
    int ret;
    if (access(name, F_OK) == 0) {  //检测是否已存在
        goto ok;
    }
#ifndef _WIN32
    ret = mkdir(name, S_IRWXU | S_IRWXG | S_IRWXO);
#else
    ret = mkdir(name);
#endif
    if (ret != 0) {
        return MR_FAILED;
    }
ok:
    return MR_SUCCESS;
}

int32_t my_rmDir(const char *name) {
    int ret = rmdir(name);
    if (ret != 0) {
        return MR_FAILED;
    }
    return MR_SUCCESS;
}

int32_t my_info(const char *filename) {
    struct stat s1;
    int ret = stat(filename, &s1);

    if (ret != 0) {
        return MR_IS_INVALID;
    }
    if (s1.st_mode & S_IFDIR) {
        return MR_IS_DIR;
    } else if (s1.st_mode & S_IFREG) {
        return MR_IS_FILE;
    }
    return MR_IS_INVALID;
}

int32_t my_opendir(const char *name) {
    DIR *pDir = opendir(name);
    if (pDir != NULL) {
        return handle2int32((uint32_t)pDir);
    }
    return MR_FAILED;
}

char *my_readdir(int32_t f) {
    DIR *pDir = (DIR *)int32ToHandle(f);
    struct dirent *pDt = readdir(pDir);
    if (pDt != NULL) {
        return pDt->d_name;
    }
    return NULL;
}

int32_t my_closedir(int32_t f) {
    DIR *pDir = (DIR *)int32ToHandle(f);
    closedir(pDir);
    handleDel(f);
    return MR_SUCCESS;
}

void writeFile(const char *filename, void *data, uint32 length) {
    int fh = my_open(filename, MR_FILE_CREATE | MR_FILE_RDWR);
    int32_t wLen = 0;
    char *ptr = (char *)data;
    do {
        ptr += wLen;
        wLen = my_write(fh, ptr, length < 1000 ? length : 1000);
        if (wLen == MR_FAILED) {
            break;
        }
        length -= wLen;
    } while (length > 0);
    my_close(fh);
}

char *readFile(const char *filename) {
    int32_t len = my_getLen(filename);
    char *p = malloc(len);
    if (p == NULL) {
        return NULL;
    }
    int32_t fh = my_open(filename, MR_FILE_RDONLY);
    if (fh) {
        int32_t rLen = 0;
        char *ptr = p;
        do {
            ptr += rLen;
            rLen = my_read(fh, ptr, len);
            if (rLen == MR_FAILED) {
                free(p);
                return NULL;
            }
            len -= rLen;
        } while (len > 0);
        my_close(fh);
        return p;
    }
    return NULL;
}

void fileLib_init() {
    handleInit();
}