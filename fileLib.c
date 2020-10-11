#include "./header/fileLib.h"

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
    int32_t ret = handle2int32(f);
    printf("my_open(%s,%d) fd is: %d\n", filename, new_mode, ret);
    return ret;
}

int32_t my_close(int32_t f) {
    if (f == 0)
        return MR_FAILED;

    int ret = close(int32ToHandle(f));
    handleDel(f);
    if (ret != 0) {
        return MR_FAILED;
    }
    printf("my_close(%d) suc\n", f);
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

//-----------------------------------------
int32 getMrpFileInfo(const char *path, const char *name, int32 *offset,
                     int32 *length) {
    int32 fd;
    int32 flStar = 0, flEnd = 0;  // MRP 文件列表起、止位置
    int32 fnLen = 0, fLen;        // mrp 内文件名长度,文件长度
    char fName[128] = {0};        //文件名
    int32 off;

    fd = my_open(path, MR_FILE_RDONLY);
    if (fd) {
        //读取文件列表终点位置
        my_seek(fd, MR_SEEK_SET, 4);
        my_read(fd, &flEnd, 4);
        flEnd += 8;

        //读取文件列表起始位置
        my_seek(fd, 12, MR_SEEK_SET);
        my_read(fd, &flStar, 4);

        while (flStar < flEnd) {
            // 1.读取文件名
            my_seek(fd, flStar, MR_SEEK_SET);
            my_read(fd, &fnLen, 4);     //获取文件名长度
            my_read(fd, fName, fnLen);  //读取文件名

            if (0 != strcmp(fName, name)) {  //找到了
                goto NEXT;
            }

            // 2.读取文件长度、偏移
            my_read(fd, &off, 4);
            my_read(fd, &fLen, 4);
            if (offset) *offset = off;
            if (length) *length = fLen;

            return MR_SUCCESS;

        NEXT:
            // 3.准备读取下一个文件
            flStar = flStar + fnLen + 16;  //查找下个文件
            fnLen = 0;
        }

        //读取完毕记录总数
        my_close(fd);
    }

    return MR_FAILED;
}

// -------------- 从mrp读取文件数据 for Mrpoid 2012-9-9 eleqian
// --------------------
/*
解压gzip数据
备注：
改编自zlib中uncompress函数 2012-9-9 eleqian
返回值：
Z_OK - 成功
Z_MEM_ERROR - 内存不足
Z_BUF_ERROR - 输出缓冲区不足
Z_DATA_ERROR - 数据错误
*/
int ungzipdata(uint8 *dest, uint32 *destLen, const uint8 *source,
               uint32 sourceLen) {
    z_stream stream;
    int err;

    stream.next_in = (Bytef *)source;
    stream.avail_in = (uInt)sourceLen;
    stream.next_out = (Bytef *)dest;
    stream.avail_out = (uInt)*destLen;
    stream.zalloc = (alloc_func)0;
    stream.zfree = (free_func)0;

    err = inflateInit2(&stream, MAX_WBITS + 16);
    if (err != Z_OK) return err;

    err = inflate(&stream, Z_FINISH);
    if (err != Z_STREAM_END) {
        inflateEnd(&stream);
        if (err == Z_NEED_DICT || (err == Z_BUF_ERROR && stream.avail_in == 0))
            return Z_DATA_ERROR;
        return err;
    }

    *destLen = stream.total_out;
    err = inflateEnd(&stream);

    return err;
}

// 读取mrp文件
// 参数：mrp路径，读取文件，读取位置(返回)，读取大小(返回，解压后)，读取的数据(返回，尝试解压)
// 返回：成功或失败
int32 readMrpFileEx(const char *path, const char *name, int32 *offset,
                    int32 *length, uint8 **data) {
    int32 fd = 0;
    int32 flStar, flEnd;    // MRP 文件列表起、止位置
    int32 fnLen = 0, fLen;  // mrp 内文件名长度,文件长度
    char fName[128] = {0};  //文件名

    fd = my_open(path, MR_FILE_RDONLY);
    if (0 == fd) goto err;

    //读取文件列表起始位置
    my_seek(fd, 12, MR_SEEK_SET);
    my_read(fd, &flStar, 4);

    //读取文件列表终点位置
    my_seek(fd, 4, MR_SEEK_SET);
    my_read(fd, &flEnd, 4);
    flEnd += 8;

    while (flStar < flEnd) {
        // 1.读取文件名
        my_seek(fd, flStar, MR_SEEK_SET);
        my_read(fd, &fnLen, 4);     //获取文件名长度
        my_read(fd, fName, fnLen);  //读取文件名

        if (0 == strcmp(fName, name)) {
            int32 fOffset;

            // 2.读取文件长度、偏移
            my_read(fd, &fOffset, 4);
            my_read(fd, &fLen, 4);

            if (NULL != offset) *offset = fOffset;

            // 读取文件大小
            if (NULL != length) {
                uint8 magic[2];

                my_seek(fd, fOffset, MR_SEEK_SET);
                my_read(fd, magic, 2);
                if (magic[0] == 0x1f && magic[1] == 0x8b) {
                    my_seek(fd, fOffset + fLen - 4, MR_SEEK_SET);
                    my_read(fd, length, 4);
                } else {
                    *length = fLen;
                }
            }

            // 读取数据
            if (NULL != data) {
                int ret;
                uint8 *data_org;
                uint8 *data_out;
                uint32 size_out;

                data_org = malloc(fLen);
                my_seek(fd, fOffset, MR_SEEK_SET);
                my_read(fd, data_org, fLen);
                size_out = *(uint32 *)(data_org + fLen - 4);
                data_out = malloc(size_out);

                ret = ungzipdata(data_out, &size_out, data_org, fLen);
                if (Z_OK == ret) {
                    *data = data_out;
                    free(data_org);
                    if (NULL != length) *length = size_out;
                } else if (Z_DATA_ERROR == ret) {
                    *data = data_org;
                    free(data_out);
                }
            }

            goto ok;
        }

        // 3.准备读取下一个文件
        flStar = flStar + fnLen + 16;  //查找下个文件
        fnLen = 0;
    }

ok:
    if (0 != fd) my_close(fd);

    return MR_SUCCESS;

err:
    if (0 != fd) my_close(fd);

    return MR_FAILED;
}

// 列出mrp内的文件
void listMrpFiles(const char *path) {
    int32 fd = 0;
    int32 flStar, flEnd;    // MRP 文件列表起、止位置
    int32 fnLen = 0;        // mrp 内文件名长度,文件长度
    char fName[128] = {0};  //文件名

    fd = my_open(path, MR_FILE_RDONLY);
    if (MR_FAILED == fd) return;

    //读取文件列表起始位置
    my_seek(fd, 12, MR_SEEK_SET);
    my_read(fd, &flStar, 4);

    //读取文件列表终点位置
    my_seek(fd, 4, MR_SEEK_SET);
    my_read(fd, &flEnd, 4);
    flEnd += 8;

    while (flStar < flEnd) {
        // 1.读取文件名
        my_seek(fd, flStar, MR_SEEK_SET);
        my_read(fd, &fnLen, 4);     //获取文件名长度
        my_read(fd, fName, fnLen);  //读取文件名
        LOG("listMrpFiles(): %s", fName);
        // 3.准备读取下一个文件
        flStar = flStar + fnLen + 16;  //查找下个文件
        fnLen = 0;
    }

    my_close(fd);
}

void fileLib_init() {
    handleInit();
}