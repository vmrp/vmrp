#ifndef _FILELIB_H
#define _FILELIB_H

#include "types.h"

#define MR_FILE_RDONLY 1  //以只读的方式打开文件。
#define MR_FILE_WRONLY 2  //以只写的方式打开文件。
#define MR_FILE_RDWR 4    //以读写的方式打开文件。
#define MR_FILE_CREATE 8  //如果文件不存在，创建该文件。

#define MR_IS_FILE 1     //文件
#define MR_IS_DIR 2      //目录
#define MR_IS_INVALID 8  //无效(非文件、非目录)

enum {
    MR_SEEK_SET,
    MR_SEEK_CUR,
    MR_SEEK_END
};

// 注意在mrp中的字符编码
int32_t my_open(const char *filename, uint32_t mode);
int32_t my_close(int32_t f);
int32_t my_seek(int32_t f, int32_t pos, int method);
int32_t my_read(int32_t f, void *p, uint32_t l);
int32_t my_write(int32_t f, void *p, uint32_t l);
int32_t my_rename(const char *oldname, const char *newname);
int32_t my_remove(const char *filename);
int32_t my_getLen(const char *filename);
int32_t my_mkDir(const char *name);
int32_t my_rmDir(const char *name);
int32_t my_info(const char *filename);
int32_t my_opendir(const char *name);
char *my_readdir(int32_t f);
int32_t my_closedir(int32_t f);

int32 getMrpFileInfo(const char *path, const char *name, int32 *offset, int32 *length);

int32 readMrpFileEx(const char *path, const char *name, int32 *offset, int32 *length, uint8 **data);

int ungzipdata(uint8 *dest, uint32 *destLen, const uint8 *source, uint32 sourceLen);

void listMrpFiles(const char *path);

void fileLib_init();
#endif
