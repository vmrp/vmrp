#include "./header/fileLib.h"

#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <malloc.h>
#include <sys/stat.h>
#include <zlib.h>
#include "header/types.h"
#include "header/gb2unicode.h"
#include "header/encode.h"

/////////////////////////////////////////////////////////////////
#define HANDLE_NUM 64

// 因为系统句柄转成int32可能是负数，导致mrp编程不规范只判断是否大于0时出现遍历文件夹为空的bug，需要有一种转换机制避免返回负数
// 0号下标不使用，下标作为mrp使用的句柄，值为系统的句柄，值为-1时表示未使用
static uint32_t handles[HANDLE_NUM + 1];

char SDPath[DSM_MAX_FILE_LEN] = "mnt/sdcard"; //内存卡目录(需要初始化) 以后考虑弃用
//char *SystemPath = "system";  //系统盘目录
//char *DataPath = "data/data";  //data目录
//char *AllPath = "";   //系统根目录
// char dsmWorkPath[DSM_MAX_FILE_LEN]; //平台目录 暂时不用管
static char ProjectPath[DSM_MAX_FILE_LEN]; //运行文件路径 工程路径(绝对路径)
static char RUN_NAME[DSM_MAX_FILE_LEN]; //运行的文件名
static char PlatDir[DSM_MAX_FILE_LEN]; //平台路径
static char SDCard[DSM_MAX_FILE_LEN]; //SD卡路径
static char DocDir[DSM_MAX_FILE_LEN]; //doc文档路径
static char CacheDir[DSM_MAX_FILE_LEN]; //应用缓存路径
static char FilesDir[DSM_MAX_FILE_LEN]; //files目录
int IS_RUN = 0; //true运行器模式 false打包模式

/*
 * 整理路径，将分隔符统一为sep，并清除连续的多个
 *
 * 参数：路径(必须可读写)
 */
char *FormatPathString(char *path, char sep) {
    char *p, *q;
    int flag = 0;

    if (NULL == path)
        return NULL;

    for (p = q = path; '\0' != *p; p++) {
        if ('\\' == *p || '/' == *p) {
            if (0 == flag)
                *q++ = sep;
            flag = 1;
        }
        else {
            *q++ = *p;
            flag = 0;
        }
    }

    *q = '\0';

    return path;
}

char *dsm_getSDCard(){
    return SDCard;
}

char *dsm_getRunName(){
    return RUN_NAME;
}

void argcopy(char *cache, char *arg){
    #if defined(WIN32)
    uint32 outlen = strlen(arg)*3;
    if(IsUTF8(arg, strlen(arg)) == 0){
        char *temp = UTF8StrToGBStr(arg, &outlen);
        printf("strcpy %s \n", temp);
        strcpy(cache, temp);
        free(temp);
    }
    else{
        strcpy(cache, arg);
    }
    #else
    strcpy(cache, arg);
    #endif
}

//解析参数 配置各目录
void dsm_parseArgs(int argc, char *argv[]){
    printf("dsm_parseArgs\n");
    int i=0;
    memset(SDCard,0,sizeof(SDCard));
    memset(PlatDir,0,sizeof(PlatDir));
    memset(ProjectPath,0,sizeof(ProjectPath));
    memset(RUN_NAME,0,sizeof(RUN_NAME));
    memset(CacheDir,0,sizeof(CacheDir));
    memset(FilesDir,0,sizeof(FilesDir));
    memset(DocDir,0,sizeof(DocDir));
    argcopy(RUN_NAME,"dsm_gm.mrp");
    argcopy(SDCard,"D:\\workspace\\vmrp\\vmrp-master\\bin\\");
    if(argc == 2){
        argcopy(RUN_NAME,argv[1]);
    }
    for(i=0;i<argc;i++){
        printf("%s\n",argv[i]);
        if(strcmp(argv[i],"-cache_dir")==0){
            argcopy(CacheDir,argv[i+1]);
        }
        if(strcmp(argv[i],"-extern_dir")==0){
            argcopy(SDCard,argv[i+1]);
        }
        if(strcmp(argv[i],"-extern_filesdir")==0){
            argcopy(DocDir,argv[i+1]);
        }
        if(strcmp(argv[i],"-files_dir")==0){
            argcopy(FilesDir,argv[i+1]);
        }
        if(strcmp(argv[i],"-extern_cache_dir")==0){
            // argcopy(CacheDir,argv[i+1]);
        }
        if(strcmp(argv[i],"-plat_dir")==0){
            argcopy(PlatDir,argv[i+1]);
        }
        if(strcmp(argv[i],"-run_name")==0){
            argcopy(RUN_NAME,argv[i+1]);
        }
        if(strcmp(argv[i],"-project_dir")==0){
            argcopy(ProjectPath,argv[i+1]);
        }
        if(strcmp(argv[i],"-is_run")==0){
            IS_RUN = 1;
        }

    }
    FormatPathString(SDCard,'/');
    FormatPathString(PlatDir,'/');
    FormatPathString(ProjectPath,'/');
    FormatPathString(RUN_NAME,'/');
    FormatPathString(CacheDir,'/');
    FormatPathString(FilesDir,'/');
    FormatPathString(DocDir,'/');
    if(argc>=2)
    my_copyFileToPlat(dsm_getRunName());

}

char *my_copyFileToPlat(char *filename){
    size_t len = my_getLen(filename);
    char *buf = NULL;
    char *name = strrchr(filename,'/');
    char temp[255];
    if(name==NULL){
        name = filename;
    }
    else{
        name = name+1;
    }
    
    sprintf(temp,"%smythroad/%s",dsm_getSDCard(), name);
    printf("copy file %s %s\n",filename,temp);
    if(len>0){
        buf = malloc(len);
        FILE *in = fopen(filename, "rb");
        fread(buf,len,1,in);
        fclose(in);

    
    FILE *fout = fopen(temp, "wb+");
    fwrite(buf, len, 1, fout);
    fclose(fout);
    free(buf);
    printf("copy success\n");
    }
    else{
        printf("copy error\n");
    }
    return name;
}

char *my_getFileName(char *filename){
    size_t len = my_getLen(filename);
    char *buf = NULL;
    char *name = strrchr(filename,'/');
    if(name==NULL){
        name = filename;
    }
    else{
        name = name+1;
    }
    // sprintf(temp,"%smythroad/%s",dsm_getSDCard(), name);

    return name;
}

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

#if defined(WIN32)
    new_mode |= O_RAW;
    char path[600];
    sprintf(path, "%s%s", dsm_getSDCard(),filename);
    LOG("my_open %s",path);
    f = open(path, new_mode, S_IRWXU | S_IRWXG | S_IRWXO);
#elif defined(__ANDROID__)
    char path[600];
    sprintf(path, "%s%s", dsm_getSDCard(),filename);
    LOG("my_open %s",path);
    f = open(path, new_mode, S_IRWXU | S_IRWXG | S_IRWXO);
#endif

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
    char old[600],new[600];
    sprintf(old, "%s%s", dsm_getSDCard(),oldname);
    sprintf(new, "%s%s", dsm_getSDCard(),newname);
    int ret = rename(old, new);
    if (ret != 0) {
        return MR_FAILED;
    }
    return MR_SUCCESS;
}

int32_t my_remove(const char *filename) {
    char temp[600];
    sprintf(temp, "%s%s", dsm_getSDCard(),filename);
    int ret = remove(temp);
    if (ret != 0) {
        return MR_FAILED;
    }
    return MR_SUCCESS;
}

int32_t my_getLen(const char *filename) {
    struct stat s1;
    char temp[600];
    if(strstr(filename,":")>0){
sprintf(temp, "%s%s", "",filename);
    }
    else{
sprintf(temp, "%s%s", dsm_getSDCard(),filename);
    }
    
    int ret = stat(temp, &s1);
    

    if (ret != 0)
        return -1;
    return s1.st_size;
}

int32_t my_mkDir(const char *name) {
    int ret;
    char path[600];
    sprintf(path, "%s%s", dsm_getSDCard(),name);
    if (access(path, F_OK) == 0) {  //检测是否已存在
        goto ok;
    }
#ifndef _WIN32
    ret = mkdir(path, S_IRWXU | S_IRWXG | S_IRWXO);
#else
    ret = mkdir(path);
#endif
    if (ret != 0) {
        return MR_FAILED;
    }
ok:
    return MR_SUCCESS;
}

int32_t my_rmDir(const char *name) {
    char path[600];
    sprintf(path, "%s%s", dsm_getSDCard(),name);
    int ret = rmdir(path);
    if (ret != 0) {
        return MR_FAILED;
    }
    return MR_SUCCESS;
}

int32_t my_info(const char *filename) {
    struct stat s1;
    char path[600];
    sprintf(path, "%s%s", dsm_getSDCard(),filename);
    int ret = stat(path, &s1);

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
    char path[600];
    sprintf(path, "%s%s", dsm_getSDCard(),name);
    DIR *pDir = opendir(path);
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
    LOG("readMrpFileEx 1");
    if (0 == fd) goto err;

    //读取文件列表起始位置
    my_seek(fd, 12, MR_SEEK_SET);
    my_read(fd, &flStar, 4);

    //读取文件列表终点位置
    my_seek(fd, 4, MR_SEEK_SET);
    my_read(fd, &flEnd, 4);
    flEnd += 8;
    LOG("readMrpFileEx 2");

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

void writeFile(const char *filename, void *data, uint32 length) {
    LOG("writeFile('%s',0x%p,%u)", filename, data, length);
    int fh = my_open(filename, MR_FILE_CREATE | MR_FILE_RDWR);
    my_write(fh, data, length);
    my_close(fh);
}

int extractFile(char *filename) {
    char *writeFilename = "cfunction.ext";
    int32 offset, length;
    uint8 *data;
    int32 ret = readMrpFileEx(filename, writeFilename, &offset, &length, &data);
    if (ret == MR_SUCCESS) {
        LOG("red suc: offset:%d, length:%d", offset, length);
        writeFile(writeFilename, data, length);
    } else {
        LOG("red failed");
    }

    return 0;
}

void fileLib_init() {
    handleInit();
}