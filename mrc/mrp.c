#include "mrc_base.h"
#include "mrc_exb.h"
#include "mrp.h"

int32 ToMrp(const char *InDir, const char *OutMrp, int32 RAM, TOMRPINFO *info, Ptr_TOMRP_progbar TOMRP_progbar)
{
#define BUFFERLEN 240
#define FILENAMELEN 255

    int32 search_handle = 0;
    int32 MRPHandle = 0;
    int32 fileHandle = 0;

    uint8 error = 0;

    char *buffer = NULL;
    char *filename = NULL;
    char *tempfile = NULL;
    char *xiegang = "/";

    int32 listLen = 0;
    int32 str_len = 0;
    int32 filepy = 0;  //文件偏移
    int32 fileLen = 0; //文件长度
    int32 space = 0;   //空白字节

    //////////////////////////////////////////////////////////////////////////////

    filename = (char *)malloc(FILENAMELEN);
    buffer = (char *)malloc(BUFFERLEN);

    mrc_memset(buffer, 0, BUFFERLEN);
    TOMRP_progbar(1, 0);
    search_handle = mrc_findStart(InDir, buffer, BUFFERLEN);
    if (search_handle == MR_FAILED)
    {
        mrc_free((void *)filename);
        mrc_free((void *)buffer);
        return MRP_SEARCHFAILED;
    }
    TOMRP_progbar(2, 0);
    //计算列表长度
    do
    {
        mrc_memset(filename, 0, FILENAMELEN);
        mrc_strcpy(filename, InDir);
        mrc_strcat(filename, xiegang);
        mrc_strcat(filename, buffer);

        if (mrc_fileState(filename) == MR_IS_FILE && mrc_strlen(buffer) < BUFFERLEN)
        {
            listLen += (mrc_strlen(buffer) + 17);
        }
        else
        {
            error++;
        }
    } while (!mrc_findGetNext(search_handle, buffer, BUFFERLEN));
    mrc_findStop(search_handle);
    if (!listLen) //如果列表长度为O出错
    {
        mrc_free((void *)filename);
        mrc_free((void *)buffer);
        return MRP_LISTLENFAILED;
    }
    TOMRP_progbar(3, 0);

    mrc_free((void *)buffer);
    buffer = (char *)mrc_readFileFromMrp("head", &str_len, 0);

    mrc_remove(OutMrp); //删除旧文件
    MRPHandle = mrc_open(OutMrp, MR_FILE_RDWR | MR_FILE_CREATE);
    if (!MRPHandle) //无法打开文件
    {
        mrc_free((void *)filename);
        if (buffer != NULL)
            mrc_freeFileData((void *)buffer, str_len);
        return MRP_OPENFAILED;
    }
    if (buffer != NULL)
    {
        mrc_write(MRPHandle, buffer, str_len); //240文件头
        mrc_freeFileData((void *)buffer, str_len);
    }
    buffer = (char *)malloc(BUFFERLEN);

    TOMRP_progbar(4, 0);
    listLen += 232; //数据区位置(文件头信息)
    mrc_seek(MRPHandle, 4, MR_SEEK_SET);
    mrc_write(MRPHandle, &listLen, 4);
    mrc_seek(MRPHandle, 240, MR_SEEK_SET);
    listLen += 8;     //数据区起始位置（所有文件偏移的基础值）
    filepy = listLen; //第一个文件偏移
    search_handle = mrc_findStart(InDir, buffer, BUFFERLEN);
    if (search_handle == MR_FAILED)
    {
        mrc_close(MRPHandle);
        mrc_free((void *)filename);
        mrc_free((void *)buffer);
        return MRP_SEARCHFAILED;
    }
    //建立文件列表
    do
    {
        mrc_memset(filename, 0, FILENAMELEN);
        mrc_strcpy(filename, InDir);
        mrc_strcat(filename, xiegang);
        mrc_strcat(filename, buffer);

        str_len = mrc_strlen(buffer);
        if (mrc_fileState(filename) == MR_IS_FILE && str_len < BUFFERLEN)
        {
            str_len++;                               //文件名长度加1
            mrc_write(MRPHandle, &str_len, 4);       //写文件名长度
            mrc_write(MRPHandle, buffer, str_len);   //写文件名
            filepy = filepy + fileLen + str_len + 8; //计算文件偏移
            fileLen = mrc_getLen(filename);
            mrc_write(MRPHandle, &filepy, 4);  //写文件偏移
            mrc_write(MRPHandle, &fileLen, 4); //写文件长度
            mrc_write(MRPHandle, &space, 4);
        }
        else
        {
            error++;
        }
    } while (!mrc_findGetNext(search_handle, buffer, BUFFERLEN));
    mrc_findStop(search_handle);
    TOMRP_progbar(5, 0);
    search_handle = mrc_findStart(InDir, buffer, BUFFERLEN);
    if (search_handle == MR_FAILED)
    {
        mrc_close(MRPHandle);
        mrc_free((void *)filename);
        mrc_free((void *)buffer);
        return MRP_SEARCHFAILED;
    }
    //完成文件数据
    tempfile = (char *)malloc(RAM);
    do
    {
        mrc_memset(filename, 0, FILENAMELEN);
        mrc_strcpy(filename, InDir);
        mrc_strcat(filename, xiegang);
        mrc_strcat(filename, buffer);

        str_len = mrc_strlen(buffer);
        if (mrc_fileState(filename) == MR_IS_FILE && str_len < BUFFERLEN)
        {
            str_len++;                             //文件名长度加1
            mrc_write(MRPHandle, &str_len, 4);     //写文件名长度
            mrc_write(MRPHandle, buffer, str_len); //写文件名
            fileLen = mrc_getLen(filename);
            mrc_write(MRPHandle, &fileLen, 4); //写文件长度

            str_len = RAM; //内存缓冲区长度
            fileHandle = mrc_open(filename, MR_FILE_RDONLY);
            if (!fileHandle)
                error++; //此处报错不作任何额外处理(没有太大影响)
            while (fileLen)
            {
                if (fileLen > str_len)
                {
                    fileLen -= str_len;
                }
                else
                {
                    str_len = fileLen;
                    fileLen = 0;
                }
                mrc_read(fileHandle, tempfile, str_len);
                mrc_write(MRPHandle, tempfile, str_len);
            }
            mrc_close(fileHandle);
        }
        else
        {
            error++; //统计错误数
        }
    } while (!mrc_findGetNext(search_handle, buffer, BUFFERLEN));
    mrc_findStop(search_handle);

    mrc_free((void *)tempfile);
    TOMRP_progbar(6, 0);

    //更新文件头
    mrc_close(MRPHandle);
    fileLen = mrc_getLen(OutMrp);
    MRPHandle = mrc_open(OutMrp, MR_FILE_RDWR);
    if (!MRPHandle)
    {
        mrc_free((void *)filename);
        mrc_free((void *)buffer);
        return MRP_OPENFAILED;
    }
    mrc_seek(MRPHandle, 8, MR_SEEK_SET);
    mrc_write(MRPHandle, &fileLen, 4);

    mrc_seek(MRPHandle, 16, MR_SEEK_SET);
    mrc_memset(buffer, 0, 12);
    mrc_strcpy(buffer, info->filename);
    mrc_write(MRPHandle, buffer, 12); //写内部文件名

    mrc_memset(buffer, 0, 24);
    mrc_strcpy(buffer, info->appname);
    mrc_write(MRPHandle, buffer, 24); //写显示名

    mrc_seek(MRPHandle, 68, MR_SEEK_SET);
    mrc_write(MRPHandle, &(info->appid), 4);   //写APPID
    mrc_write(MRPHandle, &(info->version), 4); //写版本

    mrc_seek(MRPHandle, 88, MR_SEEK_SET);
    mrc_memset(buffer, 0, 40);
    mrc_strcpy(buffer, info->vendor);
    mrc_write(MRPHandle, buffer, 40); //写作者

    mrc_memset(buffer, 0, 64);
    mrc_strcpy(buffer, info->description);
    mrc_write(MRPHandle, buffer, 64); //写介绍

    mrc_seek(MRPHandle, 192, MR_SEEK_SET);
    listLen = mrc_htonl(info->appid);
    mrc_write(MRPHandle, &listLen, 4); //写APPID
    listLen = mrc_htonl(info->version);
    mrc_write(MRPHandle, &listLen, 4); //写版本

    error -= 6;
    error = error / 3 + error % 3;
    TOMRP_progbar(7, error);

    mrc_close(MRPHandle);
    mrc_free((void *)buffer);
    mrc_free((void *)filename);
    return MRP_SUCCESS;
}

int32 UnMrp(char *MRPName, char *ToDir, int32 RAM)
{
    int32 MRPhandle,
        FileHandle;
    uint32 filenamelen;
    char filename[50];
    char filename2[128];
    uint8 *filebuf;
    int32 unfilelen;
    int32 unfilewz;
    int32 RAMlen;
    int32 sum = 0; //成功数
    T_MRP_HEAD mrp_head;

    //////////////////////////////////////////////////////////////

    mrc_mkDir(ToDir);
    MRPhandle = mrc_open(MRPName, MR_FILE_RDONLY); //打开文件
    if (!MRPhandle)
        goto aa;
    mrc_read(MRPhandle, &mrp_head, sizeof(T_MRP_HEAD));
    if (mrc_strncmp(mrp_head.Magic, "MRPG", 4)) //简单判断是否为正确的MRP格式
    {
        mrc_close(MRPhandle);
        goto aa;
    }
    mrp_head.FileStart += 8;
    while (mrp_head.ListStart < mrp_head.FileStart)
    {
        filebuf = NULL;
        mrc_seek(MRPhandle, mrp_head.ListStart, MR_SEEK_SET); //移到到列表处
        mrc_read(MRPhandle, &filenamelen, 4);                 //文件名长度
        mrc_read(MRPhandle, filename, filenamelen);           //文件名
        mrc_read(MRPhandle, &unfilewz, 4);
        mrc_read(MRPhandle, &unfilelen, 4);
        mrp_head.ListStart += filenamelen + 16; //将位置移到下个列表处

        mrc_strcpy(filename2, ToDir);
        mrc_strcat(filename2, "\\");
        mrc_strcat(filename2, filename);
        mrc_remove(filename2);
        FileHandle = mrc_open(filename2, MR_FILE_RDWR | MR_FILE_CREATE);
        if (!FileHandle)
            continue;
        mrc_seek(MRPhandle, unfilewz, MR_SEEK_SET);
        mrc_read(MRPhandle, &filenamelen, 4);
        if (filenamelen == 0x00088B1F) //判断是否为压缩文件
        {
            mrc_close(MRPhandle);
            if (mrc_readFileFromMrpExA(MRPName, filename, &filebuf, &unfilelen, 3))
            {
                mrc_close(FileHandle);
                MRPhandle = mrc_open(MRPName, MR_FILE_RDONLY); //重新打开文件
                continue;
            }
            MRPhandle = mrc_open(MRPName, MR_FILE_RDONLY); //重新打开文件
            mrc_write(FileHandle, filebuf, unfilelen);
            mrc_freeFileData((void *)filebuf, unfilelen);
        }
        else //写出压缩数据
        {
            filebuf = (uint8 *)malloc(RAM);
            RAMlen = RAM;
            mrc_seek(MRPhandle, unfilewz, MR_SEEK_SET);
            while (unfilelen)
            {
                if (unfilelen > RAMlen)
                    unfilelen -= RAMlen;
                else
                {
                    RAMlen = unfilelen;
                    unfilelen = 0;
                }
                mrc_read(MRPhandle, (void *)filebuf, RAMlen);
                mrc_write(FileHandle, filebuf, RAMlen);
            }
            mrc_free((void *)filebuf);
        }
        sum += 1;
        mrc_close(FileHandle);
    }
    mrc_close(MRPhandle);
    return sum;
aa:
    return MR_FAILED;
}