#include <zlib.h>
#include <malloc.h>

#include "fileLib.h"
#include "mrporting.h"
#include "dsm.h"

//-----------------------------------------
int32 getMrpFileInfo(const char *path, const char *name, int32 *offset, int32 *length)
{
	int32 fd;
	int32 flStar = 0, flEnd = 0; //MRP 文件列表起、止位置
	int32 fnLen = 0, fLen;		 //mrp 内文件名长度,文件长度
	char fName[128] = {0};		 //文件名
	int32 off;

	fd = mr_open(path, MR_FILE_RDONLY);
	if (fd)
	{
		//读取文件列表终点位置
		mr_seek(fd, MR_SEEK_SET, 4);
		mr_read(fd, &flEnd, 4);
		flEnd += 8;

		//读取文件列表起始位置
		mr_seek(fd, 12, MR_SEEK_SET);
		mr_read(fd, &flStar, 4);

		while (flStar < flEnd)
		{
			//1.读取文件名
			mr_seek(fd, flStar, MR_SEEK_SET);
			mr_read(fd, &fnLen, 4);	//获取文件名长度
			mr_read(fd, fName, fnLen); //读取文件名

			if (0 != mr_strcmp(fName, name))
			{ //找到了
				goto NEXT;
			}

			//2.读取文件长度、偏移
			mr_read(fd, &off, 4);
			mr_read(fd, &fLen, 4);
			if (offset)
				*offset = off;
			if (length)
				*length = fLen;

			return MR_SUCCESS;

		NEXT:
			//3.准备读取下一个文件
			flStar = flStar + fnLen + 16; //查找下个文件
			fnLen = 0;
		}

		//读取完毕记录总数
		mr_close(fd);
	}

	return MR_FAILED;
}

// -------------- 从mrp读取文件数据 for Mrpoid 2012-9-9 eleqian --------------------
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
int ungzipdata(uint8 *dest, uint32 *destLen, const uint8 *source, uint32 sourceLen)
{
	z_stream stream;
	int err;

	stream.next_in = (Bytef *)source;
	stream.avail_in = (uInt)sourceLen;
	stream.next_out = (Bytef *)dest;
	stream.avail_out = (uInt)*destLen;
	stream.zalloc = (alloc_func)0;
	stream.zfree = (free_func)0;

	err = inflateInit2(&stream, MAX_WBITS + 16);
	if (err != Z_OK)
		return err;

	err = inflate(&stream, Z_FINISH);
	if (err != Z_STREAM_END)
	{
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
int32 readMrpFileEx(const char *path, const char *name, int32 *offset, int32 *length, uint8 **data)
{
	int32 fd = 0;
	int32 flStar, flEnd;   //MRP 文件列表起、止位置
	int32 fnLen = 0, fLen; //mrp 内文件名长度,文件长度
	char fName[128] = {0}; //文件名

	fd = mr_open(path, MR_FILE_RDONLY);
	if (0 == fd)
		goto err;

	//读取文件列表起始位置
	mr_seek(fd, 12, MR_SEEK_SET);
	mr_read(fd, &flStar, 4);

	//读取文件列表终点位置
	mr_seek(fd, 4, MR_SEEK_SET);
	mr_read(fd, &flEnd, 4);
	flEnd += 8;

	while (flStar < flEnd)
	{
		//1.读取文件名
		mr_seek(fd, flStar, MR_SEEK_SET);
		mr_read(fd, &fnLen, 4);	//获取文件名长度
		mr_read(fd, fName, fnLen); //读取文件名

		if (0 == mr_strcmp(fName, name))
		{
			int32 fOffset;

			//2.读取文件长度、偏移
			mr_read(fd, &fOffset, 4);
			mr_read(fd, &fLen, 4);

			if (NULL != offset)
				*offset = fOffset;

			// 读取文件大小
			if (NULL != length)
			{
				uint8 magic[2];

				mr_seek(fd, fOffset, MR_SEEK_SET);
				mr_read(fd, magic, 2);
				if (magic[0] == 0x1f && magic[1] == 0x8b)
				{
					mr_seek(fd, fOffset + fLen - 4, MR_SEEK_SET);
					mr_read(fd, length, 4);
				}
				else
				{
					*length = fLen;
				}
			}

			// 读取数据
			if (NULL != data)
			{
				int ret;
				uint8 *data_org;
				uint8 *data_out;
				uint32 size_out;

				data_org = mr_malloc(fLen);
				mr_seek(fd, fOffset, MR_SEEK_SET);
				mr_read(fd, data_org, fLen);
				size_out = *(uint32 *)(data_org + fLen - 4);
				data_out = mr_malloc(size_out);

				ret = ungzipdata(data_out, &size_out, data_org, fLen);
				if (Z_OK == ret)
				{
					*data = data_out;
					free(data_org);
					if (NULL != length)
						*length = size_out;
				}
				else if (Z_DATA_ERROR == ret)
				{
					*data = data_org;
					free(data_out);
				}
			}

			goto ok;
		}

		//3.准备读取下一个文件
		flStar = flStar + fnLen + 16; //查找下个文件
		fnLen = 0;
	}

ok:
	if (0 != fd)
		mr_close(fd);

	return MR_SUCCESS;

err:
	if (0 != fd)
		mr_close(fd);

	return MR_FAILED;
}

// 列出mrp内的文件
void listMrpFiles(const char *path)
{
	int32 fd = 0;
	int32 flStar, flEnd;   //MRP 文件列表起、止位置
	int32 fnLen = 0; //mrp 内文件名长度,文件长度
	char fName[128] = {0}; //文件名

	fd = mr_open(path, MR_FILE_RDONLY);
	if (MR_FAILED == fd)
		return;

	//读取文件列表起始位置
	mr_seek(fd, 12, MR_SEEK_SET);
	mr_read(fd, &flStar, 4);

	//读取文件列表终点位置
	mr_seek(fd, 4, MR_SEEK_SET);
	mr_read(fd, &flEnd, 4);
	flEnd += 8;

	while (flStar < flEnd)
	{
		//1.读取文件名
		mr_seek(fd, flStar, MR_SEEK_SET);
		mr_read(fd, &fnLen, 4);	//获取文件名长度
		mr_read(fd, fName, fnLen); //读取文件名
		LOG("listMrpFiles(): %s", fName);
		//3.准备读取下一个文件
		flStar = flStar + fnLen + 16; //查找下个文件
		fnLen = 0;
	}

	mr_close(fd);
}
