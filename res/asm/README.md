确认真机是小端字节充（展讯是大端）

- asm.mrp  生成的mrp
- asm.zip  mrp工程的完整源代码
- asm.s    mrp工程中使用到的汇编文件
- asm.c    mrp工程中的C源代码
- cfunction.ext   mrp内提取的文件
- *.o    在mrp编译过程中在%TMP%生成的文件
- mr_cfunction.ext  在mrp编译过程中在%TMP%生成的文件
- mr_cfunction.fmt  在mrp编译过程中在%TMP%生成的文件,elf格式

以下结论只分析了一个样本得到，未经过多次验证：
```
在tmp目录下的临时文件mr_game.ext和最终在mrp中的game.ext相比
打包在mrp中的ext只是在文件开始处增加了8字节的MRPGCMAP

ext文件实际是fmt文件删头删尾，然后在开始处增加8字节MRPGCMAP
中间要保留下来的长度这样得到：
Program header在文件开头偏移量28的4字节记录
这个偏移量再加上16得到一个新的偏移量，在这个位置的4字节就是代码的长度
最后删除开始52字节(elf头)和保留长度之后的东西
```