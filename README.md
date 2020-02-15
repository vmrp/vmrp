<a href="https://996.icu"><img src="https://img.shields.io/badge/link-996.icu-red.svg" alt="996.icu" /></a> 反对996是每个软件工程师的义务

# vmrp

由于mrpoid模拟器受限于安卓系统，于是决定开发一款真正的模拟器

前期在linux和windows下用vscode开发，后期完全在windows下开发

第一阶段目标只打算在命令行中模拟出helloworld，并且能够响应事件(已完成)

第二阶段目标完成图形化界面，可以借助原来的mrp开发环境打造windows模拟器，如果可行的话难度会大大降低，如果不可行，则要另外想办法做，有可能做成动态库提供API的形式供其它容易做图形化的语言调用(图形化界面已用go语言实现,mingw64编译mfc有些图形api没有实现)

目前已经达成了上面两个阶段的目标，暂时停止继续开发

目前已经实现三个事件： MOUSE_DOWN, MOUSE_UP, MOUSE_MOVE

目前实现的函数：

```
mrc_malloc()
mrc_free()
mrc_memcpy()
mrc_memmove()
mrc_strcpy()
mrc_strncpy()
mrc_strcat()
mrc_strncat()
mrc_memcmp()
mrc_strcmp()
mrc_strncmp()
mrc_memchr()
mrc_memset()
mrc_strlen()
mrc_strstr()
mrc_sprintf()
mrc_open()
mrc_close()
mrc_write()
mrc_clearScreen()
mrc_drawRect()
mrc_drawPoint()
mrc_drawText()
mrc_refreshScreen()
```
如果mrp仅使用上面列出的函数开发则可以直接运行，注意入口函数是mrc_init()，如果是MRC_EXT_INIT()则是插件化开发的mrp，目前不支持。建议用mrc/baseLib或res/asm/asm.zip这两个mrp项目测试

# 实现原理

mrpoid是安卓上的mrp模拟器，c语言开发的mrp是编译后的arm指令数据，因此在arm芯片上直接加载运行就可以，mrpoid就是加载mrp代码到内存中，修改mrp内部的函数表然后运行，因此必需在arm cpu才能运行

vmrp实现原理与mrpoid基本相同，参考了mrpoid早期的实现原理，不同的地方是vmrp借助unicorn engine实现真正的模拟器，并不依赖arm cpu，由于unicorn完全是一颗模拟的cpu，并且unicorn仍存在许多bug，基于unicorn开发需要对arm汇编有比较多的了解。

因为我是在windows下开发，unicorn是预编译好的，支持各种指令集，不仅仅是arm，因此编译出来的文件可能保留了其它指令集的支持导致文件变得很大，还有go语言的gui库也是编译出来的文件很大，以及对图像的操作可能有些地方有待优化，指令的hook可能也是导致运行效率低下的一个原因

# 下载地址
https://github.com/zengming00/vmrp/releases/tag/1.0.0

# 编译方法

可能需要安装zlib，我是直接从官网下载源码安装的

需要安装unicorn (windows下载预编译文件unicorn-1.0.1，解压到./windows文件夹内，在windows下用mingw64(mingw32-make.exe)编译，我的是x86_64-8.1.0-release-posix-sjlj-rt_v6-rev0版本)
```
$ ls ./windows/ -l
total 8
drwxr-xr-x 1 zengming 197121 0 2月  11 17:10 unicorn-1.0.1-win32
drwxr-xr-x 1 zengming 197121 0 2月  11 17:09 unicorn-1.0.1-win64
```

make命令：在windows下用mingw32-make.exe，在linux下直接make

编译命令行测试程序: 直接输入make

编译SDL版本的图形化程序：
1. make lib
2. 下载解压SDL2到./GUI/lib/（我使用的版本是SDL2-2.0.10）
3. cd GUI/SDL
4. make 或 make win32
注意如果是make win32则在make lib时必需确保生成的libvmrp.a是32位版本，在64位系统下编译时gcc需要加 -m32 标志

编译go语言版本的图形化程序： 由于直接用mingw64编译mfc没有成功，所以改用了go语言，使用的版本是go1.12.7

1. make lib
2. cd GUI/golang/
3. go build

linux编译：
```
sudo apt install libsdl2-dev
```

# 参考资料
十六进制方式查看文件
```shell
hd mythroad/arm.mrp -n 100
```

https://github.com/Yichou/mrpoid2018

https://github.com/alphaSeclab/awesome-reverse-engineering

https://github.com/nationalsecurityagency/ghidra

反汇编：

```
arm-linux-gnueabi-objdump -b binary --start-address=0x8 -m arm -D game.ext
```

或radare2
```
r2 -a arm -b 32 -s 8 game.ext
```

arm汇编学习工具:

https://github.com/linouxis9/ARMStrong

https://github.com/unicorn-engine/unicorn

https://bbs.pediy.com/thread-253868.htm


arm平台函数传递参数，反汇编实例分析:

https://blog.csdn.net/ayu_ag/article/details/50734282

https://blog.csdn.net/gooogleman/article/details/3538033

# License

GNU General Public License v3.0
