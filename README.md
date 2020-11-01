<a href="https://996.icu"><img src="https://img.shields.io/badge/link-996.icu-red.svg" alt="996.icu" /></a> 反对996是每个软件工程师的义务

# vmrp

由于mrpoid模拟器受限于安卓系统，于是决定开发一款真正的模拟器

目前完全在windows下开发并且优先考虑32位版本

目前已经实现的事件： MR_KEY_PRESS, MR_KEY_RELEASE, MR_MOUSE_MOVE, MR_MOUSE_DOWN, MR_MOUSE_UP

按键： 上下左右或wsad键控制方向，回车键是ok, q键是左功能键, e键是右功能键

目前实现的函数：
|                 |                 |                |                    | 
|-----------------|-----------------|----------------|--------------------|
| mrc_malloc()    | mrc_free()      | mrc_memcpy()   | mrc_memmove()      |
| mrc_strcpy()    | mrc_strncpy()   | mrc_strcat()   | mrc_strncat()      |
| mrc_memcmp()    | mrc_strcmp()    | mrc_strncmp()  | mrc_memchr()       |
| mrc_memset()    | mrc_strlen()    | mrc_strstr()   | mrc_sprintf()      |
| mrc_atoi()      | mrc_open()      | mrc_close()    | mrc_write()        |
| mrc_read()      | mrc_seek()      | mrc_getLen()   | mrc_remove()       |
| mrc_rename()    | mrc_mkDir()     | mrc_rmDir()    | mrc_clearScreen()  |
| mrc_drawRect()  | mrc_drawPoint() | mrc_drawText() | mrc_refreshScreen()|

如果mrp仅使用上面列出的函数开发则可以直接运行，注意入口函数是mrc_init()，如果是MRC_EXT_INIT()则是插件化开发的mrp，目前不支持。建议参考mrc/baseLib或res/asm/asm.zip这两个mrp项目。

完整版模拟器将借助mythroad层代码实现，代码在vmrp_arm项目中。

# 实现原理

mrpoid是安卓上的mrp模拟器，c语言开发的mrp是编译后的arm指令数据，因此在arm芯片上直接加载运行就可以，mrpoid就是加载mrp代码到内存中，修改mrp内部的函数表然后运行，因此必需在arm cpu才能运行

vmrp实现原理与mrpoid基本相同，参考了mrpoid早期的实现原理，不同的地方是vmrp借助unicorn engine实现真正的模拟器，并不依赖arm cpu，由于unicorn完全是一颗模拟的cpu，并且unicorn仍存在许多bug，基于unicorn开发需要对arm汇编有比较多的了解。

因为我是在windows下开发，unicorn是预编译好的，支持各种指令集，不仅仅是arm，因此编译出来的文件可能保留了其它指令集的支持导致文件变得很大，指令的hook可能是导致运行效率低下的一个原因

# 潜在bug

因为ext中的mr_c_function_load()函数是第一个函数，在mythroad层调用此函数其实相当于仍然在mythroad层调用mythroad层的东西，它会回调_mr_c_function_new()将mr_extHelper()或mr_helper()函数的地址传回mythroad，所有的事件传递都是通过这个helper函数，helper函数进去的第一件事就是备份r9寄存到r10，然后设置r9寄存器的值，在ext内的所有全局变量的读写都是基于这个寄存器提供的基地址，而在ext内调用mythroad层的函数时，r9和r10寄存器的值并没有恢复，这可能导致严重的问题，这可能就是安卓上mrpoid运行不稳定的原因，从反编译的结果来看，插件化mrp内的ext之间是有恢复r9寄存器的功能，但是没有恢复r10寄存器的功能，在目前能获得的mythroad层代码中没有看到任何恢复r9和r10的操作。


# 下载地址
https://github.com/zengming00/vmrp/releases/

# 编译方法

目前使用到的工具和库：

https://sourceforge.net/projects/mingw-w64/files/Toolchains%20targetting%20Win64/Personal%20Builds/mingw-builds/8.1.0/threads-posix/sjlj/x86_64-8.1.0-release-posix-sjlj-rt_v6-rev0.7z

https://github.com/aquynh/capstone/releases/download/4.0.1/capstone-4.0.1-win32.zip

https://github.com/unicorn-engine/unicorn/releases/download/1.0.2/unicorn-1.0.2-win32.zip

https://www.libsdl.org/release/SDL2-devel-2.0.10-mingw.tar.gz

可能需要安装zlib，我是直接从官网下载源码安装的

将capstone、SDL2、unicorn解压到./windows文件夹内，在windows下用mingw64(mingw32-make.exe)编译，我的是x86_64-8.1.0-release-posix-sjlj-rt_v6-rev0版本)
```
$ ls ./windows/ -l
drwxr-xr-x 1 zengming 197121       0  2月 29  2020 capstone-4.0.1-win32
drwxr-xr-x 1 zengming 197121       0  2月 11  2020 SDL2-2.0.10
drwxr-xr-x 1 zengming 197121       0  2月 11  2020 unicorn-1.0.1-win32
```

SDL2在linux可以通过下面的命令安装：
```
sudo apt install libsdl2-dev
```

直接`make`即可编译，使用`make DEBUG=1`可以编译出带调试功能的版本


# 参考资料

mrp编辑器:  [Mrpeditor.exe](tool/Mrpeditor.exe)

十六进制方式查看文件:
```shell
hd mythroad/arm.mrp -n 100
```

https://github.com/Yichou/mrpoid2018

https://github.com/alphaSeclab/awesome-reverse-engineering

https://github.com/nationalsecurityagency/ghidra

反汇编: 
```
arm-linux-gnueabi-objdump -b binary --start-address=0x8 -m arm -D game.ext
# 或者用radare2
r2 -a arm -b 32 -s 8 game.ext
```
（推荐）这是我自己写的反汇编工具：[de.c](tool/de.c)


arm汇编学习工具:

https://github.com/linouxis9/ARMStrong

https://github.com/unicorn-engine/unicorn

https://bbs.pediy.com/thread-253868.htm


arm平台函数传递参数，反汇编实例分析:

https://blog.csdn.net/ayu_ag/article/details/50734282

https://blog.csdn.net/gooogleman/article/details/3538033

# mrp中ext的实现原理

最早的mrp实际是由mr文件组成的，mr文件其实就是编译后的lua，后来的mrp则用c语言开发，于是会至少一有个ext文件。

因为mrp标准开发环境是xp系统+ads+vs2005+skysdk，我用的虚拟机都有8G那么大，在了解mrp实现原理后我原本想用TCC编译器做一个可以精简到几M的开发环境，可惜TCC编译器并不支持arm版本的位置无关代码的生成（TCC正式发布的版本目前不支持，可能开发版已经有支持）

在mrc/mrp文件夹中有一个关于如何只用armcc编译并生成mrp的研究成果


# License

GNU General Public License v3.0
