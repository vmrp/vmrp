<a href="https://996.icu"><img src="https://img.shields.io/badge/link-996.icu-red.svg" alt="996.icu" /></a> 反对996是每个软件工程师的义务

# vmrp

由于mrpoid模拟器受限于安卓系统，于是决定开发一款真正的模拟器

前期在linux和windows下用vscode开发，后期完全在windows下开发

第一阶段目标只打算在命令行中模拟出helloworld，并且能够响应事件(已完成)

第二阶段目标完成图形化界面，可以借助原来的mrp开发环境打造windows模拟器，如果可行的话难度会大大降低，如果不可行，则要另外想办法做，有可能做成动态库提供API的形式供其它容易做图形化的语言调用(图形化界面已用go语言实现,mingw64编译mfc有些图形api没有实现)

目前已经达成了上面两个阶段的目标，因为有不少人用模拟器做刷量牟利，因此我并不打算将这个模拟器完善，能跑helloworld就是我的目的，现在**停止继续开发**

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
mrc_read()
mrc_seek()
mrc_getLen()
mrc_remove()
mrc_rename()
mrc_mkDir()
mrc_rmDir()
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

目前使用到的工具和库：

https://sourceforge.net/projects/mingw-w64/files/Toolchains%20targetting%20Win64/Personal%20Builds/mingw-builds/8.1.0/threads-posix/sjlj/x86_64-8.1.0-release-posix-sjlj-rt_v6-rev0.7z

https://github.com/aquynh/capstone/releases/download/4.0.1/capstone-4.0.1-win32.zip

https://github.com/unicorn-engine/unicorn/releases/download/1.0.1/unicorn-1.0.1-win32.zip

https://www.libsdl.org/release/SDL2-devel-2.0.10-mingw.tar.gz

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

# mrp中ext的实现原理

最早的mrp实际是由mr文件组成的，mr文件其实就是编译后的lua，后来的mrp则用c语言开发，于是会至少一有个ext文件。

因为mrp标准开发环境是xp系统+ads+vs2005+skysdk，我用的虚拟机都有8G那么大，在了解mrp实现原理后我原本想用TCC编译器做一个可以精简到几M的开发环境，可惜TCC编译器并不支持arm版本的位置无关代码的生成（TCC正式发布的版本目前不支持，可能开发版已经有支持）

```c
// 定义函数指针类型
typedef void (*MRC_DRAWRECT)(int16 x, int16 y, int16 w, int16 h, uint8 r, uint8 g, uint8 b);
typedef int32 (*MRC_DRAWTEXT)(char *pcText, int16 x, int16 y, uint8 r, uint8 g, uint8 b, int is_unicode, uint16 font);
typedef void (*MRC_REFRESHSCREEN)(int16 x, int16 y, uint16 w, uint16 h);

// 定义一个函数表，通过调用ext中的第一个函数时用参数把这个表传递进去，使得ext能够调用到系统函数
typedef struct funcTable
{
    MRC_DRAWRECT mrc_drawRect;
    MRC_DRAWTEXT mrc_drawText;
    MRC_REFRESHSCREEN mrc_refreshScreen;
} funcTable;

// 事件框架的函数指针类型
typedef int32 (*MRC_INIT)(void);
typedef int32 (*MRC_EVENT)(int32 code, int32 param0, int32 param1);

// 事件框架的函数表，使系统能够调用到我们的事件函数
typedef struct cbTable
{
    MRC_INIT init;
    MRC_EVENT event;
} cbTable;

// 全局的函数变量
MRC_DRAWRECT mrc_drawRect;
MRC_DRAWTEXT mrc_drawText;
MRC_REFRESHSCREEN mrc_refreshScreen;

/*
实际上mrp中的ext就是一种类似dll的东西，只不过是由斯凯特殊定制的，
ext的第8个字节开始就是第一个函数，相当于我这个_start()函数，
前8个字节实际上是两个结构体的内存地址，因为是32位cpu，所以是8字节，会在加载ext后由系统进行修改，相当于我这里写的p和ret参数，
事实上我们除了知道第8字节后是第一个函数外，我们根本不知道其它函数在什么地方，因为ext中只有指令和数据，没有其它任何信息，
因为ext是类似dll的东西，所以ext必需完全是位置无关的（参考gcc -fPIC编译参数）
*/
int32 _start(funcTable *p, cbTable *ret)
{
    // 将系统传过来的函数表复制到本地，供我们的代码使用
    mrc_drawRect = p->mrc_drawRect;
    mrc_drawText = p->mrc_drawText;
    mrc_refreshScreen = p->mrc_refreshScreen;

    // 因为C语言需要先声明才能使用，这里是下面两个函数的声明
    int32 mrc_init(void);
    int32 mrc_event(int32 code, int32 param0, int32 param1);

    // 将我们的事件函数地址传递给系统，当发生按键、触屏之类的事件时系统才知道要调用谁
    ret->init = mrc_init;
    ret->event = mrc_event;
    return 0;
}

/////////////////////////////////////////// 以下就是正常的mrp开发代码了 //////////////////////////////////////////////////////////}

int32 mrc_init(void)
{
    mrc_drawRect(0, 0, 240, 320, 255, 255, 0);
    mrc_drawText("hello mrp!", 0, 0, 0, 0, 0, 0, 1);
    mrc_refreshScreen(0, 0, 240, 320);
    return 0;
}

int32 mrc_event(int32 code, int32 param0, int32 param1)
{
    return 0;
}
```

# License

GNU General Public License v3.0
