<a href="https://996.icu"><img src="https://img.shields.io/badge/link-996.icu-red.svg" alt="996.icu" /></a> 反对996是每个软件工程师的义务

# vmrp

由于mrpoid模拟器受限于安卓系统，于是决定开发一款真正的模拟器

目前在linux和windows下用vscode开发

第一阶段目标只打算在命令行中模拟出helloworld，并且能够响应事件

第二阶段目标完成图形化界面，可以借助原来的mrp开发环境打造windows模拟器，如果可行的话难度会大大降低，如果不可行，则要另外想办法做，有可能做成动态库提供API的形式供其它容易做图形化的语言调用



需要安装zlib，我是直接从官网下载源码安装的
需要安装unicorn (windows下载预编译文件unicorn-1.0.1，只需要头文件和unicorn.a放到./windows文件夹内，用mingw64(mingw32-make.exe)编译，我的是x86_64-8.1.0-release-posix-sjlj-rt_v6-rev0版本)

十六进制方式查看文件
```shell
hd mythroad/arm.mrp -n 100
```
# 参考资料
https://github.com/Yichou/mrpoid2018
https://github.com/alphaSeclab/awesome-reverse-engineering
https://github.com/nationalsecurityagency/ghidra

反汇编：
arm-linux-gnueabi-objdump -b binary --start-address=0x8 -m arm -D game.ext
r2 -a arm -b 32 -s 8 game.ext

arm汇编学习工具:
https://github.com/linouxis9/ARMStrong

https://github.com/unicorn-engine/unicorn
https://bbs.pediy.com/thread-253868.htm


arm平台函数传递参数，反汇编实例分析:
https://blog.csdn.net/ayu_ag/article/details/50734282

