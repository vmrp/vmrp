这里是有关c语言开发mrp的实现原理的研究

main.go 是一个go语言编写的mrp打包工具，主要用来将elf格式转换成ext格式，以及打包资源文件

操作步骤：
1. 运行build.bat
2. 编辑pack.json
```
{
    "display": "测试",   // 显示名
    "filename": "test.mrp", // 生成的mrp文件名
    "appid": 1,
    "version": 1,
    "vendor": "vendor", 
    "description": "desc",
    "files": [       // 会按这里面的顺序打包到mrp中
        "./lib/start.mr",
        "./tmp/cfunction.elf" // 如果是elf格式，将自动转成ext打包进去
    ]
}
```
3. 运行打包工具最终生成mrp


