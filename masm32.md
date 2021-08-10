# win32 汇编基础


**MASM32 环境搭建：**

MASM32是一个免费的软件包，该软件包中包含了汇编编译器 ml.exe、资源编译器 rc.exe、32位的链接器 link.exe 和一个简单的集成开发环境 QEditor.exe。

- 下载并解压 https://www.masm32.com
- 运行安装程序：install.exe （一路 next）
- 设置系统环境变量 (改为自己设置的工作区目录)
    - include=F:\masm32\include
    - lib=F:\masm32\lib
    - path=F:\masm32\bin

**windows 追加环境变量：**
`path=D:\GO\bin;%PATH%`


## hello-world demo

```masm
; hello.asm
    .386
    .model flat,stdcall
    option casemap:none

include windows.inc
include user32.inc
includelib user32.lib
include kernel32.inc
includelib kernel32.lib

; 数据段
    .data
szText db 'HelloWorld', 0
szTitle db 'title', 0
; 代码段
    .code
start:
    invoke MessageBox,NULL,offset szText,offset szTitle,MB_OK
    invoke ExitProcess,NULL
end start
```
编译：
```
F:\> ml -c -coff .\hello.asm
F:\> link -subsystem:windows .\hello.obj
```

# 小记

## Win32 API

### A-W

Win32 API中有名字的函数一般都有两个版本，其后缀分别以“A”和“W”结束，如创建文件的函数CreateFileA和CreateFileW（当然也有例外，如前面的ExitProcess函数）。

A和W表示这个函数使用的字符集，A代表ANSI字符集，W表示宽字符，即Unicode字符集，在Windows中的Unicode字符一般是使用UCS2的UTF16-LE编码。

## 寄存器

32位寄存器，如eax、ebx、ecx、esi、edi、esp、ebp等。

- ebp（栈基地址指针）
- esp（栈顶指针）
- eip（指向下一条要执行的指令的位置）

