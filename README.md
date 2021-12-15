# 0xpe

相关结构和常量定义在 `pe` package

## 手搓PE文件
- shellcode: [code](./pe-demo/shellcode)

创建一个 exe 将 shellcode 直接填充到 .text 区块。

- helloworld: [code](./pe-demo/helloworld)

导入 `user32.dll`，`kernel32.dll` 库及函数寻址，实现一个功能和 `hello.asm` 一样的 exe。

## 编写 windows shellcode

- 用ASM编写一个简单的Windows Shellcode思路总结 [🔗xz.aliyun.com/t/10078](https://xz.aliyun.com/t/10078) | [notes.md](./shellcode/shellcode-notes.md)

## shellcodeLoader 小记

- 基本原理和常见加载的方式（还有一些姿势没来得及学）[notes.md](./shellcodeLoader/shellcode-loader-notes.md)
