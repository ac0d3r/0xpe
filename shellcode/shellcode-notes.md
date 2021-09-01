## shellcode 是什么？
[shellcode-wiki](https://en.wikipedia.org/wiki/Shellcode)

> “代码也好数据也好只要是与位置无关的二进制就都是shellcode。”

为了写出位置无关的代码，需要注意以下几点：
- 不能对字符串使用直接偏移，必须将字符串存储在堆栈中
- dll中的函数寻址，由于 ASLR 不会每次都在同一个地址中加载，可以通过 PEB.PEB_LDR_DATA 找到加载模块调用其导出的函数，或加载新 dll。
- 避免空字节

     `NULL` 字节的值为 `0x00`，在 C/C++ 代码中，NULL 字节被视为字符串的终止符。因此，shellcode 中这些字节的存在可能会干扰目标应用程序的功能，并且我们的 shellcode 可能无法正确复制到内存中。

     ```asm
     mov ebx, 0x00
     xor ebx, ebx
     ```
     用下面的语句代替上面的语句，结果是一样的。

     此外，在某些特定情况下，shellcode 必须避免使用字符，例如 `\r` 或 `\n`，甚至只使用字母数字字符。


## windows下dll加载的机制

在 Windows 中，应用程序不能直接访问系统调用，使用来自 Windows API ( WinAPI ) 的函数，Windows API函数都存储在 kernel32.dll、advapi32.dll、gdi32.dll 等中。ntdll.dll 和 kernel32.dll 非常重要，以至于每个进程都会导入它们：

这是我编写 [nothing_to_do](https://github.com/Buzz2d0/0xpe/blob/master/shellcode/nothing_to_do.cpp) 程序，用 [listdlls](https://docs.microsoft.com/en-us/sysinternals/downloads/listdlls)列出导入的 dll：


![image](https://user-images.githubusercontent.com/26270009/128963802-891275c3-c4ef-4ec6-ad86-1c6caf070772.png)


### dll寻址

[TEB（线程环境块）](https://en.wikipedia.org/wiki/Win32_Thread_Information_Block)该结构包含用户模式中的线程信息，32位系统中我们可以使用 `FS` 寄存器在偏移`0x30`处找到[进程环境块(PEB)](https://en.wikipedia.org/wiki/Process_Environment_Block) 的地址。

![image](https://user-images.githubusercontent.com/26270009/129133383-a0eb435d-9137-469d-bf59-66016c68b799.png)

`PEB.ldr` 指向`PEB_LDR_DATA`提供有关加载模块的信息的结构的指针，包含`kernel32` 和 `ntdll` 的基地址

```c++
typedef struct _PEB_LDR_DATA {
  BYTE       Reserved1[8];
  PVOID      Reserved2[3];
  LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
```

`PEB_LDR_DATA.InMemoryOrderModuleList` 包含进程加载模块的双向链表的头部。列表中的每一项都是指向 `LDR_DATA_TABLE_ENTRY` 结构的指针

```c++
typedef struct _LIST_ENTRY
{
     PLIST_ENTRY Flink;
     PLIST_ENTRY Blink;
} LIST_ENTRY, *PLIST_ENTRY;
```

LDR_DATA_TABLE_ENTRY 加载的 DLL 信息：

```c++
typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID EntryPoint;
    PVOID Reserved3;
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
```

**tips**

在 Vista 之前的 Windows 版本中，`InInitializationOrderModuleList` 中的前两个DLL是 `ntdll.dll`和`kernel32.dll`，但对于 Vista 及以后的版本，第二个DLL更改为`kernelbase.dll`。

`InMemoryOrderModuleList` 中的第一个 `自身.exe`，第二个是`ntdll.dll`，第三个是`kernel32.dll`，目前这适用于所有 Windows 版本是首选方法。

**kernel32.dll寻址流程：**

![image](https://user-images.githubusercontent.com/26270009/129302443-14a22825-2554-4aec-b8e1-6aa52c9cd535.png)

转化为汇编代码：
```asm
xor ecx, ecx
mov ebx, fs:[ecx + 0x30]    ; 避免 00 空值 ebx = PEB基地址
mov ebx, [ebx+0x0c]         ; ebx = PEB.Ldr
mov esi, [ebx+0x14]         ; ebx = PEB.Ldr.InMemoryOrderModuleList
lodsd                       ; eax = Second module
xchg eax, esi               ; eax = esi, esi = eax
lodsd                       ; eax = Third(kernel32)
mov ebx, [eax + 0x10]       ; ebx = dll Base address
```

### dll导出表中函数寻址
之前学习pe结构相关资料在[这](https://github.com/Buzz2d0/0xpe/blob/master/pe-demo)。

ImageOptionalHeader32.DataDirectory[0].VirtualAddress 指向导出表RVA，导出表的结构如下：
```c++
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;    //未使用
    DWORD   TimeDateStamp;      //时间戳
    WORD    MajorVersion;       //未使用
    WORD    MinorVersion;       //未使用
    DWORD   Name;               //指向改导出表文件名字符串
    DWORD   Base;               //导出表的起始序号
    DWORD   NumberOfFunctions;  //导出函数的个数(更准确来说是AddressOfFunctions的元素数，而不是函数个数)
    DWORD   NumberOfNames;      //以函数名字导出的函数个数
    DWORD   AddressOfFunctions;     //导出函数地址表RVA:存储所有导出函数地址(表元素宽度为4，总大小NumberOfFunctions * 4)
    DWORD   AddressOfNames;         //导出函数名称表RVA:存储函数名字符串所在的地址(表元素宽度为4，总大小为NumberOfNames * 4)
    DWORD   AddressOfNameOrdinals;  //导出函数序号表RVA:存储函数序号(表元素宽度为2，总大小为NumberOfNames * 2)
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

**函数寻址流程：**：

![image](https://user-images.githubusercontent.com/26270009/128981444-7acf1ed2-50dc-4e12-bf2b-3d571be41a41.png)


导出表寻址汇编：

```asm
mov edx, [ebx + 0x3c]   ; 找到 dos header e_lfanew 偏移量
add edx, ebx            ; edx =  pe header
mov edx, [edx + 0x78]   ; edx = offset export table
add edx, ebx            ; edx = export table
mov esi, [edx + 0x20]   ; esi = offset names table
add esi, ebx            ; esi = names table
```

查找 Winexec 函数名：

```asm
xor ecx, ecx
Get_Function:
    inc ecx                         ; ecx++
    lodsd                           ; eax = 下一个函数名字符串rva
    add eax, ebx                    ; eax = 函数名字符串指针
    cmp dword ptr[eax], 0x456E6957  ; eax[0:4] == EniW
    jnz Get_Function
dec ecx;
```

查找 Winexec 函数指针：

```asm
mov esi, [edx + 0x24]     ; esi = ordianl table rva
add esi, ebx              ; esi = ordianl table
mov cx, [esi + ecx * 2]   ; ecx = func ordianl
mov esi, [edx + 0x1c]     ; esi = address table rva
add esi, ebx              ; esi = address table
mov edx, [esi + ecx * 4]  ; edx = func address rva
add edx, ebx              ; edx = func address
```

调用 Winexec 函数：
```asm
xor eax, eax
push edx
push eax        ; 0x00
push 0x6578652e
push 0x636c6163
push 0x5c32336d
push 0x65747379
push 0x535c7377
push 0x6f646e69
push 0x575c3a43
mov esi, esp    ; esi = "C:\Windows\System32\calc.exe"
push 10         ; window state SW_SHOWDEFAULT
push esi        ; "C:\Windows\System32\calc.exe"
call edx        ; WinExec(esi, 10)
```

最终的[shellcode](https://github.com/Buzz2d0/0xpe/blob/master/shellcode/shellcode.cpp):

```cpp
int main()
{
    __asm {
        ; Find where kernel32.dll is loaded into memory
        xor ecx, ecx
        mov ebx, fs:[ecx + 0x30]    ; 避免 00 空值 ebx = PEB基地址
        mov ebx, [ebx+0x0c]         ; ebx = PEB.Ldr
        mov esi, [ebx+0x14]         ; ebx = PEB.Ldr.InMemoryOrderModuleList
        lodsd                       ; eax = Second module
        xchg eax, esi               ; eax = esi, esi = eax
        lodsd                       ; eax = Third(kernel32)
        mov ebx, [eax + 0x10]       ; ebx = dll Base address
        
        ; Find PE export table
        mov edx, [ebx + 0x3c]   ; 找到 dos header e_lfanew 偏移量
        add edx, ebx            ; edx =  pe header
        mov edx, [edx + 0x78]   ; edx = offset export table
        add edx, ebx            ; edx = export table
        mov esi, [edx + 0x20]   ; esi = offset names table
        add esi, ebx            ; esi = names table
        
        ; 查找 WinExec 函数名
        ; EniW  456E6957
        xor ecx, ecx
        Get_Function:
            inc ecx                         ; ecx++
            lodsd                           ; eax = 下一个函数名字符串rva
            add eax, ebx                    ; eax = 函数名字符串指针
            cmp dword ptr[eax], 0x456E6957  ; eax[0:4] == EniW
            jnz Get_Function
        dec ecx;
        
        ; 查找 Winexec 函数指针
        mov esi, [edx + 0x24]     ; esi = ordianl table rva
        add esi, ebx              ; esi = ordianl table
        mov cx, [esi + ecx * 2]   ; ecx = func ordianl
        mov esi, [edx + 0x1c]     ; esi = address table rva
        add esi, ebx              ; esi = address table
        mov edx, [esi + ecx * 4]  ; edx = func address rva
        add edx, ebx              ; edx = func address
        
        ; 调用 Winexec 函数
        xor eax, eax
        push edx
        push eax        ; 0x00
        push 0x6578652e
        push 0x636c6163
        push 0x5c32336d
        push 0x65747379
        push 0x535c7377
        push 0x6f646e69
        push 0x575c3a43
        mov esi, esp    ; esi = "C:\Windows\System32\calc.exe"
        push 10         ; window state SW_SHOWDEFAULT
        push esi        ; "C:\Windows\System32\calc.exe"
        call edx        ; WinExec(esi, 10)

        ; exit
		add esp, 0x1c
        pop eax
        pop edx
    }
    return 0;
} 
```

## dump shellcode

vs 生成 shellcode 体积膨胀了好多，用 masm 重新写一下，小了很多：[shellcode.asm](./shellcode.asm)

编译：
```
F:\> ml -c -coff .\shellcode.asm
F:\> link -subsystem:windows .\shellcode.obj
```

---
两种方法：

1. dumpbin.exe

`$ dumpbin.exe /ALL .\shellcode.obj`

![image](https://user-images.githubusercontent.com/26270009/129534584-09f97d3f-f576-4a10-8f7d-14d2f0fd801d.png)

2. 从 PE  .text 区块中读取

从 `PointerToRawData` 开始，取 `VirtualSize` 大小的数据

![image](https://user-images.githubusercontent.com/26270009/129534764-43b61379-10e9-414d-8877-28d32f31904b.png)


## 用 golang 写个 loader
> thx [@w8ay](https://github.com/boy-hack)

[loader.go](https://github.com/Buzz2d0/0xpe/blob/master/shellcode/loader.go)，直接用[Makefile](https://github.com/Buzz2d0/0xpe/blob/master/shellcode/Makefile)编译：`$ make`

**成功！！！**

![image](https://user-images.githubusercontent.com/26270009/129661556-c8c72b49-de5b-47e8-87df-18d5302f018f.png)


## res
- https://idafchev.github.io/exploit/2017/09/26/writing_windows_shellcode.html

- https://securitycafe.ro/2015/10/30/introduction-to-windows-shellcode-development-part1/
- https://securitycafe.ro/2015/12/14/introduction-to-windows-shellcode-development-part-2/
- https://securitycafe.ro/2016/02/15/introduction-to-windows-shellcode-development-part-3/
