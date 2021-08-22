# Shellcode-Loader

## 基本原理

shellcode 是位置无关代码所以只要给他EIP就能够开始运行。

在低版本Windows中的会利用堆栈溢出执行ShellCode或者直接将函数指针指向shellcode数据段。例如：

```cpp
#include <stdio.h>
unsigned char shellcode[] =
        "\x33\xC9\x64\x8B\x59\x30\x8B\x5B\x0C\x8B\x73\x14\xAD\x96\xAD\x8B"
        "\x58\x10\x8B\x53\x3C\x03\xD3\x8B\x52\x78\x03\xD3\x8B\x72\x20\x03"
        "\xF3\x33\xC9\x41\xAD\x03\xC3\x81\x38\x57\x69\x6E\x45\x75\xF4\x49"
        "\x8B\x72\x24\x03\xF3\x66\x8B\x0C\x4E\x8B\x72\x1C\x03\xF3\x8B\x14"
        "\x8E\x03\xD3\x33\xC0\x52\x50\x68\x2E\x65\x78\x65\x68\x63\x61\x6C"
        "\x63\x68\x6D\x33\x32\x5C\x68\x79\x73\x74\x65\x68\x77\x73\x5C\x53"
        "\x68\x69\x6E\x64\x6F\x68\x43\x3A\x5C\x57\x8B\xF4\x6A\x0A\x56\xFF"
        "\xD2\x83\xC4\x1C\x58\x5A";

int main()
{   
    // void (*)()   指向不带参数的 void 函数的指针
    // 类型转换 (void (*)()) shellcode
    ((void (*)())shellcode)();
    return 0;
}
```

但从 Windows XP 和 Windows Server 2003 开始，内置于操作系统中的系统级内存保护功能 `DEP(Data Execution Prevention)`，DEP 阻止从数据页（例如默认堆、堆栈和内存池）运行代码。

所以常见运行 shellcode 的核心思路为以下几种：

- 用 `VirtualAlloc` 类似的函数分配一个具有可执行权限内存空间
- 用 `VirtualProtect` 函数修改 shellcode 所在内存空间的访问权限（RWE）

除此之外还有`ntdll`的非导出函数`Nt(Zw)ProtectVirtualMemory/Nt(Zw)AllocateVirtualMemory`，是上文两个函数在R3的最底层，多了个process handle参数，R3下的`Nt*`和`Zw*`没区别...

## 整理常见的加载 shellcode 方式

用 C/C++ 编写的 Demo 环境均为 `win10 + vs2019`： 

- [0x00.c](./cpp_demos/0x00.c) 
  
  VirtualAlloc 申请读写执行的内存，memcpy 拷贝code，转换为函数指针执行。

- [0x01.c](./cpp_demos/0x01.c)
  
  和[0x00.c](./cpp_demos/0x00.c)一样，不过是新定义了函数指针： `typedef void(_stdcall *CODE)();`

- [0x02.c](./cpp_demos/0x02.c)

  VirtualAlloc 申请RW内存，拷贝code后用VirtualProtect添加执行权限再利用线程执行。

**内嵌汇编：**

- [0x03.c](./cpp_demos/0x03.c)

  VirtualProtect 添加执行权限后用汇编指令 `jmp shellcode`

- [0x04.c](./cpp_demos/0x04.c)

  设置 .data 区块属性为`RWE`，直接用汇编指令 `jmp shellcode`

- [0x05.c](./cpp_demos/0x05.c)

   和[0x04.c](./cpp_demos/0x04.c)一样，用一些花指令替换了`jmp`指令


---

用 golang 写 ShellcodeLoader 前先学习下 golang 中指针的知识：

golang 中的指针及与指针对指针的操作主要有以下三种：
1. 普通的指针类型，例如 var intptr *T，定义一个T类型指针变量
2. 内置类型 uintptr，本质是一个无符号的整型，它的长度是跟平台相关的，可以用来保存一个指针地址
3. unsafe包提供的Pointer，表示可以指向任意类型的指针

各举一个例子🌰：

1. **普通指针可以通过引用来修改变量的值：**
```golang
...
func intTest(c *int) {
	*c++
}

func main() {
	count := 1
	fmt.Println(&count) // 0xc0000140c8
	intTest(&count)
	fmt.Println(count)  // 2
}
```
2. **指针操作 uintptr ：**

一个`uintptr`可以被转换成`unsafe.Pointer`,同时`unsafe.Pointer`也可以被转换为`uintptr`。可以使用使用`uintptr+offset`计算出地址，然后使用`unsafe.Pointer`进行转换，格式如下：`p = unsafe.Pointer(uintptr(p) + offset)`

```golang
func main(){
  buf := []byte{1, 2, 3, 4}
  // buf 数据的基地址，以下两种方式是等效的：
  // 1. &buf[0]
  // 2. (*reflect.SliceHeader)(unsafe.Pointer(&buf)).Data
  base := uintptr(unsafe.Pointer(&buf[0]))
  for i := 0; i < len(buf); i++ {
    fmt.Printf("%#v\n", *(*byte)(unsafe.Pointer(base + uintptr(i))))
  }
}
```

3. **unsafe.Pointer：**

`unsafe.Pointer`主要是用来进行桥接，用于不同类型的指针进行互相转换，

```golang
...
type Person struct {
    age int
    name string
}
func main() {
  p := &Person{age: 30, name: "Bob"}
  pname := unsafe.Pointer(uintptr(unsafe.Pointer(p)) + unsafe.Offsetof(p.name))
  fmt.Println(*(*string)(pname))
}
```
--- 

[golang_demos](./golang_demos) 和上面 c/c++ 的套路基本一样：
- [0x00.go](./golang_demos/0x00/0x00.go) 
- [0x01.go](./golang_demos/0x00/0x01.go) 
  
  要注意的 ZwProtectVirtualMemory 函数的参数 `BaseAddress` 是指向基地地址的指针(Pointer to base address to protect)
- [0x02.go](./golang_demos/0x00/0x02.go) 


## 总结

虽然目前只是为了研究下 shellcode loader 原理以及 windows api，但是发现上面这些运行 shellcode 的方式 bypassAV 能力都很弱。关键点为了编写位置无关代码就一定要先获取到 `ntdll.dll` 或者 `kernel32.dll` 的基地址，就会存在明显的特征指令。要么就是在动态运行时要通过关键函数 `VirtualAlloc`、 `VirtualProtect`等，搞到一块有执行权限的内存，这些关键函数都被 hook 时也很容易被检测出来，我觉得 bypass AV 第一步就是要解决上面两个问题...

## 贴心小公举

整理一些常量函数签名以便查阅：

```cpp
#define MEM_COMMIT              0x00001000
#define MEM_RESERVE             0x00002000
#define MEM_RESET               0x00080000
#define MEM_RESET_UNDO          0x1000000

#define PAGE_NOACCESS           0x01
#define PAGE_READONLY           0x02
#define PAGE_READWRITE          0x04
#define PAGE_WRITECOPY          0x08
#define PAGE_EXECUTE            0x10
#define PAGE_EXECUTE_READ       0x20
#define PAGE_EXECUTE_READWRITE  0x40
#define PAGE_EXECUTE_WRITECOPY  0x80

// https://docs.microsoft.com/zh-cn/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
LPVOID VirtualAlloc(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);

// https://docs.microsoft.com/zh-cn/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
BOOL VirtualProtect(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flNewProtect,
  PDWORD lpflOldProtect
);

// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtProtectVirtualMemory.html

NtAllocateVirtualMemory(
  IN HANDLE               ProcessHandle,
  IN OUT PVOID            *BaseAddress,
  IN ULONG                ZeroBits,
  IN OUT PULONG           RegionSize,
  IN ULONG                AllocationType,
  IN ULONG                Protect 
);

// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtProtectVirtualMemory.html
NtProtectVirtualMemory(
  IN HANDLE               ProcessHandle,
  IN OUT PVOID            *BaseAddress,
  IN OUT PULONG           NumberOfBytesToProtect,
  IN ULONG                NewAccessProtection,
  OUT PULONG              OldAccessProtection 
);
```

# res
- https://docs.microsoft.com/en-us/windows/win32/memory/
- https://www.ascotbe.com/2020/03/07/Basics/
- [Windows下32位进程内存模型](http://www.xumenger.com/01-windows-process-memory-20170101/)
- [Golang-unsafe.Pointer和uintptr](https://studygolang.com/articles/33151)
- https://iv4n.cc/go-shellcode-loader/

这些还没来得及看：
- https://github.com/Ne0nd0g/go-shellcode
- https://github.com/Binject/shellcode
- https://paper.seebug.org/1413/
- https://zhuanlan.zhihu.com/p/26012567