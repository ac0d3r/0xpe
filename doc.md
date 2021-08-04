## PE 结构

![](https://user-images.githubusercontent.com/26270009/127626619-ac815081-5353-4b7a-a356-cce93ffe74c7.png)


### DOS头
Dos 头主要是为了兼容DOS系统所遗留下来的产物。包含了`DOS MZ头`和`DOS Stub`两个部分。

其中DOS MZ头它的定义数据结构名称为`IMAGE_DOS_HEADER`：

```c++
typedef struct _IMAGE_DOS_HEADER
{
    WORD   e_magic;                     // Magic number     MZ 标识 0x5A4D
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file  文件中页数
    WORD   e_crlc;                      // Relocations  重新定位表中的指针数
    WORD   e_cparhdr;                   // Size of header in paragraphs  头部尺寸，以段落为单位
    WORD   e_minalloc;                  // Minimum extra paragraphs needed  所需最小附加段
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed  所需最大附加段
    WORD   e_ss;                        // Initial (relative) SS value  初始化的SS值（相对偏移量）
    WORD   e_sp;                        // Initial SP value  初始的SP值
    WORD   e_csum;                      // Checksum  补码校验值
    WORD   e_ip;                        // Initial IP value  初始的IP值
    WORD   e_cs;                        // Initial (relative) CS value 初始的CS值（相对偏移量）
    WORD   e_lfarlc;                    // File address of relocation table  重定位表的字节偏移里
    WORD   e_ovno;                      // Overlay number  覆盖号
    WORD   e_res[4];                    // Reserved words  保留字
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)  OEM标识符（相对 e_oeminfo）
    WORD   e_oeminfo;                   // OEM information; e_oemid specific  OEM信息
    WORD   e_res2[10];                  // Reserved words  保留字
    LONG   e_lfanew;                    // File address of new exe header  PE头相对文件的真正偏移量
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```

### PE头

第二部分PE头的数据结构定义为`IMAGE_NT_HEADERS`：

```c++
typedef struct _IMAGE_NT_HEADERS {
  DWORD                   Signature;    // PE文件标识 0x00004550 // PE00
  IMAGE_FILE_HEADER       FileHeader;   // PE 标准头
  IMAGE_OPTIONAL_HEADER32 OptionalHeader;   // PE 扩展头
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
```

PE 标准头 `IMAGE_FILE_HEADER`结构 : 

整个 IMAGE_FILE_HEADER 数据结构（标准通用对象文件格式COFF）占位20字节。该结构当中记录了PE文件的全局属性详：

```c++
typedef struct _IMAGE_FILE_HEADER {
  WORD  Machine;    // 运行平台
  WORD  NumberOfSections;   // PE中节的数量
  DWORD TimeDateStamp;      // 文件创建日期和时间
  DWORD PointerToSymbolTable;   // 指向符号表（用于调试）
  DWORD NumberOfSymbols;        // 符号表中的符号数量（用于调试）
  WORD  SizeOfOptionalHeader;   // 扩展头结构的长度
  WORD  Characteristics;        // 文件属性标志
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
```

**运行平台 Machine 表：**
![image](https://user-images.githubusercontent.com/26270009/127740934-51b54c4b-4270-49bc-abd4-42eb462c05b2.png)


**文件属性标志 Characteristics 表：**（注意是数据位）
![](https://user-images.githubusercontent.com/26270009/127734599-c661aaea-e306-4b7d-9d88-8cbe095be69c.png)


PE 扩展头 `IMAGE_OPTIONAL_HEADERS` 结构：

```c++
// 32
typedef struct _IMAGE_OPTIONAL_HEADER {
    //
    // Standard fields.
    //
    WORD    Magic;  // 魔术字
    BYTE    MajorLinkerVersion; // 链接器版本号
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode; // 所以含代码节的总大小
    DWORD   SizeOfInitializedData;  // 所有含已初始化数据的节的总大小
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint; // 程序执行入口RVA
    DWORD   BaseOfCode; // 代码节 起始RVA
    DWORD   BaseOfData;// 数据节 起始RVA
    //
    // NT additional fields.
    //
    DWORD   ImageBase;  // 程序的建议装载地址
    DWORD   SectionAlignment;   // 内存中节的对其粒度
    DWORD   FileAlignment;   // 文件中节的对其粒度
    WORD    MajorOperatingSystemVersion; // 操作系统版本号
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;  // 该PE的版本号
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;  // 所需子系统的版本号
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;  // 未用
    DWORD   SizeOfImage;    // 内存中整个 PE 映像尺寸
    DWORD   SizeOfHeaders;  // 所有头 + 节表的大小
    DWORD   CheckSum;   // 校验和
    WORD    Subsystem;  //文件子系统
    WORD    DllCharacteristics; // DLL 文件特性
    DWORD   SizeOfStackReserve; // 初始化时的栈大小
    DWORD   SizeOfStackCommit;  // 初始化时实际提交的栈大小
    DWORD   SizeOfHeapReserve;  // 初始化时的堆大小
    DWORD   SizeOfHeapCommit;  // 初始化时实际提交的堆大小
    DWORD   LoaderFlags;    // 调试相关
    DWORD   NumberOfRvaAndSizes;  // DataDirectory 数据目录数量
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];  // 数据目录
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
```

数据目录 `IMAGE_DATA_DIRECTORY` 结构：
数据目录项其中记录了不同类型的数据的目录信息。比如：导出表，导入表，资源，重定位表等

```c++
typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress; // 数据的起始 RVA
  DWORD Size;           // 数据块的长度
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```

**数据目录表：**
![image](https://user-images.githubusercontent.com/26270009/127740431-45c62fbc-e287-4d51-a4e0-42ebe878bb03.png)

### 节表

PE头下面紧接着就是节表，节表当中记录着特定的节有关的信息。（节的属性，节的大小，在文件和内存中的起始位置）。

节表中节的数量：`IMAGE_FILE_HEADER.NumberOfSections`

```c++
typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME]; // 8个字节 节名
    union {
            DWORD   PhysicalAddress;
            DWORD   VirtualSize;    //实际的、被使用的区块大小，是区块在没被对齐处理之前的大小
    } Misc;
    DWORD   VirtualAddress; //（Voffset）：装载到内存中的RVA，按照内存对齐，默认为1000h
    DWORD   SizeOfRawData; // （Rsize）在磁盘中的大小，经过了对齐，FileAlignment默认大小为200h
    DWORD   PointerToRawData; // （Roffset）盘文件中的偏移。如果程序自装载，这个字段比VitrualAddress更重要
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics; // 节的属性
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```

**Characteristics 字段属性：**
![image](https://user-images.githubusercontent.com/26270009/127741135-3b1442d2-d9f2-4bdb-863d-bee3f4a33cd1.png)


**各种区块的描述：**

![image](https://user-images.githubusercontent.com/26270009/127740395-e8e6c03d-99fd-4cdb-9653-39377ee70468.png)

#### 区块的对齐值
- 内存对齐：默认对齐值：1000h（4KB）
- 磁盘文件对齐：典型对齐值：200h

## PE导入表

### 导入表的作用
导入表当中的数据就是指定了PE文件调用外来函数（这里外来函数是指不在本程序当中定义的函数）的数目，这些外来函数在哪些动态链接库当中等等。Windows 加载器在运行PE时会通过导入库将动态链接库一并加载到进程的地址空间当中。

### `IMAGE_IMPORT_DESCRIPTOR`

导入表是数据目录中注册的数据类型，描述信息位于数据目录的第2个目录项。

导入表的当中每20个字节为一组数据结构，该数据结构名称为 `IMAGE_IMPORT_DESCRIPTOR`（导入表描述符）详细内容如下：

```c++
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
  union {
    DWORD Characteristics;
    DWORD OriginalFirstThunk;   // 指向输入名称表的表（INT）的 RVA
  };
  DWORD TimeDateStamp;  // 时间戳
  DWORD ForwarderChain; // 链表的前一个结构
  DWORD Name;   // 指向导入映像文件的名称
  DWORD FirstThunk;    // 指向输入地址表的表（IAT）的 RVA
} IMAGE_IMPORT_DESCRIPTOR;
```

元素`Name`保存着导入动态链接库的名称，其中我们需要关注的是`OriginalFirstThunk`和`FirstThunk`，它们指向了另外一个数据结构，其中元素 `OriginalFirstThunk` 指向的数组称之为`INT`。元素`FirstThunk` 指向的数据结构称之为`IAT`。

**导入表，INT，IAT之间的关系图：**
![image](https://user-images.githubusercontent.com/26270009/127755440-b6e1edbc-770e-4c1d-84f9-93c85933d932.png)

数组 INT、IAT 当中的每一项均是 IMAGE_THUNK_DATA 结构。定义如下：
```c++
typedef struct _IMAGE_THUNK_DATA32 {
    union {
        DWORD ForwarderString;      // PBYTE 
        DWORD Function;             // PDWORD
        DWORD Ordinal;
        DWORD AddressOfData;        // PIMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA32;
```

可以看出，INT和IAT其实都是链表结构，ForwarderString 指针指向下一个表项，其结构也是IMAGE_THUNK_DATA

AddressOfData：指向函数名，这里包含在数据结构 IMAGE_IMPORT_BY_NAME 中，IMAGE_IMPORT_BY_NAME的定义：

```c++
typedef struct _IMAGE_IMPORT_BY_NAME {
  WORD    Hint; // 函数编号
  BYTE    Name[1]; // 表示函数名的字符串
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
```

#### 输入地址表（IAT）

- **IAT和INT结构相同是否是重复？**

INT表（又称为提示名表Hint-name Table）不可以改写，IAT由PE装载器重写

- **执行流程？**

  PE装载器首先搜索 OriginalFirstThunk

  如果找到，加载器迭代搜索数组中的每一个指针（*PIMAGE_IMPORT_BY_NAME），依据其中的函数名Name找到其指向的输入函数的地址

  找到地址之后，会将IAT表中IMAGE_IMPORT_BY_NAME中的Name字段替换为真实的函数地址，这个时候，IT结构中除了IAT表之外的结构就已经不需要了

  PE加载器加载完成的图如下所示：

![image](https://user-images.githubusercontent.com/26270009/127756041-eecf4913-5fab-475b-a777-bf5eceb1f978.png)

## PE导出表

导出表描述了导出表所在PE文件向其他程序提供的可供调用的函数的情况。说明这个问题首先我们先了解一下代码重用机制。该机制提供了重用代码的动态链接库。而导出表就向调用者说明库当中有哪些函数可以被调用。

```c++
typedef struct _IMAGE_EXPORT_DIRECTORY
{
  DWORD Characteristics; // 未使用，总是定义为0
  DWORD TimeDateStamp; // 文件生成时间
  WORD MajorVersion; // 未使用，总是定义为0
  WORD MinorVersion; // 未使用，总是定义为0
  DWORD Name; // 模块的真实名称
  DWORD Base; // 基数，加上序数就是函数地址数组的索引值
  DWORD NumberOfFunctions; // 导出函数的总数
  DWORD NumberOfNames; // 以名称方式导出的函数的总数
  DWORD AddressOfFunctions; // 指向输出函数地址的RVA
  DWORD AddressOfNames; // 指向输出函数名字的RVA
  DWORD AddressOfNameOrdinals; // 指向输出函数序号的RVA
} IMAGE_EXPORT_DIRECTORY;
```

在导入表当中的 IMAGE_IMPORT_DESCRIPTOR 个数与调用的动态链接库个数相等，然而导出表的 IMAGE_EXPORT_DIRECTORY 只有一个。


## thx:
- https://docs.microsoft.com/en-us/windows/win32/api/winnt/
- https://www.nirsoft.net/kernel_struct/vista/index.html

- https://bbs.pediy.com/thread-265024.htm
- https://0xor-writeup.readthedocs.io/zh/latest/reversing/encrypt&decrypt/%E5%8A%A0%E5%AF%86%E4%B8%8E%E8%A7%A3%E5%AF%86%20%E7%AC%AC%E5%8D%81%E7%AB%A0-PE%E6%96%87%E4%BB%B6%E6%A0%BC%E5%BC%8F/
- http://www.nvnv.xyz/newsinfo/804196.html （PE结构 RVA和FOA的转换）