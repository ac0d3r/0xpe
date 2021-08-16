## 寄存器

32位寄存器，如eax、ebx、ecx、esi、edi、esp、ebp等。

- ebp（栈基地址指针）
- esp（栈顶指针）
- eip 寄存器存放下一个CPU指令存放的内存地址，当CPU执行完当前的指令后，从EIP寄存器中读取下一条指令的内存地址，然后继续执行。
- eax 是"累加器"(accumulator), 它是很多加法乘法指令的缺省寄存器。
- ebx 是"基地址"(base)寄存器, 在内存寻址时存放基地址。
- ecx 是计数器(counter), 是重复(REP)前缀指令和LOOP指令的内定计数器。
- edx 则总是被用来放整数除法产生的余数。
- esi: 字符串操作时，用于存放数据源的地址

## 指令

- mov destination, source   ;赋值
- add destination, source
- sub destination, source 
- inc destination           ;(+1)
- dec destination           ;(-1)
- jmp destination           ;跳转指令 address/label
- cmp destination, source   ; dest - src(不影响des) 并比较 dect,src；如果相等将设置一个`Zero Flag`此标识将会被下一条跳转指令使用
- jz destination            ;上条指令存在Zero Flag将跳转 address/label
- jnz destination           ;与 jz 相反
- xor destination, source   ;按位异或
- lea destination, source   ;(加载有效地址)将src指定的内存地址放入dest
- lodsd                     ;在 EAX 寄存器中放入 ESI 寄存器指定地址处的值
    等同于：mov eax, [esi], add esi, 4
- xchg destination, source  ;交换操作数的值

### 栈相关

- push 
- pushw
- pop

### 函数

- call

## res
- https://zhuanlan.zhihu.com/p/53394807