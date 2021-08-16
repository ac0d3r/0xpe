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
