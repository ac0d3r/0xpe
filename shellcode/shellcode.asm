; hello.asm
    .386
    .model flat,stdcall
    option casemap:none

    .code
start:
    ; Find where kernel32.dll is loaded into memory
    ASSUME  fs:NOTHING
    xor ecx, ecx               ; 避免 00 空值 
    mov ebx, fs:[ecx + 30h]    ; ebx = PEB基地址
    ASSUME  fs:ERROR
    mov ebx, [ebx + 0ch]         ; ebx = PEB.Ldr
    mov esi, [ebx+14h]         ; ebx = PEB.Ldr.InMemoryOrderModuleList
    lodsd                       ; eax = Second module
    xchg eax, esi               ; eax = esi, esi = eax
    lodsd                       ; eax = Third(kernel32)
    mov ebx, [eax + 10h]       ; ebx = dll Base address

    ; Find PE export table
    mov edx, [ebx + 3ch]   ; 找到 dos header e_lfanew 偏移量
    add edx, ebx            ; edx =  pe header
    mov edx, [edx + 78h]   ; edx = offset export table
    add edx, ebx            ; edx = export table
    mov esi, [edx + 20h]   ; esi = offset names table
    add esi, ebx            ; esi = names table

    ; 查找 WinExec 函数名
    ; EniW  456E6957
    xor ecx, ecx
    Get_Function:
        inc ecx                         ; ecx++
        lodsd                           ; eax = 下一个函数名字符串rva
        add eax, ebx                    ; eax = 函数名字符串指针
        cmp dword ptr[eax], 456E6957h  ; eax[0:4] == EniW
        jnz Get_Function
    dec ecx;

    ; 查找 Winexec 函数指针
    mov esi, [edx + 24h]     ; esi = ordianl table rva
    add esi, ebx              ; esi = ordianl table
    mov cx, [esi + ecx * 2]   ; ecx = func ordianl
    mov esi, [edx + 1ch]     ; esi = address table rva
    add esi, ebx              ; esi = address table
    mov edx, [esi + ecx * 4]  ; edx = func address rva
    add edx, ebx              ; edx = func address

    ; 调用 Winexec 函数
    xor eax, eax
    push edx
    push eax        ; 0x00
    push 6578652eh
    push 636c6163h
    push 5c32336dh
    push 65747379h
    push 535c7377h
    push 6f646e69h
    push 575c3a43h
    mov esi, esp    ; esi = "C:\Windows\System32\calc.exe"
    push 10         ; window state SW_SHOWDEFAULT
    push esi        ; "C:\Windows\System32\calc.exe"
    call edx        ; WinExec(esi, 10)

    ; exit
    add esp, 1ch
    pop eax
    pop edx
end start