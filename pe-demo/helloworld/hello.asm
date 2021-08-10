; https://docs.microsoft.com/zh-cn/cpp/assembler/masm/directives-reference?view=msvc-160
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
