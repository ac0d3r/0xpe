/*
thx:
	https://x.hacking8.com/post-419.html
*/
package main

import (
	"0xpe/pe"
	"encoding/binary"
	"encoding/hex"
	"log"
	"os"
)

func main() {
	length := 0
	dosHeader := pe.DOSHeadr{
		EMagic: pe.MZMagic,
	}
	dosHeader.Elfanew = uint32(binary.Size(dosHeader))
	length += binary.Size(dosHeader)

	pent := pe.ImageNtHeaders32{
		Signature: pe.PEMagic,
		FileHeader: pe.ImageFileHeader{
			Machine:          pe.ImageFileMachineI386,
			NumberOfSections: 1,
			Characteristics:  pe.ImageFileRelocsStripped | pe.ImageFileExecutableImage | pe.ImageFileLineNumsStripped | pe.ImageFile32bitMachine,
		},
		OptionalHeader: pe.ImageOptionalHeader32{
			Magic:                 pe.ImageOptionalMagic32,
			AddressOfEntryPoint:   0x1000,
			ImageBase:             0x400000,
			SectionAlignment:      0x1000,
			FileAlignment:         0x200,
			MajorSubsystemVersion: 0x4,
			Subsystem:             0x2,
			NumberOfRvaAndSizes:   0x10,
		},
	}
	pent.FileHeader.SizeOfOptionalHeader = uint16(binary.Size(pent.OptionalHeader))
	length += binary.Size(pent)

	text := pe.SectionHeader32{
		Name:            pe.ToC8bytes(".text"),
		Characteristics: pe.ImageScnCntCode | pe.ImageScnMemRead | pe.ImageScnMemExecute,
		VirtualAddress:  0x1000,
	}
	length += binary.Size(text)

	pent.OptionalHeader.SizeOfHeaders = uint32(pe.Align(uint(length), uint(pent.OptionalHeader.FileAlignment)))
	// 对齐，填充0x00
	textPadding := pe.FillZeroByte(int(pent.OptionalHeader.SizeOfHeaders) - length)
	length = int(pent.OptionalHeader.SizeOfHeaders)

	shellcode, err := hex.DecodeString(`fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d6a018d85b20000005068318b6f87ffd5bbf0b5a25668a695bd9dffd53c067c0a80fbe07505bb4713726f6a0053ffd563616c6300`)
	if err != nil {
		log.Fatalln(err)
	}

	text.VirtualSize = uint32(len(shellcode))
	text.SizeOfRawData = uint32(pe.Align(uint(text.VirtualSize), uint(pent.OptionalHeader.SectionAlignment)))
	text.PointerToRawData = uint32(length)

	// 对齐，填充0x00
	fillBytes := pe.FillZeroByte(int(text.SizeOfRawData - uint32(len(shellcode))))
	shellcode = append(shellcode, fillBytes...)
	length += len(shellcode)

	pent.OptionalHeader.SizeOfImage = pent.OptionalHeader.SizeOfHeaders +
		uint32(pe.Align(uint(text.SizeOfRawData),
			uint(pent.OptionalHeader.SectionAlignment))) // Image大小,内存中整个PE文件的映射的尺寸，可比实际的值大，必须是SectionAlignment的整数倍

	// 写入文件
	f, err := os.Create("go-pe.exe")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	binary.Write(f, binary.LittleEndian, dosHeader)
	binary.Write(f, binary.LittleEndian, pent)
	binary.Write(f, binary.LittleEndian, text)
	binary.Write(f, binary.LittleEndian, textPadding)
	binary.Write(f, binary.LittleEndian, shellcode)
}
