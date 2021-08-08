package main

import (
	"0xpe/pe"
	"encoding/binary"
	"fmt"
	"log"
	"os"
)

func main() {
	length := 0
	// dos-header:
	dosHeader := pe.DOSHeadr{
		EMagic: pe.MZMagic,
	}
	// not have dos-stub
	dosHeader.Elfanew = uint32(binary.Size(dosHeader))
	length += binary.Size(dosHeader)

	// pe-header:
	pent := pe.ImageNtHeaders32{
		Signature: pe.PEMagic,
		FileHeader: pe.ImageFileHeader{
			Machine:          pe.ImageFileMachineI386,
			NumberOfSections: 3,
			Characteristics:  pe.ImageFileRelocsStripped | pe.ImageFileExecutableImage | pe.ImageFileLineNumsStripped | pe.ImageFile32bitMachine,
		},
		OptionalHeader: pe.ImageOptionalHeader32{
			Magic:                 pe.ImageNtOptionalHdr32Magic,
			AddressOfEntryPoint:   0x1000, // ImageBase + AddressOfEntryPoint
			ImageBase:             0x400000,
			SectionAlignment:      0x1000,
			FileAlignment:         0x200,
			MajorSubsystemVersion: 0x4,
			Subsystem:             pe.ImageSubSystemWindowsGUI,
			NumberOfRvaAndSizes:   0x10,
		},
	}
	pent.FileHeader.SizeOfOptionalHeader = uint16(binary.Size(pent.OptionalHeader))
	length += binary.Size(pent)
	// .text section header:
	text := pe.SectionHeader32{
		Name:            pe.ToC8bytes(".text"),
		VirtualAddress:  0x1000,
		Characteristics: pe.ImageScnCntCode | pe.ImageScnMemExecute | pe.ImageScnMemRead,
	}
	length += binary.Size(text)
	// .rdata section header:
	rdata := pe.SectionHeader32{
		Name:            pe.ToC8bytes(".rdata"),
		VirtualAddress:  0x2000,
		Characteristics: pe.ImageScnCntInitializedData | pe.ImageScnMemRead,
	}
	length += binary.Size(rdata)

	// .data section header:
	data := pe.SectionHeader32{
		Name:            pe.ToC8bytes(".data"),
		VirtualAddress:  0x3000,
		Characteristics: pe.ImageScnCntInitializedData | pe.ImageScnMemWrite | pe.ImageScnMemRead,
	}
	length += binary.Size(data)

	// DOS头+PE头+所有区块表的总大小
	pent.OptionalHeader.SizeOfHeaders = uint32(pe.Align(uint(length), uint(pent.OptionalHeader.FileAlignment)))
	// PEheader 对齐
	ntheaderPadding := pe.FillZeroByte(int(pent.OptionalHeader.SizeOfHeaders) - length)
	length = int(pent.OptionalHeader.SizeOfHeaders)

	// .data 先初始化 messageBox 参数
	messageBoxAParams := map[string]string{
		"title": "title",
		"text":  "HelloWorld",
	}
	var titleAddress uint32 = 0x00
	var textAddress uint32 = 0x00
	sectionData := make([]byte, 0)

	textAddress = pent.OptionalHeader.ImageBase + data.VirtualAddress
	msg := pe.StrConv2Bytes(messageBoxAParams["text"])
	titleAddress = textAddress + uint32(len(msg))
	sectionData = append(msg, pe.StrConv2Bytes(messageBoxAParams["title"])...)
	data.VirtualSize = uint32(len(sectionData))
	data.SizeOfRawData = uint32(pe.Align(uint(text.VirtualSize), uint(pent.OptionalHeader.FileAlignment)))
	// fmt.Printf("%xh - %xh - %x", textAddress, titleAddress, sectionData)

	// .rdata - include dll
	includes := map[string][]string{
		"user32.dll":   []string{"MessageBoxA"},
		"kernel32.dll": []string{"ExitProcess"},
	}
	var sectionRdata []byte
	var sectionRdata2 []byte
	var sentryAddress uint32 = 0
	offset := 0
	dllImporter := make(map[string]*pe.ImageImportDescriptor)
	for dll := range includes {
		dllImporter[dll] = &pe.ImageImportDescriptor{}
		offset += binary.Size(dllImporter[dll])
	}
	// ntheader - import table
	pent.OptionalHeader.DataDirectory[1] = pe.DataDirectory{
		VirtualAddress: rdata.VirtualAddress,
		Size:           uint32(offset),
	}
	offset += 20 // 导入表末端 20字节为 0x00
	sentryAddress = rdata.VirtualAddress + uint32(offset)
	// dll name
	for dll := range includes {
		dllImporter[dll].Name = uint32(sentryAddress)
		name := pe.StrConv2Bytes(dll)
		sectionRdata2 = append(sectionRdata2, name...)
		sentryAddress += uint32(len(name))
	}

	thunks := make(map[string]map[string]*pe.ImageThunkData32)
	// ImageImportByName 内存布局
	for dll := range includes {
		for i := range includes[dll] {
			fname := includes[dll][i]
			n := pe.ImageImportByName{Name: fname}
			raw := n.GetRaw()
			sectionRdata2 = append(sectionRdata2, raw...)
			if _, ok := thunks[dll]; !ok {
				thunks[dll] = make(map[string]*pe.ImageThunkData32)
			}
			thunks[dll][fname] = &pe.ImageThunkData32{Function: sentryAddress}
			sentryAddress += uint32(len(raw))
		}
	}
	sectionRdata2 = append(sectionRdata2, pe.FillZeroByte(4)...)
	sentryAddress += 4

	//  ThunkData32 OriginalFirstThunk 内存布局
	for dll := range includes {
		dllImporter[dll].OriginalFirstThunk = sentryAddress
		for f := range thunks[dll] {
			raw, err := pe.GetBinaryBytes(binary.LittleEndian, thunks[dll][f])
			if err != nil {
				log.Fatalln(err)
			}
			sectionRdata2 = append(sectionRdata2, raw...)
			sentryAddress += uint32(len(raw))
		}
		sectionRdata2 = append(sectionRdata2, pe.FillZeroByte(4)...)
		sentryAddress += 4
	}
	//  ThunkData32 FirstThunk 内存布局
	var funcAddress = make(map[string]uint32)
	for dll := range includes {
		dllImporter[dll].FirstThunk = sentryAddress
		for f := range thunks[dll] {
			funcAddress[f] = pent.OptionalHeader.ImageBase + sentryAddress
			raw, err := pe.GetBinaryBytes(binary.LittleEndian, thunks[dll][f])
			if err != nil {
				log.Fatalln(err)
			}
			sectionRdata2 = append(sectionRdata2, raw...)
			sentryAddress += uint32(len(raw))
		}
		sectionRdata2 = append(sectionRdata2, pe.FillZeroByte(4)...)
		sentryAddress += 4
	}
	// 组装 section rdata
	for dll := range dllImporter {
		raw, err := pe.GetBinaryBytes(binary.LittleEndian, dllImporter[dll])
		if err != nil {
			log.Fatalln(err)
		}
		sectionRdata = append(sectionRdata, raw...)
	}
	sectionRdata = append(sectionRdata, pe.FillZeroByte(20)...)
	sectionRdata = append(sectionRdata, sectionRdata2...)
	rdata.VirtualSize = uint32(len(sectionRdata))
	rdata.SizeOfRawData = uint32(pe.Align(uint(rdata.VirtualSize), uint(pent.OptionalHeader.FileAlignment)))

	// .text
	/*
		; uType
		push 0x00
		push ->title
		push ->text
		; hWnd 句柄
		push 0x00
		call ->user32.MessageBoxA
		push 0x00
		call ->kernel32.ExitProcess
	*/
	sectionText := []byte{0x6a, 0x00, 0x68}
	sectionText = append(sectionText, pe.MustGetBinaryBytes(binary.LittleEndian, titleAddress)...)
	sectionText = append(sectionText, 0x68)
	sectionText = append(sectionText, pe.MustGetBinaryBytes(binary.LittleEndian, textAddress)...)
	sectionText = append(sectionText, 0x6a, 0x00, 0xff, 0x15)
	sectionText = append(sectionText, pe.MustGetBinaryBytes(binary.LittleEndian, funcAddress["MessageBoxA"])...)
	sectionText = append(sectionText, 0x6a, 0x00, 0xff, 0x15)
	sectionText = append(sectionText, pe.MustGetBinaryBytes(binary.LittleEndian, funcAddress["ExitProcess"])...)
	fmt.Println(sectionText)
	text.VirtualSize = uint32(len(sectionText))
	text.SizeOfRawData = uint32(pe.Align(uint(text.VirtualSize), uint(pent.OptionalHeader.FileAlignment)))

	text.PointerToRawData = uint32(length)
	sectionText = append(sectionText, pe.FillZeroByte(int(text.SizeOfRawData-text.VirtualSize))...)
	length += len(sectionText)

	rdata.PointerToRawData = uint32(length)
	sectionRdata = append(sectionRdata, pe.FillZeroByte(int(rdata.SizeOfRawData-rdata.VirtualSize))...)
	length += len(sectionRdata)

	data.PointerToRawData = uint32(length)
	sectionData = append(sectionData, pe.FillZeroByte(int(data.SizeOfRawData-data.VirtualSize))...)

	pent.OptionalHeader.SizeOfImage = pent.OptionalHeader.SizeOfHeaders +
		uint32(pe.Align(uint(text.SizeOfRawData), uint(pent.OptionalHeader.SectionAlignment))) +
		uint32(pe.Align(uint(rdata.SizeOfRawData), uint(pent.OptionalHeader.SectionAlignment))) +
		uint32(pe.Align(uint(data.SizeOfRawData),
			uint(pent.OptionalHeader.SectionAlignment)))

	// make exe
	f, err := os.Create("hello.exe")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	binary.Write(f, binary.LittleEndian, dosHeader)
	binary.Write(f, binary.LittleEndian, pent)
	binary.Write(f, binary.LittleEndian, text)
	binary.Write(f, binary.LittleEndian, rdata)
	binary.Write(f, binary.LittleEndian, data)
	binary.Write(f, binary.LittleEndian, ntheaderPadding)

	binary.Write(f, binary.LittleEndian, sectionText)
	binary.Write(f, binary.LittleEndian, sectionRdata)
	binary.Write(f, binary.LittleEndian, sectionData)
}
