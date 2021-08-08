package pe

const (
	PEMagic uint32 = 0x4550
)

const (
	ImageFileMachineUnknown   uint16 = 0x00
	ImageFileMachineAM33      uint16 = 0x1d3
	ImageFileMachineAMD64     uint16 = 0x8664
	ImageFileMachineARM       uint16 = 0x1c0
	ImageFileMachineARMNT     uint16 = 0x1c4
	ImageFileMachineARM64     uint16 = 0xaa64
	ImageFileMachineEBC       uint16 = 0xebc
	ImageFileMachineI386      uint16 = 0x14c
	ImageFileMachineIA64      uint16 = 0x200
	ImageFileMachineM32R      uint16 = 0x9041
	ImageFileMachineMIPS16    uint16 = 0x266
	ImageFileMachineMIPSFPU   uint16 = 0x366
	ImageFileMachineMIPSFPU16 uint16 = 0x466
	ImageFileMachinePOWERPC   uint16 = 0x1f0
	ImageFileMachinePOWERPCFP uint16 = 0x1f1
	ImageFileMachineR4000     uint16 = 0x166
	ImageFileMachineSH3       uint16 = 0x1a2
	ImageFileMachineSH3DSP    uint16 = 0x1a3
	ImageFileMachineSH4       uint16 = 0x1a6
	ImageFileMachineSH5       uint16 = 0x1a8
	ImageFileMachineTHUMB     uint16 = 0x1c2
	ImageFileMachineWCEMIPSV2 uint16 = 0x169
)

// ImageFileHeader Characteristics
// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header
const (
	ImageFileRelocsStripped uint16 = 1 << iota
	ImageFileExecutableImage
	ImageFileLineNumsStripped
	ImageFileLocalSymsStripped
	ImageFileAggresiveWsTrim
	ImageFileLargeAddressAware
	ImageFileBytesReversedLo uint16 = 1 << (iota + 1)
	ImageFile32bitMachine
	ImageFileDebugStripped
	ImageFileRemovableRunFromSwap
	ImageFileNetRunFromSwap
	ImageFileSystem
	ImageFileDll
	ImageFileUpSystemOnly
	ImageFileBytesReversedHi
)

const (
	ImageNtOptionalHdr32Magic uint16 = 0x10B // 32 可执行映像
	ImageNtOptionalHdr64Magic uint16 = 0x20B // 64 可执行映像
	ImageRomOptionalHdrMagic  uint16 = 0x107 // ROM 映像
)

// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32#members
const (
	ImageSubSystemUnknown    uint16 = iota // 未知子系统
	ImageSubSystemNative                   // 不需要子系统（设备驱动程序和本机系统进程）
	ImageSubSystemWindowsGUI               // Windows 图形用户界面 (GUI)
	ImageSubSystemWindowsCUI               // Windows 字符模式用户界面 (CUI)
)

type ImageNtHeaders32 struct {
	Signature      uint32                // PE文件标识 0x4550 'PE00'
	FileHeader     ImageFileHeader       // PE 标准头
	OptionalHeader ImageOptionalHeader32 // PE 扩展头
}

type ImageFileHeader struct {
	Machine              uint16 // 运行平台
	NumberOfSections     uint16 // PE中节的数量
	TimeDateStamp        uint32 // 文件创建日期和时间
	PointerToSymbolTable uint32 // 指向符号表（用于调试）
	NumberOfSymbols      uint32 // 符号表中的符号数量（用于调试）
	SizeOfOptionalHeader uint16 // 扩展头结构的长度
	Characteristics      uint16 // 文件属性标志
}

type ImageOptionalHeader32 struct {
	Magic                       uint16 // 魔术字
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32 // 代码段的大小，以字节为单位，如果有多个代码段，则为所有这些段的总和。必须是 FileAlignment 的整数倍，是在文件里的大小。
	SizeOfInitializedData       uint32 // 所有含已初始化数据的节的总大小
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32 // 程序执行入口RVA
	BaseOfCode                  uint32 // 代码节 起始RVA
	BaseOfData                  uint32 // 数据节 起始RVA
	ImageBase                   uint32 // 程序默认装入基地址,提供整个二进制文件包括所有头的优先（线性）载入地址,RVA
	SectionAlignment            uint32 // 内存中节的对其粒度
	FileAlignment               uint32 // 文件中节的对其粒度
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32 // 内存中整个PE映像体的尺寸(它是所有头和节经过节对齐处理后的大小)
	SizeOfHeaders               uint32 // DOS头+PE头+所有区块表的总大小(经过文件对齐处理后的大小)
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint32
	SizeOfStackCommit           uint32
	SizeOfHeapReserve           uint32
	SizeOfHeapCommit            uint32
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32 // 指定 DataDirectory 的数组个数，由于以前发行的 Windows NT的原因，它只能为 0x10
	DataDirectory               [16]DataDirectory
}

type DataDirectory struct {
	VirtualAddress uint32 // 数据的起始 RVA
	Size           uint32 // 数据块的长度
}
