package pe

// SectionHeader32 Characteristics
// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header
const (
	ImageScnCntCode              uint32 = 0x00000020
	ImageScnCntInitializedData   uint32 = 0x00000040
	ImageScnCntUnInitializedData uint32 = 0x00000080
	ImageScnMemDiscardable       uint32 = 0x02000000
	ImageScnMemShared            uint32 = 0x10000000
	ImageScnMemExecute           uint32 = 0x20000000
	ImageScnMemRead              uint32 = 0x40000000
	ImageScnMemWrite             uint32 = 0x80000000
)

type SectionHeader32 struct {
	Name                 [8]uint8
	VirtualSize          uint32 //实际的、被使用的区块大小，是区块在没被对齐处理之前的大小
	VirtualAddress       uint32 //（Voffset）：装载到内存中的RVA，按照内存对齐，默认为1000h
	SizeOfRawData        uint32 // （Rsize）在磁盘中的大小，经过了对齐，FileAlignment默认大小为200h
	PointerToRawData     uint32 // （Roffset）盘文件中的偏移。如果程序自装载，这个字段比VitrualAddress更重要
	PointerToRelocations uint32
	PointerToLineNumbers uint32
	NumberOfRelocations  uint16
	NumberOfLineNumbers  uint16
	Characteristics      uint32 // 区块的属性
}
