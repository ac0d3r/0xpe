package pe

const (
	MZMagic uint16 = 0x5A4D
)

type DOSHeadr struct {
	EMagic    uint16     // Magic number  MZ 标识 0x5A4D
	ECblp     uint16     // Bytes on last page of file
	Ecp       uint16     // Pages in file  文件中页数
	Ecrlc     uint16     // Relocations  重新定位表中的指针数
	Ecparhdr  uint16     // Size of header in paragraphs  头部尺寸，以段落为单位
	Eminalloc uint16     // Minimum extra paragraphs needed  所需最小附加段
	Emaxalloc uint16     // Maximum extra paragraphs needed  所需最大附加段
	Ess       uint16     // Initial (relative) SS value  初始化的SS值（相对偏移量）
	Esp       uint16     // Initial SP value  初始的SP值
	Ecsum     uint16     // Checksum  补码校验值
	Eip       uint16     // Initial IP value  初始的IP值
	Ecs       uint16     // Initial (relative) CS value 初始的CS值（相对偏移量）
	Elfarlc   uint16     // File address of relocation table  重定位表的字节偏移里
	Eovno     uint16     // Overlay number  覆盖号
	Eres      [4]uint16  // Reserved words  保留字
	Eoemid    uint16     // OEM identifier (for e_oeminfo)  OEM标识符（相对 e_oeminfo）
	Eoeminfo  uint16     // OEM information; e_oemid specific  OEM信息
	Eres2     [10]uint16 // Reserved words  保留字
	Elfanew   uint32     // File address of new exe header  PE头相对文件的真正偏移量
}
