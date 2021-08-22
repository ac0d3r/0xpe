package pe

type ImageImportDescriptor struct {
	OriginalFirstThunk uint32
	TimeDateStamp      uint32
	ForwarderChain     uint32
	Name               uint32
	FirstThunk         uint32
}

type ImageThunkData32 struct {
	Function uint32
}

type ImageImportByName struct {
	Hint uint16
	Name string
}

func (i ImageImportByName) GetRaw() []byte {
	raw := make([]byte, 0, 3)
	raw = append(raw, byte(i.Hint&0xff00>>8), byte(i.Hint&0x00ff))
	raw = append(raw, StrConv2Bytes(i.Name)...)
	if len(raw)%2 == 1 {
		raw = append(raw, 0x00)
	}
	return raw
}
