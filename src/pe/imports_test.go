package pe

import (
	"fmt"
	"testing"
)

func TestImageImportByName(t *testing.T) {
	i := ImageImportByName{
		Hint: 0xfb01,
		Name: "printf",
	}
	fmt.Println(i.GetRaw())
}
