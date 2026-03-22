package serialization

import (
	"encoding/binary"
	"errors"
	"unicode/utf16"
)

// serialized data structure
// +---------+----------+----------+----------+------------+
// |  magic  |  item 1  |  item 2  | item END |  raw data  |
// +---------+----------+----------+----------+------------+
// |  uint32 |  uint32  |  uint32  |  uint32  |    var     |
// +---------+----------+----------+----------+------------+
//
// item data structure
// 0······· value or pointer
// ·0000000 data length

const (
	magic   = 0xACFFFFEE
	itemEnd = 0x00000000

	maskType   = 0x80000000
	maskLength = 0x7FFFFFFF

	typeValue   = 0x00000000
	typePointer = 0x80000000
)

func stringToUTF16(s string) []byte {
	if s == "" {
		return nil
	}
	w := utf16.Encode([]rune(s))
	output := make([]byte, (len(w)+1)*2)
	for i := 0; i < len(w); i++ {
		binary.LittleEndian.PutUint16(output[i*2:], w[i])
	}
	return output
}

func utf16ToString(b []byte) (string, error) {
	n := len(b)
	n -= 2 // remove last character
	if n%2 != 0 {
		return "", errors.New("invalid utf16 string")
	}
	u16 := make([]uint16, n/2)
	for i := 0; i < len(u16); i++ {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u16)), nil
}
