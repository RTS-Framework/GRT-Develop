package shield

import (
	"bytes"
	"encoding/hex"
	"errors"
)

// +---------+-------------+--------+------------+-------+
// |   key   | shield size | shield | decoy size | decoy |
// +---------+-------------+--------+------------+-------+
// | 4 byte  |   uint16    |   var  |   uint16   |  var  |
// +---------+-------------+--------+------------+-------+

// MaxStubSize is the maximum supported size about shield and decoy.
// Reference the shield stub at the tail of Gleam-RT.
const MaxStubSize = 8 * 1024

// Set is used to encrypt shield and write to runtime shield stub.
func Set(tpl, shield, decoy []byte) ([]byte, error) {
	if len(shield)+len(decoy)+(4+2+2) > MaxStubSize {
		return nil, errors.New("shield or decoy is too large")
	}

	output := make([]byte, len(tpl))
	copy(output, tpl)
	return output, nil
}

// Get is used to extra shield from tje runtime shield stub.
func Get(instance []byte, offset int) ([]byte, []byte, error) {
	return nil, nil, nil
}

// // aligned to the memory page size
//		pad := bytes.Repeat([]byte{0x00}, shield.MaxShieldSize-len(output))
//		output = append(output, pad...)
//		output = dumpModule(output)

func dumpModule(b []byte) []byte {
	n := len(b)
	builder := bytes.Buffer{}
	builder.Grow(len("0FFh, ")*n - len(", "))
	buf := make([]byte, 2)
	var counter = 0
	for i := 0; i < n; i++ {
		if counter == 0 {
			builder.WriteString("  db ")
		}
		hex.Encode(buf, b[i:i+1])
		builder.WriteString("0")
		builder.Write(bytes.ToUpper(buf))
		builder.WriteString("h")
		if i == n-1 {
			builder.WriteString("\r\n")
			break
		}
		counter++
		if counter != 16 {
			builder.WriteString(", ")
			continue
		}
		counter = 0
		builder.WriteString("\r\n")
	}
	return builder.Bytes()
}
