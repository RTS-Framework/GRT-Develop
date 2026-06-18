package ptrtable

import (
	"bytes"
	"crypto/rand"
	"errors"
)

// +------------+----------+----------+
// | magic mark | reserved | pointers |
// +------------+----------+----------+
// |    0xFA    |  7 byte  | 248 byte |
// +------------+----------+----------+

const (
	// StubMagic is the mark of pointer stub.
	StubMagic = 0xFA

	// StubSize is the pointer stub total size at the runtime tail.
	StubSize = 256
)

// Set is used to fill the random data to pointer stub.
func Set(template []byte) ([]byte, error) {
	if len(template) < StubSize {
		return nil, errors.New("invalid runtime template")
	}
	// locate pointer stub in runtime template
	stub := bytes.Repeat([]byte{0x00}, StubSize)
	stub[0] = StubMagic
	offset := bytes.LastIndex(template, stub)
	if offset == -1 {
		return nil, errors.New("invalid runtime pointer stub")
	}
	// fill the random data to the stub
	_, err := rand.Read(stub[1:])
	if err != nil {
		return nil, errors.New("failed to fill random data")
	}
	// copy template and set stub
	output := bytes.Clone(template)
	copy(output[offset:], stub)
	return output, nil
}
