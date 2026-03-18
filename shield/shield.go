package shield

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// +------------+---------+-------------+--------+------------+-------+
// | magic mark | xor key | shield size | shield | decoy size | decoy |
// +------------+---------+-------------+--------+------------+-------+
// |    0xFB    | 4 byte  |   uint16    |   var  |   uint16   |  var  |
// +------------+---------+-------------+--------+------------+-------+

const (
	// StubMagic is the mark of shield stub.
	StubMagic = 0xFB

	// StubSize is the shield stub total size at the runtime tail.
	StubSize = 8 * 1024
)

const xorKeySize = 4

// Set is used to encrypt shield and decoy, then write to runtime shield stub.
func Set(tpl, shield, decoy []byte) ([]byte, error) {
	if len(tpl) < StubSize {
		return nil, errors.New("invalid runtime template")
	}
	if 1+xorKeySize+2+len(shield)+2+len(decoy) > StubSize {
		return nil, errors.New("shield or decoy is too large")
	}
	// locate shield stub in runtime template
	stub := bytes.Repeat([]byte{0x00}, StubSize)
	stub[0] = StubMagic
	offset := bytes.Index(tpl, stub)
	if offset == -1 {
		return nil, errors.New("invalid runtime shield stub")
	}
	// copy template
	output := make([]byte, len(tpl))
	copy(output, tpl)
	// generate xor key
	key := make([]byte, xorKeySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, errors.New("failed to generate key")
	}
	// build stub
	off := 1
	copy(stub[off:], key)
	off += xorKeySize
	size := binary.LittleEndian.AppendUint16(nil, uint16(len(shield)))
	copy(stub[off:], size)
	off += 2
	copy(stub[off:], xor(shield, key))
	off += len(shield)
	size = binary.LittleEndian.AppendUint16(nil, uint16(len(decoy)))
	copy(stub[off:], size)
	off += 2
	copy(stub[off:], xor(decoy, key))
	off += len(decoy)
	// append padding data
	pad := make([]byte, StubSize-off)
	_, err = rand.Read(pad)
	if err != nil {
		return nil, errors.New("failed to generate padding data")
	}
	copy(stub[off:], pad)
	// set stub data
	copy(output[offset:], stub)
	return output, nil
}

// Get is used to extract shield and decoy from the runtime shield stub.
func Get(instance []byte, offset int) ([]byte, []byte, error) {
	return nil, nil, nil
}

func xor(data, key []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	output := make([]byte, len(data))
	keyLen := len(key)
	for i := 0; i < len(data); i++ {
		output[i] = data[i] ^ key[i%keyLen]
	}
	return output
}
