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
// |    0xFB    | 32 byte |   uint16    |   var  |   uint16   |  var  |
// +------------+---------+-------------+--------+------------+-------+

const (
	// StubMagic is the mark of shield stub.
	StubMagic = 0xFB

	// StubSize is the shield stub total size at the runtime tail.
	StubSize = 8 * 1024
)

const xorKeySize = 32

// Set is used to encrypt shield and decoy, then write to runtime shield stub.
func Set(template, shield, decoy []byte) ([]byte, error) {
	if len(template) < StubSize {
		return nil, errors.New("invalid runtime template")
	}
	if 1+xorKeySize+2+len(shield)+2+len(decoy) > StubSize {
		return nil, errors.New("shield or decoy is too large")
	}
	// locate shield stub in runtime template
	stub := bytes.Repeat([]byte{0x00}, StubSize)
	stub[0] = StubMagic
	offset := bytes.Index(template, stub)
	if offset == -1 {
		return nil, errors.New("invalid runtime shield stub")
	}
	// generate xor key
	key := make([]byte, xorKeySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, errors.New("failed to generate key")
	}
	// build stub
	off := 1
	// write xor key
	copy(stub[off:], key)
	off += xorKeySize
	// write shield size
	size := binary.LittleEndian.AppendUint16(nil, uint16(len(shield))) // #nosec G115
	copy(stub[off:], size)
	off += 2
	// write encrypted shield
	copy(stub[off:], xor(shield, key))
	off += len(shield)
	// write decoy size
	size = binary.LittleEndian.AppendUint16(nil, uint16(len(decoy))) // #nosec G115
	copy(stub[off:], size)
	off += 2
	// write encrypted decoy
	copy(stub[off:], xor(decoy, key))
	off += len(decoy)
	// append padding data
	pad := make([]byte, StubSize-off)
	_, err = rand.Read(pad)
	if err != nil {
		return nil, errors.New("failed to generate padding data")
	}
	copy(stub[off:], pad)
	// copy template and set stub
	output := bytes.Clone(template)
	copy(output[offset:], stub)
	return output, nil
}

// Get is used to extract shield and decoy from the runtime shield stub.
// The offset is the position of the shield stub in the instance.
func Get(instance []byte, offset int) (shield []byte, decoy []byte, err error) {
	if len(instance) < StubSize {
		return nil, nil, errors.New("invalid runtime instance")
	}
	if offset < 0 || len(instance)-offset < StubSize {
		return nil, nil, errors.New("invalid offset of the runtime shield stub")
	}
	if instance[offset] != StubMagic {
		return nil, nil, errors.New("invalid runtime shield stub")
	}
	stub := instance[offset:]
	// skip magic
	off := 1
	// read xor key
	key := stub[off : off+xorKeySize]
	off += xorKeySize
	// read shield size
	shieldSize := int(binary.LittleEndian.Uint16(stub[off:]))
	off += 2
	// check stub have enough data
	if off+shieldSize+2 > StubSize {
		return nil, nil, errors.New("invalid shield size in stub")
	}
	// read encrypted shield
	shield = stub[off : off+shieldSize]
	off += shieldSize
	// read decoy size
	decoySize := int(binary.LittleEndian.Uint16(stub[off:]))
	off += 2
	// check stub have enough data
	if off+decoySize > StubSize {
		return nil, nil, errors.New("invalid decoy size in stub")
	}
	// read encrypted decoy
	decoy = stub[off : off+decoySize]
	// decrypt shield and decoy
	return xor(shield, key), xor(decoy, key), nil
}

func xor(data, key []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	output := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		output[i] = data[i] ^ key[i%len(key)]
	}
	return output
}
