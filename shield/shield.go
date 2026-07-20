package shield

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"

	"github.com/RTS-Framework/GRT-Develop/option"
	"github.com/RTS-Framework/GRT-Develop/ptrtable"
)

// +------------+--------+-------------+--------+------------+-------+
// | magic mark |  seed  | shield size | shield | decoy size | decoy |
// +------------+--------+-------------+--------+------------+-------+
// |    0xFA    | uint64 |   uint16    |   var  |   uint16   |  var  |
// +------------+--------+-------------+--------+------------+-------+

const (
	// StubMagic is the mark of shield stub.
	StubMagic = 0xFA

	// StubSize is the shield stub total size at the runtime tail.
	StubSize = 8 * 1024

	// StubSuffix is used to calculate fake template size for generator.
	StubSuffix = ptrtable.StubSize + option.StubSize
)

// about shield source
const (
	SourcePreInjected = "pre-injected"
	SourceShieldStub  = "shield stub"
	SourceExternal    = "external"
	SourceUnknown     = "unknown"
)

const (
	srcPreInjected = iota + 1
	srcShieldStub
	srcExternal
)

const seedSize = 8

// Set is used to obfuscate shield and decoy, then write to runtime shield stub.
// if shield or decoy is empty. it will reuse the old shield or decoy in stub.
func Set(template, shield, decoy []byte) ([]byte, error) {
	if len(template) < StubSize+StubSuffix {
		return nil, errors.New("invalid runtime template")
	}
	if 1+seedSize+2+len(shield)+2+len(decoy) > StubSize {
		return nil, errors.New("shield or decoy is too large")
	}
	// locate shield stub in runtime template
	offset := len(template) - (StubSize + StubSuffix)
	if template[offset] != StubMagic {
		return nil, errors.New("invalid runtime shield stub")
	}
	// get old shield and decoy
	oldShield, oldDecoy, err := Get(template, offset)
	if err != nil {
		return nil, err
	}
	if len(shield) < 1 {
		shield = oldShield
	}
	if len(decoy) < 1 {
		decoy = oldDecoy
	}
	// build new stub
	stub := bytes.Repeat([]byte{0x00}, StubSize)
	stub[0] = StubMagic
	// generate shuffle seed
	seed := make([]byte, seedSize)
	_, err = rand.Read(seed)
	if err != nil {
		return nil, errors.New("failed to generate key")
	}
	// build stub
	off := 1
	// write xor key
	copy(stub[off:], seed)
	off += seedSize
	// write shield size
	size := binary.LittleEndian.AppendUint16(nil, uint16(len(shield))) // #nosec G115
	copy(stub[off:], size)
	off += 2
	// write shuffled shield
	copy(stub[off:], shuffle(shield, seed))
	off += len(shield)
	// write decoy size
	size = binary.LittleEndian.AppendUint16(nil, uint16(len(decoy))) // #nosec G115
	copy(stub[off:], size)
	off += 2
	// write shuffled decoy
	copy(stub[off:], shuffle(decoy, seed))
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

func shuffle(data, seed []byte) []byte {
	buffer := bytes.Clone(data)
	s := binary.LittleEndian.Uint64(seed)
	for i := len(buffer) - 1; i > 0; i-- {
		j := s % uint64(i+1)
		t := buffer[i]
		buffer[i] = buffer[j]
		buffer[j] = t
		s = xorShift64(s)
	}
	return buffer
}

func xorShift64(seed uint64) uint64 {
	seed ^= seed << 13
	seed ^= seed >> 7
	seed ^= seed << 17
	return seed
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
	key := stub[off : off+seedSize]
	off += seedSize
	// read shield size
	shieldSize := int(binary.LittleEndian.Uint16(stub[off:]))
	off += 2
	// check stub have enough data
	if off+shieldSize+2 > StubSize {
		return nil, nil, errors.New("invalid shield size in stub")
	}
	// read shuffled shield
	shield = stub[off : off+shieldSize]
	off += shieldSize
	// read decoy size
	decoySize := int(binary.LittleEndian.Uint16(stub[off:]))
	off += 2
	// check stub have enough data
	if off+decoySize > StubSize {
		return nil, nil, errors.New("invalid decoy size in stub")
	}
	// read shuffled decoy
	decoy = stub[off : off+decoySize]
	// unshuffle shield and decoy
	return unshuffle(shield, key), unshuffle(decoy, key), nil
}

func unshuffle(data, seed []byte) []byte {
	buffer := bytes.Clone(data)
	s := binary.LittleEndian.Uint64(seed)
	// advance to the final seed
	for i := len(buffer) - 1; i > 0; i-- {
		s = xorShift64(s)
	}
	for i := 1; i < len(data); i++ {
		s = reverseXORShift64(s)
		j := s % uint64(i+1)
		t := buffer[i]
		buffer[i] = buffer[j]
		buffer[j] = t
	}
	return buffer
}

func reverseXORShift64(seed uint64) uint64 {
	// reverse seed ^= seed << 17
	seed ^= seed << 17
	seed ^= seed << 34

	// reverse seed ^= seed >> 7
	seed ^= seed >> 7
	seed ^= seed >> 14
	seed ^= seed >> 28
	seed ^= seed >> 56

	// reverse seed ^= seed << 13
	seed ^= seed << 13
	seed ^= seed << 26
	seed ^= seed << 52
	return seed
}

// ConvertSource is used to convert raw shield source.
func ConvertSource(src int64) string {
	switch src {
	case srcPreInjected:
		return SourcePreInjected
	case srcShieldStub:
		return SourceShieldStub
	case srcExternal:
		return SourceExternal
	default:
		return SourceUnknown
	}
}
