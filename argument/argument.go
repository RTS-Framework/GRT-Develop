package argument

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// +------+---------+----------+-----------+----------+--------+----------+----------+
// | init |   key   | num args | args size | checksum | arg id | arg size | arg data |
// +------+---------+----------+-----------+----------+--------+----------+----------+
// | bool | 32 byte |  uint16  |  uint32   |  uint32  | uint32 |  uint32  |   var    |
// +------+---------+----------+-----------+----------+--------+----------+----------+

const (
	// MaxNumArguments is the maximum number of the arguments.
	MaxNumArguments = 1024

	// AlgoSwitchSize is a threshold for selecting the encryption algorithm.
	AlgoSwitchSize = 512
)

const (
	cryptoKeySize  = 32
	offsetNumArgs  = 1 + 32
	offsetArgsSize = 1 + 32 + 2
	offsetChecksum = 1 + 32 + 2 + 4
	offsetFirstArg = 1 + 32 + 2 + 4 + 4
)

// Arg contains the id and data about argument.
type Arg struct {
	ID   uint32 `toml:"id"   json:"id"`
	Data []byte `toml:"data" json:"data"`
}

// Encode is used to encode and encrypt arguments to stub.
func Encode(args ...*Arg) ([]byte, error) {
	if len(args) > MaxNumArguments {
		return nil, errors.New("too many arguments")
	}
	// generate seed for init flag and key
	seed := make([]byte, 1+cryptoKeySize)
	_, err := rand.Read(seed)
	if err != nil {
		return nil, errors.New("failed to generate seed")
	}
	buffer := bytes.NewBuffer(nil)
	buffer.Grow(offsetFirstArg)
	// write init flag
	buffer.WriteByte(seed[0] | 1)
	// write crypto key
	buffer.Write(seed[1:])
	// write the number of arguments
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint16(buf, uint16(len(args))) // #nosec G115
	buffer.Write(buf[:2])
	// calculate the total size of the arguments
	var argsSize uint32
	for i := 0; i < len(args); i++ {
		if args[i] == nil {
			return nil, fmt.Errorf("argument %d is nil", i)
		}
		argsSize += 4 + 4 + uint32(len(args[i].Data)) // #nosec G115
	}
	binary.LittleEndian.PutUint32(buf, argsSize)
	buffer.Write(buf)
	// reserve space for checksum
	buffer.Write(buf)
	// write arguments
	buffer.Grow(int(argsSize))
	ids := make(map[uint32]struct{})
	for i := 0; i < len(args); i++ {
		id := args[i].ID
		data := args[i].Data
		// check ID is already exists
		if _, ok := ids[id]; ok {
			return nil, fmt.Errorf("argument id %d already exists", id)
		}
		ids[id] = struct{}{}
		// write argument id
		binary.LittleEndian.PutUint32(buf, id)
		buffer.Write(buf)
		// write argument size
		binary.LittleEndian.PutUint32(buf, uint32(len(data))) // #nosec G115
		buffer.Write(buf)
		// write argument data
		buffer.Write(data)
	}
	stub := buffer.Bytes()
	xorHeader(stub)
	encryptStub(stub)
	// calculate argument checksum
	checksum := calculateChecksum(stub)
	binary.LittleEndian.PutUint32(stub[offsetChecksum:], checksum)
	return stub, nil
}

// Decode is used to decrypt and decode arguments from raw stub.
func Decode(stub []byte) ([]*Arg, error) {
	if len(stub) < offsetFirstArg {
		return nil, errors.New("invalid argument stub")
	}
	if stub[0] == 0 {
		return nil, errors.New("invalid argument stub flag")
	}
	// calculate checksum
	checksum := calculateChecksum(stub)
	expected := binary.LittleEndian.Uint32(stub[offsetChecksum:])
	if checksum != expected {
		return nil, errors.New("invalid argument stub checksum")
	}
	stub = bytes.Clone(stub)
	xorHeader(stub)
	numArgs := binary.LittleEndian.Uint16(stub[offsetNumArgs:])
	argsSize := binary.LittleEndian.Uint32(stub[offsetArgsSize:])
	if numArgs == 0 && argsSize == 0 {
		return nil, nil
	}
	if numArgs == 0 {
		return nil, errors.New("invalid argument total size")
	}
	if numArgs > MaxNumArguments {
		return nil, errors.New("invalid num argument")
	}
	decryptStub(stub)
	// decode arguments
	args := make([]*Arg, 0, numArgs)
	offset := int64(offsetFirstArg)
	rem := int64(binary.LittleEndian.Uint32(stub[offsetArgsSize:]))
	for i := 0; i < int(numArgs); i++ {
		if offset+8 > int64(len(stub)) {
			return nil, errors.New("invalid argument data")
		}
		id := binary.LittleEndian.Uint32(stub[offset:])
		offset += 4
		size := int64(binary.LittleEndian.Uint32(stub[offset:]))
		offset += 4
		if offset+size > int64(len(stub)) || 4+4+size > rem {
			return nil, errors.New("invalid argument size")
		}
		data := make([]byte, size)
		copy(data, stub[offset:offset+size])
		args = append(args, &Arg{ID: id, Data: data})
		offset += size
		rem -= 4 + 4 + size
	}
	return args, nil
}

func calculateChecksum(stub []byte) uint32 {
	data := stub[offsetFirstArg:]
	var crc uint32 = 0xFFFFFFFF
	for i := 0; i < len(data); i++ {
		crc ^= uint32(data[i])
		for j := 0; j < 8; j++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xEDB88320
			} else {
				crc >>= 1
			}
		}
	}
	return crc ^ 0xFFFFFFFF
}

func xorHeader(stub []byte) {
	data := stub[offsetNumArgs:offsetChecksum]
	key := stub[:cryptoKeySize]
	for i := 0; i < len(data); i++ {
		data[i] = data[i] ^ key[i%len(key)]
	}
}

func encryptStub(stub []byte) {
	data := stub[offsetFirstArg:]
	key := stub[:cryptoKeySize]
	if len(data) > AlgoSwitchSize {
		seed := binary.LittleEndian.Uint64(key[:8])
		obfuscateStub(data, seed)
		return
	}
	last := binary.LittleEndian.Uint32(key[:4])
	ctr := binary.LittleEndian.Uint32(key[4:])
	keyIdx := last % cryptoKeySize
	for i := 0; i < len(data); i++ {
		b := data[i]
		b ^= byte(last)           // #nosec G115
		b = rol(b, uint8(last%8)) // #nosec G115
		b ^= key[keyIdx]
		b += byte(ctr ^ last)     // #nosec G115
		b = ror(b, uint8(last%8)) // #nosec G115
		data[i] = b
		// update key index
		keyIdx++
		if keyIdx >= cryptoKeySize {
			keyIdx = 0
		}
		ctr++
		last = xorShift32(last)
	}
}

func decryptStub(stub []byte) {
	data := stub[offsetFirstArg:]
	key := stub[:cryptoKeySize]
	if len(data) > AlgoSwitchSize {
		seed := binary.LittleEndian.Uint64(key[:8])
		illuminateStub(data, seed)
		return
	}
	last := binary.LittleEndian.Uint32(key[:4])
	ctr := binary.LittleEndian.Uint32(key[4:])
	keyIdx := last % cryptoKeySize
	for i := 0; i < len(data); i++ {
		b := data[i]
		b = rol(b, uint8(last%8)) // #nosec G115
		b -= byte(ctr ^ last)     // #nosec G115
		b ^= key[keyIdx]
		b = ror(b, uint8(last%8)) // #nosec G115
		b ^= byte(last)           // #nosec G115
		data[i] = b
		// update key index
		keyIdx++
		if keyIdx >= cryptoKeySize {
			keyIdx = 0
		}
		ctr++
		last = xorShift32(last)
	}
}

func obfuscateStub(stub []byte, seed uint64) {
	sbox := initSBox(seed)
	for i := 0; i < len(stub); i++ {
		stub[i] = sbox[stub[i]]
	}
	shuffle(stub, seed)
}

func illuminateStub(stub []byte, seed uint64) {
	sbox := initSBox(seed)
	sbox = reverseSBox(sbox)
	unshuffle(stub, seed)
	for i := 0; i < len(stub); i++ {
		stub[i] = sbox[stub[i]]
	}
}

func initSBox(seed uint64) [256]byte {
	var sbox [256]byte
	for i := 0; i < 256; i++ {
		sbox[i] = byte(i)
	}
	for i := len(sbox) - 1; i > 0; i-- {
		j := seed % uint64(i+1)
		t := sbox[i]
		sbox[i] = sbox[j]
		sbox[j] = t
		seed = xorShift64(seed)
	}
	return sbox
}

func reverseSBox(sbox [256]byte) [256]byte {
	var r [256]byte
	for i := 0; i < 256; i++ {
		r[sbox[i]] = byte(i)
	}
	return r
}

func shuffle(data []byte, seed uint64) {
	for i := len(data) - 1; i > 0; i-- {
		j := seed % uint64(i+1)
		t := data[i]
		data[i] = data[j]
		data[j] = t
		seed = xorShift64(seed)
	}
}

func unshuffle(data []byte, seed uint64) {
	// advance to the final seed
	for i := len(data) - 1; i > 0; i-- {
		seed = xorShift64(seed)
	}
	for i := 1; i < len(data); i++ {
		seed = reverseXORShift64(seed)
		j := seed % uint64(i+1)
		t := data[i]
		data[i] = data[j]
		data[j] = t
	}
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

func xorShift64(seed uint64) uint64 {
	seed ^= seed << 13
	seed ^= seed >> 7
	seed ^= seed << 17
	return seed
}

func xorShift32(seed uint32) uint32 {
	seed ^= seed << 13
	seed ^= seed >> 17
	seed ^= seed << 5
	return seed
}

func ror(value byte, bits uint8) byte {
	return value>>bits | value<<(8-bits)
}

func rol(value byte, bits uint8) byte {
	return value<<bits | value>>(8-bits)
}
