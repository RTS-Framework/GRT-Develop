package argument

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// +---------+----------+-----------+----------+--------+----------+----------+
// |   key   | num args | args size | checksum | arg id | arg size | arg data |
// +---------+----------+-----------+----------+--------+----------+----------+
// | 32 byte |  uint32  |  uint32   |  uint32  | uint32 |  uint32  |   var    |
// +---------+----------+-----------+----------+--------+----------+----------+

// MaxNumArguments is the maximum number of the arguments.
const MaxNumArguments = 1024

const (
	cryptoKeySize  = 32
	offsetNumArgs  = 32
	offsetArgsSize = 32 + 4
	offsetChecksum = 32 + 4 + 4
	offsetFirstArg = 32 + 4 + 4 + 4
)

// Arg contains the id and data about argument.
type Arg struct {
	ID   uint32
	Data []byte
}

// Encode is used to encode and encrypt arguments to stub.
func Encode(args ...*Arg) ([]byte, error) {
	if len(args) > MaxNumArguments {
		return nil, errors.New("too many arguments")
	}
	key := make([]byte, cryptoKeySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, errors.New("failed to generate crypto key")
	}
	// write crypto key
	buffer := bytes.NewBuffer(nil)
	buffer.Grow(offsetFirstArg)
	buffer.Write(key)
	// write the number of arguments
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(len(args))) // #nosec G115
	buffer.Write(buf)
	// calculate the total size of the arguments
	var argsSize uint32
	for i := 0; i < len(args); i++ {
		if args[i] == nil {
			return nil, errors.New("appear nil argument")
		}
		argsSize += 4 + 4 + uint32(len(args[i].Data)) // #nosec G115
	}
	binary.LittleEndian.PutUint32(buf, argsSize)
	buffer.Write(buf)
	// calculate header checksum
	var checksum uint32
	for _, b := range buffer.Bytes() {
		checksum += checksum << 1
		checksum += uint32(b)
	}
	binary.LittleEndian.PutUint32(buf, checksum)
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
	output := buffer.Bytes()
	encryptStub(output)
	return output, nil
}

// Decode is used to decrypt and decode arguments from raw stub.
func Decode(stub []byte) ([]*Arg, error) {
	if len(stub) < offsetFirstArg {
		return nil, errors.New("invalid argument stub")
	}
	// calculate checksum
	var checksum uint32
	for _, b := range stub[:offsetChecksum] {
		checksum += checksum << 1
		checksum += uint32(b)
	}
	expected := binary.LittleEndian.Uint32(stub[offsetChecksum:])
	if checksum != expected {
		return nil, errors.New("invalid argument stub checksum")
	}
	numArgs := binary.LittleEndian.Uint32(stub[offsetNumArgs:])
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
	stub = bytes.Clone(stub)
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

func encryptStub(stub []byte) {
	data := stub[offsetFirstArg:]
	key := stub[:cryptoKeySize]
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
