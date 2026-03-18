package shield

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

// +---------+-------------+--------+------------+-------+
// |   key   | shield size | shield | decoy size | decoy |
// +---------+-------------+--------+------------+-------+
// | 4 byte  |   uint16    |   var  |   uint16   |  var  |
// +---------+-------------+--------+------------+-------+

const (
	// StubMagic is the mark of shield stub.
	StubMagic = 0xFB

	// StubSize is the shield stub total size at the runtime tail.
	StubSize = 8 * 1024
)

const keySize = 4

// Set is used to encrypt shield and decoy, then write to runtime shield stub.
func Set(tpl, shield, decoy []byte) ([]byte, error) {
	// check runtime template is valid
	if len(tpl) < StubSize {
		return nil, errors.New("invalid runtime template")
	}
	if keySize+2+len(shield)+2+len(decoy) > StubSize {
		return nil, errors.New("shield or decoy is too large")
	}
	// copy template
	output := make([]byte, len(tpl))
	copy(output, tpl)
	// generate random key
	key := make([]byte, keySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, errors.New("failed to generate key")
	}
	// encrypt shield and decoy
	encryptedShield := encrypt(shield, key)
	encryptedDecoy := encrypt(decoy, key)

	stub := make([]byte, totalSize)
	offset := 0
	// write key (4 bytes)
	copy(stub[offset:], key)
	offset += cryptoKeySize
	// write shield size (uint16)
	binary.LittleEndian.PutUint16(stub[offset:], uint16(len(encryptedShield))) // #nosec G115
	offset += 2
	// write shield data (var)
	copy(stub[offset:], encryptedShield)
	offset += len(encryptedShield)
	// write decoy size (uint16)
	binary.LittleEndian.PutUint16(stub[offset:], uint16(len(encryptedDecoy))) // #nosec G115
	offset += 2
	// write decoy data (var)
	copy(stub[offset:], encryptedDecoy)
	// append stub to output
	output = append(output, stub...)
	return output, nil
}

// Get is used to extract shield and decoy from the runtime shield stub.
func Get(instance []byte, offset int) ([]byte, []byte, error) {

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
