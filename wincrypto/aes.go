package wincrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
)

// +---------+-------------+
// |   IV    | cipher data |
// +---------+-------------+
// | 16 byte |     var     |
// +---------+-------------+

// about AES block and IV.
const (
	AESBlockSize = 16
	AESIVSize    = 16
)

// errors about AESEncrypt and AESDecrypt.
var (
	ErrEmptyPlainData    = errors.New("empty aes plain data")
	ErrEmptyCipherData   = errors.New("empty aes cipher data")
	ErrInvalidCipherData = errors.New("invalid aes cipher data")
)

// AESEncrypt is used to encrypt data with CBC mode and PKCS#5 padding method.
func AESEncrypt(data, key []byte) ([]byte, error) {
	l := len(data)
	if l < 1 {
		return nil, ErrEmptyPlainData
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// make buffer
	paddingSize := AESBlockSize - l%AESBlockSize
	output := make([]byte, AESIVSize+l+paddingSize)
	// generate random iv
	iv := output[:AESIVSize]
	_, err = rand.Read(iv)
	if err != nil {
		return nil, fmt.Errorf("failed to generate aes iv: %s", err)
	}
	// copy plain data and padding data
	copy(output[AESIVSize:], data)
	padding := byte(paddingSize)
	for i := 0; i < paddingSize; i++ {
		output[AESIVSize+l+i] = padding
	}
	// encrypt plain data
	encrypter := cipher.NewCBCEncrypter(block, iv) // #nosec G407
	encrypter.CryptBlocks(output[AESIVSize:], output[AESIVSize:])
	return output, nil
}

// AESDecrypt is used to decrypt data with CBC mode and PKCS#5 padding method.
// The padding validation uses constant-time operations to prevent padding oracle attacks.
func AESDecrypt(data, key []byte) ([]byte, error) {
	l := len(data)
	if l < 1 {
		return nil, ErrEmptyCipherData
	}
	if l-AESIVSize < AESBlockSize {
		return nil, ErrInvalidCipherData
	}
	if (l-AESIVSize)%AESBlockSize != 0 {
		return nil, ErrInvalidCipherData
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	output := make([]byte, l-AESIVSize)
	iv := data[:AESIVSize]
	// decrypt cipher data
	decrypter := cipher.NewCBCDecrypter(block, iv)
	decrypter.CryptBlocks(output, data[AESIVSize:])
	// constant-time padding validation to prevent padding oracle attack.
	//
	// the attack works by observing different error responses for different
	// padding states. to mitigate this, we:
	// 1. always iterate through all AESBlockSize bytes (no early exit)
	// 2. use crypto/subtle for constant-time byte comparison
	// 3. accumulate the result in a single int flag (no branching on secret)
	// 4. return the same error for all failure cases
	outputSize := len(output)
	paddingSize := int(output[outputSize-1])
	// check that paddingSize is in valid range [1, AESBlockSize] using
	// constant-time comparison: valid if (paddingSize-1) < AESBlockSize
	valid := subtle.ConstantTimeLessOrEq(paddingSize-1, AESBlockSize-1)
	// check all bytes in the last block: each byte at position
	// (outputSize-1-i) for i in [0, paddingSize) must equal paddingSize.
	// we always loop AESBlockSize times and mask the result.
	for i := 0; i < AESBlockSize; i++ {
		// constant-time: 1 if i < paddingSize, 0 otherwise
		inRange := subtle.ConstantTimeLessOrEq(i, paddingSize-1)
		// constant-time: 1 if byte matches paddingSize, 0 otherwise
		match := subtle.ConstantTimeByteEq(output[outputSize-1-i], byte(paddingSize))
		// if inRange: require match; if not inRange: accept (mask = 1)
		// result = inRange*match + (1-inRange)*1 = 1 - inRange + inRange*match
		mask := 1 - inRange + inRange*match
		valid &= mask
	}
	if valid == 0 {
		return nil, ErrInvalidCipherData
	}
	return output[:outputSize-paddingSize], nil
}
