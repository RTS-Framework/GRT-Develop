package wincrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
	ErrEmptyPlainData     = errors.New("empty aes plain data")
	ErrEmptyCipherData    = errors.New("empty aes cipher data")
	ErrInvalidCipherData  = errors.New("invalid aes cipher data")
	ErrInvalidPaddingSize = errors.New("invalid aes padding size")
	ErrInvalidPaddingData = errors.New("invalid aes padding data")
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
	// process padding data
	outputSize := len(output)
	paddingSize := int(output[outputSize-1])
	if paddingSize > AESBlockSize || paddingSize == 0 {
		return nil, ErrInvalidPaddingSize
	}
	for i := outputSize - paddingSize; i < outputSize; i++ {
		if output[i] != byte(paddingSize) {
			return nil, ErrInvalidPaddingData
		}
	}
	return output[:outputSize-paddingSize], nil
}
