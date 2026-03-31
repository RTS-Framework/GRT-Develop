package wincrypto

import (
	"crypto/rand"
	"errors"
	"testing"

	"github.com/For-ACGN/monkey"
	"github.com/stretchr/testify/require"
)

func TestAESEncrypt(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 1
	key[1] = 2

	t.Run("common", func(t *testing.T) {
		data := []byte("hello world")

		output, err := AESEncrypt(data, key)
		require.NoError(t, err)
		require.Len(t, output, 32)
	})

	t.Run("empty plain data", func(t *testing.T) {
		output, err := AESEncrypt(nil, key)
		require.Equal(t, ErrEmptyPlainData, err)
		require.Nil(t, output)
	})

	t.Run("invalid key", func(t *testing.T) {
		data := []byte("hello world")

		output, err := AESEncrypt(data, nil)
		require.EqualError(t, err, "crypto/aes: invalid key size 0")
		require.Nil(t, output)
	})

	t.Run("failed to generate IV", func(t *testing.T) {
		patch := func([]byte) (int, error) {
			return 0, errors.New("monkey error")
		}
		pg := monkey.Patch(rand.Read, patch)
		defer pg.Unpatch()

		data := []byte("hello world")

		output, err := AESEncrypt(data, key)
		require.EqualError(t, err, "failed to generate aes iv: monkey error")
		require.Nil(t, output)
	})
}

func TestAESDecrypt(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 1
	key[1] = 2

	t.Run("common", func(t *testing.T) {
		data := []byte("hello world")

		output, err := AESEncrypt(data, key)
		require.NoError(t, err)

		output, err = AESDecrypt(output, key)
		require.NoError(t, err)
		require.Equal(t, data, output)
	})

	t.Run("empty cipher data", func(t *testing.T) {
		output, err := AESDecrypt(nil, key)
		require.Equal(t, ErrEmptyCipherData, err)
		require.Nil(t, output)
	})

	t.Run("invalid key size", func(t *testing.T) {
		output, err := AESDecrypt(make([]byte, 32), nil)
		require.EqualError(t, err, "crypto/aes: invalid key size 0")
		require.Nil(t, output)
	})

	t.Run("invalid cipher data", func(t *testing.T) {
		plainData, err := AESDecrypt(make([]byte, 7), key)
		require.Equal(t, ErrInvalidCipherData, err)
		require.Nil(t, plainData)

		plainData, err = AESDecrypt(make([]byte, 63), key)
		require.Equal(t, ErrInvalidCipherData, err)
		require.Nil(t, plainData)
	})

	t.Run("invalid padding size", func(t *testing.T) {
		cipherData := make([]byte, 32)

		plainData, err := AESDecrypt(cipherData, key)
		require.Equal(t, ErrInvalidPaddingSize, err)
		require.Nil(t, plainData)

		cipherData = make([]byte, 32)
		cipherData[31] = 17 // decrypted

		plainData, err = AESDecrypt(cipherData, key)
		require.Equal(t, ErrInvalidPaddingSize, err)
		require.Nil(t, plainData)
	})

	t.Run("invalid padding data", func(t *testing.T) {
		cipherData := make([]byte, 32)
		cipherData[31] = 7 // decrypted

		plainData, err := AESDecrypt(cipherData, key)
		require.Equal(t, ErrInvalidPaddingData, err)
		require.Nil(t, plainData)
	})
}
