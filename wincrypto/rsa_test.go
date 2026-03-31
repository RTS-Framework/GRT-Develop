package wincrypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"os"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func TestParseRSAPublicKeyPEM(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		data := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey),
		})

		pub, err := ParseRSAPublicKeyPEM(data)
		require.NoError(t, err)
		require.Equal(t, &key.PublicKey, pub)
	})

	t.Run("invalid data", func(t *testing.T) {
		pub, err := ParseRSAPublicKeyPEM(nil)
		require.EqualError(t, err, "failed to decode PEM data")
		require.Nil(t, pub)
	})
}

func TestParseRSAPrivateKeyPEM(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		data := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		})

		pri, err := ParseRSAPrivateKeyPEM(data)
		require.NoError(t, err)
		require.Equal(t, key, pri)
	})

	t.Run("invalid data", func(t *testing.T) {
		pri, err := ParseRSAPrivateKeyPEM(nil)
		require.EqualError(t, err, "failed to decode PEM data")
		require.Nil(t, pri)
	})
}

func TestParseRSAPublicKey(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		data, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		require.NoError(t, err)

		pub, err := ParseRSAPublicKey(data)
		require.NoError(t, err)
		require.Equal(t, &key.PublicKey, pub)
	})

	t.Run("invalid data", func(t *testing.T) {
		pub, err := ParseRSAPublicKey(nil)
		require.EqualError(t, err, "asn1: syntax error: sequence truncated")
		require.Nil(t, pub)
	})

	t.Run("invalid public key type", func(t *testing.T) {
		key, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		data, err := x509.MarshalPKIXPublicKey(key)
		require.NoError(t, err)

		pub, err := ParseRSAPublicKey(data)
		require.EqualError(t, err, "invalid public key type")
		require.Nil(t, pub)
	})
}

func TestParseRSAPrivateKey(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		data, err := x509.MarshalPKCS8PrivateKey(key)
		require.NoError(t, err)

		pri, err := ParseRSAPrivateKey(data)
		require.NoError(t, err)
		require.Equal(t, key, pri)
	})

	t.Run("invalid data", func(t *testing.T) {
		pri, err := ParseRSAPrivateKey(nil)
		require.EqualError(t, err, "asn1: syntax error: sequence truncated")
		require.Nil(t, pri)
	})

	t.Run("invalid public key type", func(t *testing.T) {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		data, err := x509.MarshalPKCS8PrivateKey(key)
		require.NoError(t, err)

		pri, err := ParseRSAPrivateKey(data)
		require.EqualError(t, err, "invalid private key type")
		require.Nil(t, pri)
	})
}

func TestImportRSAPublicKeyBlob(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		key, err := os.ReadFile("testdata/public.key")
		require.NoError(t, err)

		publicKey, err := ImportRSAPublicKeyBlob(key)
		require.NoError(t, err)
		require.NotNil(t, publicKey)
	})

	t.Run("invalid blob header", func(t *testing.T) {
		publicKey, err := ImportRSAPublicKeyBlob(nil)
		require.EqualError(t, err, "failed to read blob header: EOF")
		require.Nil(t, publicKey)
	})

	t.Run("invalid blob type", func(t *testing.T) {
		buf := new(bytes.Buffer)
		_ = binary.Write(buf, binary.LittleEndian, blobHeader{
			Type:     privateKeyBlob,
			Version:  curBlobVersion,
			AiKeyAlg: cAlgRSASign,
		})

		publicKey, err := ImportRSAPublicKeyBlob(buf.Bytes())
		require.EqualError(t, err, "invalid blob type")
		require.Nil(t, publicKey)
	})

	t.Run("invalid blob version", func(t *testing.T) {
		buf := new(bytes.Buffer)
		_ = binary.Write(buf, binary.LittleEndian, blobHeader{
			Type:     publicKeyBlob,
			Version:  1,
			AiKeyAlg: cAlgRSASign,
		})

		publicKey, err := ImportRSAPublicKeyBlob(buf.Bytes())
		require.EqualError(t, err, "invalid blob version")
		require.Nil(t, publicKey)
	})

	t.Run("invalid public key algorithm", func(t *testing.T) {
		buf := new(bytes.Buffer)
		_ = binary.Write(buf, binary.LittleEndian, blobHeader{
			Type:     publicKeyBlob,
			Version:  curBlobVersion,
			AiKeyAlg: 1,
		})

		publicKey, err := ImportRSAPublicKeyBlob(buf.Bytes())
		require.EqualError(t, err, "invalid public key algorithm")
		require.Nil(t, publicKey)
	})

	t.Run("failed to read blob public key", func(t *testing.T) {
		buf := new(bytes.Buffer)
		_ = binary.Write(buf, binary.LittleEndian, blobHeader{
			Type:     publicKeyBlob,
			Version:  curBlobVersion,
			AiKeyAlg: cAlgRSASign,
		})
		_ = binary.Write(buf, binary.LittleEndian, uint32(magicRSA1))

		publicKey, err := ImportRSAPublicKeyBlob(buf.Bytes())
		require.EqualError(t, err, "failed to read blob public key: unexpected EOF")
		require.Nil(t, publicKey)
	})

	t.Run("invalid blob magic", func(t *testing.T) {
		buf := new(bytes.Buffer)
		_ = binary.Write(buf, binary.LittleEndian, blobHeader{
			Type:     publicKeyBlob,
			Version:  curBlobVersion,
			AiKeyAlg: cAlgRSASign,
		})
		_ = binary.Write(buf, binary.LittleEndian, rsaPubKey{
			Magic:  magicRSA2,
			BitLen: 2048,
			PubExp: 65537,
		})

		publicKey, err := ImportRSAPublicKeyBlob(buf.Bytes())
		require.EqualError(t, err, "invalid blob magic")
		require.Nil(t, publicKey)
	})

	t.Run("zero blob bit len", func(t *testing.T) {
		buf := new(bytes.Buffer)
		_ = binary.Write(buf, binary.LittleEndian, blobHeader{
			Type:     publicKeyBlob,
			Version:  curBlobVersion,
			AiKeyAlg: cAlgRSASign,
		})
		_ = binary.Write(buf, binary.LittleEndian, rsaPubKey{
			Magic:  magicRSA1,
			BitLen: 0,
			PubExp: 65537,
		})

		privateKey, err := ImportRSAPublicKeyBlob(buf.Bytes())
		require.EqualError(t, err, "blob bit length is zero")
		require.Nil(t, privateKey)
	})

	t.Run("invalid blob bit length", func(t *testing.T) {
		buf := new(bytes.Buffer)
		_ = binary.Write(buf, binary.LittleEndian, blobHeader{
			Type:     publicKeyBlob,
			Version:  curBlobVersion,
			AiKeyAlg: cAlgRSASign,
		})
		_ = binary.Write(buf, binary.LittleEndian, rsaPubKey{
			Magic:  magicRSA1,
			BitLen: 2047,
			PubExp: 65537,
		})

		publicKey, err := ImportRSAPublicKeyBlob(buf.Bytes())
		require.EqualError(t, err, "invalid blob bit length")
		require.Nil(t, publicKey)
	})

	t.Run("too large blob bit length", func(t *testing.T) {
		buf := new(bytes.Buffer)
		_ = binary.Write(buf, binary.LittleEndian, blobHeader{
			Type:     publicKeyBlob,
			Version:  curBlobVersion,
			AiKeyAlg: cAlgRSASign,
		})
		_ = binary.Write(buf, binary.LittleEndian, rsaPubKey{
			Magic:  magicRSA1,
			BitLen: 65536,
			PubExp: 65537,
		})

		publicKey, err := ImportRSAPublicKeyBlob(buf.Bytes())
		require.EqualError(t, err, "blob bit length is too large")
		require.Nil(t, publicKey)
	})

	t.Run("failed to read modulus", func(t *testing.T) {
		buf := new(bytes.Buffer)
		_ = binary.Write(buf, binary.LittleEndian, blobHeader{
			Type:     publicKeyBlob,
			Version:  curBlobVersion,
			AiKeyAlg: cAlgRSASign,
		})
		_ = binary.Write(buf, binary.LittleEndian, rsaPubKey{
			Magic:  magicRSA1,
			BitLen: 2048,
			PubExp: 65537,
		})
		_ = binary.Write(buf, binary.LittleEndian, []byte{0x01})

		publicKey, err := ImportRSAPublicKeyBlob(buf.Bytes())
		require.EqualError(t, err, "failed to read modulus: unexpected EOF")
		require.Nil(t, publicKey)
	})
}

func TestImportRSAPrivateKeyBlob(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		key, err := os.ReadFile("testdata/private.key")
		require.NoError(t, err)

		privateKey, err := ImportRSAPrivateKeyBlob(key)
		require.NoError(t, err)
		require.NotNil(t, privateKey)
	})

	t.Run("invalid blob header", func(t *testing.T) {
		privateKey, err := ImportRSAPrivateKeyBlob(nil)
		require.EqualError(t, err, "failed to read blob header: EOF")
		require.Nil(t, privateKey)
	})

	t.Run("invalid blob type", func(t *testing.T) {
		buf := new(bytes.Buffer)
		_ = binary.Write(buf, binary.LittleEndian, blobHeader{
			Type:     publicKeyBlob,
			Version:  curBlobVersion,
			AiKeyAlg: cAlgRSASign,
		})

		privateKey, err := ImportRSAPrivateKeyBlob(buf.Bytes())
		require.EqualError(t, err, "invalid blob type")
		require.Nil(t, privateKey)
	})

	t.Run("invalid blob version", func(t *testing.T) {
		buf := new(bytes.Buffer)
		_ = binary.Write(buf, binary.LittleEndian, blobHeader{
			Type:     privateKeyBlob,
			Version:  1,
			AiKeyAlg: cAlgRSASign,
		})

		privateKey, err := ImportRSAPrivateKeyBlob(buf.Bytes())
		require.EqualError(t, err, "invalid blob version")
		require.Nil(t, privateKey)
	})

	t.Run("invalid private key algorithm", func(t *testing.T) {
		buf := new(bytes.Buffer)
		_ = binary.Write(buf, binary.LittleEndian, blobHeader{
			Type:     privateKeyBlob,
			Version:  curBlobVersion,
			AiKeyAlg: 1,
		})

		privateKey, err := ImportRSAPrivateKeyBlob(buf.Bytes())
		require.EqualError(t, err, "invalid private key algorithm")
		require.Nil(t, privateKey)
	})

	t.Run("failed to read blob public key", func(t *testing.T) {
		buf := new(bytes.Buffer)
		_ = binary.Write(buf, binary.LittleEndian, blobHeader{
			Type:     privateKeyBlob,
			Version:  curBlobVersion,
			AiKeyAlg: cAlgRSASign,
		})
		_ = binary.Write(buf, binary.LittleEndian, uint32(magicRSA1))

		privateKey, err := ImportRSAPrivateKeyBlob(buf.Bytes())
		require.EqualError(t, err, "failed to read blob private key: unexpected EOF")
		require.Nil(t, privateKey)
	})

	t.Run("invalid blob magic", func(t *testing.T) {
		buf := new(bytes.Buffer)
		_ = binary.Write(buf, binary.LittleEndian, blobHeader{
			Type:     privateKeyBlob,
			Version:  curBlobVersion,
			AiKeyAlg: cAlgRSASign,
		})
		_ = binary.Write(buf, binary.LittleEndian, rsaPubKey{
			Magic:  magicRSA1,
			BitLen: 2048,
			PubExp: 65537,
		})

		privateKey, err := ImportRSAPrivateKeyBlob(buf.Bytes())
		require.EqualError(t, err, "invalid blob magic")
		require.Nil(t, privateKey)
	})

	t.Run("zero blob bit len", func(t *testing.T) {
		buf := new(bytes.Buffer)
		_ = binary.Write(buf, binary.LittleEndian, blobHeader{
			Type:     privateKeyBlob,
			Version:  curBlobVersion,
			AiKeyAlg: cAlgRSASign,
		})
		_ = binary.Write(buf, binary.LittleEndian, rsaPubKey{
			Magic:  magicRSA2,
			BitLen: 0,
			PubExp: 65537,
		})

		privateKey, err := ImportRSAPrivateKeyBlob(buf.Bytes())
		require.EqualError(t, err, "blob bit length is zero")
		require.Nil(t, privateKey)
	})

	t.Run("invalid blob bit length", func(t *testing.T) {
		buf := new(bytes.Buffer)
		_ = binary.Write(buf, binary.LittleEndian, blobHeader{
			Type:     privateKeyBlob,
			Version:  curBlobVersion,
			AiKeyAlg: cAlgRSASign,
		})
		_ = binary.Write(buf, binary.LittleEndian, rsaPubKey{
			Magic:  magicRSA2,
			BitLen: 2047,
			PubExp: 65537,
		})

		privateKey, err := ImportRSAPrivateKeyBlob(buf.Bytes())
		require.EqualError(t, err, "invalid blob bit length")
		require.Nil(t, privateKey)
	})

	t.Run("too large blob bit length", func(t *testing.T) {
		buf := new(bytes.Buffer)
		_ = binary.Write(buf, binary.LittleEndian, blobHeader{
			Type:     privateKeyBlob,
			Version:  curBlobVersion,
			AiKeyAlg: cAlgRSASign,
		})
		_ = binary.Write(buf, binary.LittleEndian, rsaPubKey{
			Magic:  magicRSA2,
			BitLen: 65536,
			PubExp: 65537,
		})

		privateKey, err := ImportRSAPrivateKeyBlob(buf.Bytes())
		require.EqualError(t, err, "blob bit length is too large")
		require.Nil(t, privateKey)
	})

	t.Run("failed to read modulus", func(t *testing.T) {
		buf := new(bytes.Buffer)
		_ = binary.Write(buf, binary.LittleEndian, blobHeader{
			Type:     privateKeyBlob,
			Version:  curBlobVersion,
			AiKeyAlg: cAlgRSASign,
		})
		_ = binary.Write(buf, binary.LittleEndian, rsaPubKey{
			Magic:  magicRSA2,
			BitLen: 2048,
			PubExp: 65537,
		})
		_ = binary.Write(buf, binary.LittleEndian, []byte{0x01})

		privateKey, err := ImportRSAPrivateKeyBlob(buf.Bytes())
		require.EqualError(t, err, "failed to read modulus: unexpected EOF")
		require.Nil(t, privateKey)
	})

	t.Run("failed to read prime1", func(t *testing.T) {
		buf := new(bytes.Buffer)
		_ = binary.Write(buf, binary.LittleEndian, blobHeader{
			Type:     privateKeyBlob,
			Version:  curBlobVersion,
			AiKeyAlg: cAlgRSASign,
		})
		_ = binary.Write(buf, binary.LittleEndian, rsaPubKey{
			Magic:  magicRSA2,
			BitLen: 2048,
			PubExp: 65537,
		})
		_ = binary.Write(buf, binary.LittleEndian, bytes.Repeat([]byte{0x01}, 256))
		_ = binary.Write(buf, binary.LittleEndian, []byte{0x02})

		privateKey, err := ImportRSAPrivateKeyBlob(buf.Bytes())
		require.EqualError(t, err, "failed to read prime1: unexpected EOF")
		require.Nil(t, privateKey)
	})

	t.Run("failed to read prime2", func(t *testing.T) {
		buf := new(bytes.Buffer)
		_ = binary.Write(buf, binary.LittleEndian, blobHeader{
			Type:     privateKeyBlob,
			Version:  curBlobVersion,
			AiKeyAlg: cAlgRSASign,
		})
		_ = binary.Write(buf, binary.LittleEndian, rsaPubKey{
			Magic:  magicRSA2,
			BitLen: 2048,
			PubExp: 65537,
		})
		_ = binary.Write(buf, binary.LittleEndian, bytes.Repeat([]byte{0x01}, 256))
		_ = binary.Write(buf, binary.LittleEndian, bytes.Repeat([]byte{0x02}, 128))
		_ = binary.Write(buf, binary.LittleEndian, []byte{0x03})

		privateKey, err := ImportRSAPrivateKeyBlob(buf.Bytes())
		require.EqualError(t, err, "failed to read prime2: unexpected EOF")
		require.Nil(t, privateKey)
	})

	t.Run("failed to read skipped fields", func(t *testing.T) {
		buf := new(bytes.Buffer)
		_ = binary.Write(buf, binary.LittleEndian, blobHeader{
			Type:     privateKeyBlob,
			Version:  curBlobVersion,
			AiKeyAlg: cAlgRSASign,
		})
		_ = binary.Write(buf, binary.LittleEndian, rsaPubKey{
			Magic:  magicRSA2,
			BitLen: 2048,
			PubExp: 65537,
		})
		_ = binary.Write(buf, binary.LittleEndian, bytes.Repeat([]byte{0x01}, 256))
		_ = binary.Write(buf, binary.LittleEndian, bytes.Repeat([]byte{0x02}, 128))
		_ = binary.Write(buf, binary.LittleEndian, bytes.Repeat([]byte{0x03}, 128))
		_ = binary.Write(buf, binary.LittleEndian, []byte{0x00})

		privateKey, err := ImportRSAPrivateKeyBlob(buf.Bytes())
		require.EqualError(t, err, "failed to read skipped fields: unexpected EOF")
		require.Nil(t, privateKey)
	})

	t.Run("failed to read private exponent", func(t *testing.T) {
		buf := new(bytes.Buffer)
		_ = binary.Write(buf, binary.LittleEndian, blobHeader{
			Type:     privateKeyBlob,
			Version:  curBlobVersion,
			AiKeyAlg: cAlgRSASign,
		})
		_ = binary.Write(buf, binary.LittleEndian, rsaPubKey{
			Magic:  magicRSA2,
			BitLen: 2048,
			PubExp: 65537,
		})
		_ = binary.Write(buf, binary.LittleEndian, bytes.Repeat([]byte{0x01}, 256))
		_ = binary.Write(buf, binary.LittleEndian, bytes.Repeat([]byte{0x02}, 128))
		_ = binary.Write(buf, binary.LittleEndian, bytes.Repeat([]byte{0x03}, 128))
		_ = binary.Write(buf, binary.LittleEndian, bytes.Repeat([]byte{0x00}, 128*3))
		_ = binary.Write(buf, binary.LittleEndian, []byte{0x04})

		privateKey, err := ImportRSAPrivateKeyBlob(buf.Bytes())
		require.EqualError(t, err, "failed to read private exponent: unexpected EOF")
		require.Nil(t, privateKey)
	})

	t.Run("invalid private key validation", func(t *testing.T) {
		buf := new(bytes.Buffer)
		_ = binary.Write(buf, binary.LittleEndian, blobHeader{
			Type:     privateKeyBlob,
			Version:  curBlobVersion,
			AiKeyAlg: cAlgRSASign,
		})
		_ = binary.Write(buf, binary.LittleEndian, rsaPubKey{
			Magic:  magicRSA2,
			BitLen: 2048,
			PubExp: 65537,
		})
		_ = binary.Write(buf, binary.LittleEndian, bytes.Repeat([]byte{0x01}, 256))
		_ = binary.Write(buf, binary.LittleEndian, bytes.Repeat([]byte{0x02}, 128))
		_ = binary.Write(buf, binary.LittleEndian, bytes.Repeat([]byte{0x02}, 128)) // same as prime1
		_ = binary.Write(buf, binary.LittleEndian, bytes.Repeat([]byte{0x00}, 128*3))
		_ = binary.Write(buf, binary.LittleEndian, bytes.Repeat([]byte{0x04}, 256))

		privateKey, err := ImportRSAPrivateKeyBlob(buf.Bytes())
		require.ErrorContains(t, err, "failed to validate private key")
		require.Nil(t, privateKey)
	})
}

func TestExportRSAPublicKeyBlob(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	t.Run("sign", func(t *testing.T) {
		blob, err := ExportRSAPublicKeyBlob(&key.PublicKey, RSAKeyUsageSIGN)
		require.NoError(t, err)

		spew.Dump(blob)
		require.Len(t, blob, 276)
	})

	t.Run("key exchange", func(t *testing.T) {
		blob, err := ExportRSAPublicKeyBlob(&key.PublicKey, RSAKeyUsageKEYX)
		require.NoError(t, err)

		spew.Dump(blob)
		require.Len(t, blob, 276)
	})

	t.Run("invalid key usage", func(t *testing.T) {
		blob, err := ExportRSAPublicKeyBlob(&key.PublicKey, 0)
		require.EqualError(t, err, "invalid rsa key usage")
		require.Nil(t, blob)
	})
}

func TestExportRSAPrivateKeyBlob(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	t.Run("sign", func(t *testing.T) {
		blob, err := ExportRSAPrivateKeyBlob(key, RSAKeyUsageSIGN)
		require.NoError(t, err)

		spew.Dump(blob)
		require.Len(t, blob, 1172)
	})

	t.Run("key exchange", func(t *testing.T) {
		blob, err := ExportRSAPrivateKeyBlob(key, RSAKeyUsageKEYX)
		require.NoError(t, err)

		spew.Dump(blob)
		require.Len(t, blob, 1172)
	})

	t.Run("invalid key usage", func(t *testing.T) {
		blob, err := ExportRSAPrivateKeyBlob(key, 0)
		require.EqualError(t, err, "invalid rsa key usage")
		require.Nil(t, blob)
	})
}
