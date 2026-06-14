package shield

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/For-ACGN/monkey"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

var (
	template []byte
	offset   int
)

func init() {
	offset = 256
	inst := bytes.Repeat([]byte{0xFF}, offset)
	stub := bytes.Repeat([]byte{0x00}, StubSize+stubSuffix)
	stub[0] = StubMagic
	template = append(inst, stub...)
}

func TestSet(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		shield := []byte("test shield instruction")
		decoy := []byte("test decoy instruction")

		output, err := Set(template, shield, decoy)
		require.NoError(t, err)

		s, d, err := Get(output, offset)
		require.NoError(t, err)
		require.Equal(t, shield, s)
		require.Equal(t, decoy, d)

		spew.Dump(output)
	})

	t.Run("empty shield and decoy", func(t *testing.T) {
		output, err := Set(template, nil, nil)
		require.NoError(t, err)

		s, d, err := Get(output, offset)
		require.NoError(t, err)
		require.Empty(t, s)
		require.Empty(t, d)

		spew.Dump(output)
	})

	t.Run("empty shield", func(t *testing.T) {
		decoy := []byte("test decoy instruction")

		output, err := Set(template, nil, decoy)
		require.NoError(t, err)

		s, d, err := Get(output, offset)
		require.NoError(t, err)
		require.Empty(t, s)
		require.Equal(t, decoy, d)
	})

	t.Run("empty decoy", func(t *testing.T) {
		shield := []byte("test shield instruction")

		output, err := Set(template, shield, nil)
		require.NoError(t, err)

		s, d, err := Get(output, offset)
		require.NoError(t, err)
		require.Equal(t, shield, s)
		require.Empty(t, d)
	})

	t.Run("invalid template", func(t *testing.T) {
		output, err := Set(nil, nil, nil)
		require.EqualError(t, err, "invalid runtime template")
		require.Nil(t, output)
	})

	t.Run("too large shield", func(t *testing.T) {
		shield := bytes.Repeat([]byte{0xFF}, StubSize)
		decoy := []byte("test decoy instruction")

		output, err := Set(template, shield, decoy)
		require.EqualError(t, err, "shield or decoy is too large")
		require.Nil(t, output)
	})

	t.Run("too large decoy", func(t *testing.T) {
		shield := []byte("test shield instruction")
		decoy := bytes.Repeat([]byte{0xFF}, StubSize)

		output, err := Set(template, shield, decoy)
		require.EqualError(t, err, "shield or decoy is too large")
		require.Nil(t, output)
	})

	t.Run("invalid stub", func(t *testing.T) {
		tpl := make([]byte, len(template))

		output, err := Set(tpl, nil, nil)
		require.EqualError(t, err, "invalid runtime shield stub")
		require.Nil(t, output)
	})

	t.Run("failed to generate xor key", func(t *testing.T) {
		patch := func(b []byte) (int, error) {
			return 0, errors.New("monkey error")
		}
		pg := monkey.Patch(rand.Read, patch)
		defer pg.Unpatch()

		shield := []byte("test shield instruction")
		decoy := []byte("test decoy instruction")

		output, err := Set(template, shield, decoy)
		require.EqualError(t, err, "failed to generate key")
		require.Nil(t, output)
	})

	t.Run("failed to generate padding data", func(t *testing.T) {
		patch := func(b []byte) (int, error) {
			if len(b) == xorKeySize {
				b[0] = 0xFE
				return len(b), nil
			}
			return 0, errors.New("monkey error")
		}
		pg := monkey.Patch(rand.Read, patch)
		defer pg.Unpatch()

		shield := []byte("test shield instruction")
		decoy := []byte("test decoy instruction")

		output, err := Set(template, shield, decoy)
		require.EqualError(t, err, "failed to generate padding data")
		require.Nil(t, output)
	})
}

func TestGet(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		shield := []byte("test shield instruction")
		decoy := []byte("test decoy instruction")

		output, err := Set(template, shield, decoy)
		require.NoError(t, err)

		s, d, err := Get(output, offset)
		require.NoError(t, err)
		require.Equal(t, shield, s)
		require.Equal(t, decoy, d)
	})

	t.Run("invalid instance", func(t *testing.T) {
		s, d, err := Get(nil, 0)
		require.EqualError(t, err, "invalid runtime instance")
		require.Nil(t, s)
		require.Nil(t, d)
	})

	t.Run("invalid offset", func(t *testing.T) {
		instance := make([]byte, StubSize)

		s, d, err := Get(instance, -1)
		require.EqualError(t, err, "invalid offset of the runtime shield stub")
		require.Nil(t, s)
		require.Nil(t, d)

		s, d, err = Get(instance, len(instance)+1)
		require.EqualError(t, err, "invalid offset of the runtime shield stub")
		require.Nil(t, s)
		require.Nil(t, d)
	})

	t.Run("invalid stub", func(t *testing.T) {
		instance := make([]byte, StubSize)
		instance[0] = 0x00 // wrong magic

		s, d, err := Get(instance, 0)
		require.EqualError(t, err, "invalid runtime shield stub")
		require.Nil(t, s)
		require.Nil(t, d)
	})

	t.Run("invalid shield size", func(t *testing.T) {
		shield := []byte("test shield instruction")
		decoy := []byte("test decoy instruction")

		output, err := Set(template, shield, decoy)
		require.NoError(t, err)

		// set shield size to be too large
		off := offset + 1 + xorKeySize
		output[off+0] = 0xFF
		output[off+1] = 0xFF

		s, d, err := Get(output, offset)
		require.EqualError(t, err, "invalid shield size in stub")
		require.Nil(t, s)
		require.Nil(t, d)
	})

	t.Run("invalid decoy size", func(t *testing.T) {
		shield := []byte("test shield instruction")
		decoy := []byte("test decoy instruction")

		output, err := Set(template, shield, decoy)
		require.NoError(t, err)

		// set decoy size to be too large
		off := offset + 1 + xorKeySize + 2 + len(shield)
		output[off+0] = 0xFF
		output[off+1] = 0xFF

		s, d, err := Get(output, offset)
		require.EqualError(t, err, "invalid decoy size in stub")
		require.Nil(t, s)
		require.Nil(t, d)
	})
}
