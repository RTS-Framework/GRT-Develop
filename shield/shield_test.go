package shield

import (
	"bytes"
	"testing"

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
	stub := bytes.Repeat([]byte{0x00}, StubSize)
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
		tpl := make([]byte, StubSize+offset)

		output, err := Set(tpl, nil, nil)
		require.EqualError(t, err, "invalid runtime shield stub")
		require.Nil(t, output)
	})
}
