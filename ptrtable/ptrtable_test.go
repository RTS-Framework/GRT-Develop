package ptrtable

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
	stub := bytes.Repeat([]byte{0x00}, StubSize)
	stub[0] = StubMagic
	template = append(inst, stub...)
}

func TestSet(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		output, err := Set(template)
		require.NoError(t, err)

		spew.Dump(output)
	})

	t.Run("invalid template", func(t *testing.T) {
		output, err := Set(nil)
		require.EqualError(t, err, "invalid runtime template")
		require.Nil(t, output)
	})

	t.Run("invalid stub", func(t *testing.T) {
		tpl := make([]byte, StubSize+offset)

		output, err := Set(tpl)
		require.EqualError(t, err, "invalid runtime pointer stub")
		require.Nil(t, output)
	})

	t.Run("failed to fill random data", func(t *testing.T) {
		patch := func(b []byte) (int, error) {
			return 0, errors.New("monkey error")
		}
		pg := monkey.Patch(rand.Read, patch)
		defer pg.Unpatch()

		output, err := Set(template)
		require.EqualError(t, err, "failed to fill random data")
		require.Nil(t, output)
	})
}
