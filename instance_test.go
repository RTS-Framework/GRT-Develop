package develop

import (
	"bytes"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"

	"github.com/RTS-Framework/GRT-Develop/option"
	"github.com/RTS-Framework/GRT-Develop/ptrtable"
	"github.com/RTS-Framework/GRT-Develop/shield"
)

var (
	template []byte
	offset   int
)

func init() {
	offset = 256
	inst := bytes.Repeat([]byte{0xFF}, offset)
	template = append(template, inst...)
	// append shield stub
	stub := bytes.Repeat([]byte{0x00}, shield.StubSize)
	stub[0] = shield.StubMagic
	template = append(template, stub...)
	// append pointer stub
	stub = bytes.Repeat([]byte{0x00}, ptrtable.StubSize)
	stub[0] = ptrtable.StubMagic
	template = append(template, stub...)
	// append option stub
	stub = bytes.Repeat([]byte{0x00}, option.StubSize)
	stub[0] = option.StubMagic
	template = append(template, stub...)
}

func TestInstantiate(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		opts := Options{
			Shield: []byte("test shield"),
			Decoy:  []byte("test decoy"),
		}

		instance, err := Instantiate(template, &opts)
		require.NoError(t, err)

		spew.Dump(instance)
	})
}
