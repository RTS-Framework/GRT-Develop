package option

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
		opts := &Options{
			ImagePinningHash:    0x1234,
			ShieldModuleHash:    0x5678,
			ShieldEntryPoint:    0x9012,
			ShieldMemAddress:    0,
			EnableSecurityMode:  true,
			DisableDetector:     true,
			DisableWatchdog:     true,
			DisableSysmon:       true,
			NotEraseInstruction: true,
			NotAdjustProtect:    true,
			TrackCurrentThread:  true,
		}
		output, err := Set(template, opts)
		require.NoError(t, err)
		o, err := Get(output, offset)
		require.NoError(t, err)
		require.Equal(t, opts, o)

		output, err = Set(template, nil)
		require.NoError(t, err)
		o, err = Get(output, offset)
		require.NoError(t, err)
		opts = &Options{
			ImagePinningHash:    0,
			ShieldModuleHash:    0,
			ShieldEntryPoint:    0,
			ShieldMemAddress:    0,
			EnableSecurityMode:  false,
			DisableDetector:     false,
			DisableWatchdog:     false,
			DisableSysmon:       false,
			NotEraseInstruction: false,
			NotAdjustProtect:    false,
			TrackCurrentThread:  false,
		}
		require.Equal(t, opts, o)

		spew.Dump(output)
	})

	t.Run("invalid template", func(t *testing.T) {
		output, err := Set(nil, nil)
		require.EqualError(t, err, "invalid runtime template")
		require.Nil(t, output)
	})

	t.Run("invalid stub", func(t *testing.T) {
		tpl := make([]byte, StubSize+offset)

		output, err := Set(tpl, nil)
		require.EqualError(t, err, "invalid runtime option stub")
		require.Nil(t, output)
	})

	t.Run("failed to generate xor key", func(t *testing.T) {
		patch := func(b []byte) (int, error) {
			return 0, errors.New("monkey error")
		}
		pg := monkey.Patch(rand.Read, patch)
		defer pg.Unpatch()

		output, err := Set(template, nil)
		require.EqualError(t, err, "failed to generate key")
		require.Nil(t, output)
	})

	t.Run("option conflict", func(t *testing.T) {
		opts := &Options{
			ShieldModuleHash: 0x5678,
			ShieldEntryPoint: 0,
		}
		output, err := Set(template, opts)
		errStr := "shield entry point cannot be zero"
		require.EqualError(t, err, errStr)
		require.Nil(t, output)

		opts = &Options{
			ShieldModuleHash: 0x5678,
			ShieldEntryPoint: 0x1234,
			ShieldMemAddress: 0x7FFA,
		}
		output, err = Set(template, opts)
		errStr = "shield module hash and address cannot be set at the same time"
		require.EqualError(t, err, errStr)
		require.Nil(t, output)

		opts = &Options{
			ShieldModuleHash: 0,
			ShieldEntryPoint: 0x1234,
		}
		output, err = Set(template, opts)
		errStr = "shield entry point must be with module hash"
		require.EqualError(t, err, errStr)
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

		output, err := Set(template, nil)
		require.EqualError(t, err, "failed to generate padding data")
		require.Nil(t, output)
	})
}

func TestGet(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		opts := &Options{
			ImagePinningHash:    0x1234,
			ShieldModuleHash:    0,
			ShieldEntryPoint:    0,
			ShieldMemAddress:    0x7FFA,
			EnableSecurityMode:  true,
			DisableDetector:     true,
			DisableWatchdog:     true,
			DisableSysmon:       true,
			NotEraseInstruction: true,
			NotAdjustProtect:    true,
			TrackCurrentThread:  true,
		}
		output, err := Set(template, opts)
		require.NoError(t, err)

		o, err := Get(output, offset)
		require.NoError(t, err)
		require.Equal(t, opts, o)
	})

	t.Run("invalid instance", func(t *testing.T) {
		opts, err := Get(nil, 0)
		require.EqualError(t, err, "invalid runtime instance")
		require.Nil(t, opts)
	})

	t.Run("invalid offset", func(t *testing.T) {
		tpl := make([]byte, StubSize+offset)

		opts, err := Get(tpl, len(tpl))
		require.EqualError(t, err, "invalid offset of the runtime option stub")
		require.Nil(t, opts)
	})

	t.Run("invalid stub", func(t *testing.T) {
		tpl := make([]byte, StubSize+offset)

		opts, err := Get(tpl, len(tpl)-StubSize)
		require.EqualError(t, err, "invalid runtime option stub")
		require.Nil(t, opts)
	})
}

func TestFlag(t *testing.T) {
	opts := Options{
		ImagePinningHash:    0x1234,
		ShieldModuleHash:    0x5678,
		ShieldEntryPoint:    0x9012,
		ShieldMemAddress:    0x7FFA,
		EnableSecurityMode:  true,
		DisableDetector:     true,
		DisableWatchdog:     true,
		DisableSysmon:       true,
		NotEraseInstruction: true,
		NotAdjustProtect:    true,
		TrackCurrentThread:  true,
	}
	Flag(&opts)

	expected := Options{}
	require.Equal(t, expected, opts)
}
