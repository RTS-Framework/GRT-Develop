package option

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

var template []byte

func init() {
	inst := bytes.Repeat([]byte{0xFF}, 256)
	stub := bytes.Repeat([]byte{0x00}, StubSize)
	stub[0] = StubMagic
	template = append(inst, stub...)
}

func TestSet(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		opts := &Options{
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
		o, err := Get(output, 256)
		require.NoError(t, err)
		require.Equal(t, opts, o)

		output, err = Set(template, nil)
		require.NoError(t, err)
		o, err = Get(output, 256)
		require.NoError(t, err)
		opts = &Options{
			EnableSecurityMode:  false,
			DisableDetector:     false,
			DisableWatchdog:     false,
			DisableSysmon:       false,
			NotEraseInstruction: false,
			NotAdjustProtect:    false,
			TrackCurrentThread:  false,
		}
		require.Equal(t, opts, o)
	})

	t.Run("invalid runtime template", func(t *testing.T) {
		output, err := Set(nil, nil)
		require.EqualError(t, err, "invalid runtime template")
		require.Nil(t, output)
	})

	t.Run("invalid runtime option stub", func(t *testing.T) {
		tpl := make([]byte, StubSize+256)

		output, err := Set(tpl, nil)
		require.EqualError(t, err, "invalid runtime option stub")
		require.Nil(t, output)
	})
}

func TestGet(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		opts := &Options{
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

		o, err := Get(output, 256)
		require.NoError(t, err)
		require.Equal(t, opts, o)
	})

	t.Run("invalid instance", func(t *testing.T) {
		opts, err := Get(nil, 0)
		require.EqualError(t, err, "invalid runtime instance")
		require.Nil(t, opts)
	})

	t.Run("invalid offset", func(t *testing.T) {
		tpl := make([]byte, StubSize+256)

		opts, err := Get(tpl, len(tpl))
		require.EqualError(t, err, "invalid offset of the runtime option stub")
		require.Nil(t, opts)
	})

	t.Run("invalid option stub", func(t *testing.T) {
		tpl := make([]byte, StubSize+256)

		opts, err := Get(tpl, len(tpl)-StubSize)
		require.EqualError(t, err, "invalid runtime option stub")
		require.Nil(t, opts)
	})
}

func TestFlag(t *testing.T) {
	opts := Options{
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
