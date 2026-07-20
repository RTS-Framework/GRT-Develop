package instance

import (
	"bytes"
	"testing"
	
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
	
	"github.com/RTS-Framework/GRT-Develop/argument"
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
			ImagePinningName: "test.exe",
			ShieldModuleName: MainModule,
			ShieldEntryPoint: 0x4000,
			ShieldMemAddress: 0,
			
			Shield: []byte("test shield"),
			Decoy:  []byte("test decoy"),
			
			Arguments: []*argument.Arg{
				{ID: 1, Data: []byte("test1")},
				{ID: 2, Data: []byte("test2")},
			},
		}
		
		instance, err := Instantiate(template, &opts)
		require.NoError(t, err)
		
		spew.Dump(instance)
	})
	
	t.Run("default options", func(t *testing.T) {
		instance, err := Instantiate(template, nil)
		require.NoError(t, err)
		
		spew.Dump(instance)
	})
	
	t.Run("invalid template", func(t *testing.T) {
		instance, err := Instantiate(nil, nil)
		require.EqualError(t, err, "invalid runtime template")
		require.Nil(t, instance)
	})
	
	t.Run("failed to set shield stub", func(t *testing.T) {
		opts := Options{
			Shield: []byte("test shield"),
			Decoy:  []byte("test decoy"),
		}
		
		tpl := bytes.Clone(template)
		tpl = bytes.ReplaceAll(tpl, []byte{shield.StubMagic}, []byte{0x00})
		
		instance, err := Instantiate(tpl, &opts)
		require.EqualError(t, err, "invalid runtime shield stub")
		require.Nil(t, instance)
	})
	
	t.Run("failed to set pointer stub", func(t *testing.T) {
		tpl := bytes.Clone(template)
		tpl = bytes.ReplaceAll(tpl, []byte{ptrtable.StubMagic}, []byte{0x00})
		
		instance, err := Instantiate(tpl, nil)
		require.EqualError(t, err, "invalid runtime pointer stub")
		require.Nil(t, instance)
	})
	
	t.Run("failed to set option stub", func(t *testing.T) {
		tpl := bytes.Clone(template)
		tpl = bytes.ReplaceAll(tpl, []byte{option.StubMagic}, []byte{0x00})
		
		instance, err := Instantiate(tpl, nil)
		require.EqualError(t, err, "invalid runtime option stub")
		require.Nil(t, instance)
	})
	
	t.Run("invalid arguments", func(t *testing.T) {
		opts := Options{
			Arguments: []*argument.Arg{
				{ID: 1, Data: []byte("test1")},
				{ID: 1, Data: []byte("test2")},
			},
		}
		
		instance, err := Instantiate(template, &opts)
		require.EqualError(t, err, "argument id 1 already exists")
		require.Nil(t, instance)
	})
}
