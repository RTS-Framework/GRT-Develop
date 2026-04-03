package argument

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/For-ACGN/monkey"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func TestEncode(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		arg0 := &Arg{
			ID:   0,
			Data: []byte{0x12, 0x34, 0x56, 0x78},
		}
		arg1 := &Arg{
			ID:   1,
			Data: bytes.Repeat([]byte("hello runtime"), 10),
		}
		arg2 := &Arg{
			ID:   2,
			Data: make([]byte, 0),
		}
		stub, err := Encode(arg0, arg1, arg2)
		require.NoError(t, err)

		header := offsetFirstArg
		argSize := 3 * (4 + 4)
		argLen := len(arg0.Data) + len(arg1.Data)
		expected := header + argSize + argLen
		require.Len(t, stub, expected)

		spew.Dump(stub)
	})

	t.Run("too many arguments", func(t *testing.T) {
		args := make([]*Arg, MaxNumArguments+1)
		stub, err := Encode(args...)
		require.EqualError(t, err, "too many arguments")
		require.Nil(t, stub)
	})

	t.Run("nil argument", func(t *testing.T) {
		stub, err := Encode(nil)
		require.EqualError(t, err, "appear nil argument")
		require.Nil(t, stub)
	})

	t.Run("id already exists", func(t *testing.T) {
		arg0 := &Arg{
			ID:   0,
			Data: []byte{0x12, 0x34, 0x56, 0x78},
		}
		arg1 := &Arg{
			ID:   0,
			Data: bytes.Repeat([]byte("hello runtime"), 10),
		}
		stub, err := Encode(arg0, arg1)
		require.EqualError(t, err, "argument id 0 already exists")
		require.Nil(t, stub)
	})

	t.Run("failed to generate crypto key", func(t *testing.T) {
		patch := func(b []byte) (int, error) {
			return 0, errors.New("monkey error")
		}
		pg := monkey.Patch(rand.Read, patch)
		defer pg.Unpatch()

		arg0 := &Arg{
			ID:   0,
			Data: []byte{0x12, 0x34, 0x56, 0x78},
		}
		stub, err := Encode(arg0)
		require.EqualError(t, err, "failed to generate crypto key")
		require.Nil(t, stub)
	})
}

func TestDecode(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		arg0 := &Arg{
			ID:   0,
			Data: []byte{0x12, 0x34, 0x56, 0x78},
		}
		arg1 := &Arg{
			ID:   1,
			Data: bytes.Repeat([]byte("hello runtime"), 10),
		}
		arg2 := &Arg{
			ID:   2,
			Data: make([]byte, 0),
		}
		args := []*Arg{arg0, arg1, arg2}
		stub, err := Encode(args...)
		require.NoError(t, err)

		output, err := Decode(stub)
		require.NoError(t, err)
		require.Equal(t, args, output)
	})

	t.Run("no argument", func(t *testing.T) {
		stub, err := Encode()
		require.NoError(t, err)

		output, err := Decode(stub)
		require.NoError(t, err)
		require.Empty(t, output)
	})

	t.Run("invalid stub", func(t *testing.T) {
		stub, err := Decode(nil)
		require.EqualError(t, err, "invalid argument stub")
		require.Nil(t, stub)
	})

	t.Run("invalid checksum", func(t *testing.T) {
		arg0 := &Arg{
			ID:   0,
			Data: []byte{0x12, 0x34, 0x56, 0x78},
		}
		arg1 := &Arg{
			ID:   1,
			Data: bytes.Repeat([]byte("hello runtime"), 10),
		}
		arg2 := &Arg{
			ID:   2,
			Data: make([]byte, 0),
		}
		stub, err := Encode(arg0, arg1, arg2)
		require.NoError(t, err)

		// destruct checksum
		copy(stub[offsetChecksum:], []byte{0x00, 0x00, 0x00, 0x00})

		output, err := Decode(stub)
		require.EqualError(t, err, "invalid argument stub checksum")
		require.Nil(t, output)
	})

	t.Run("invalid argument total size", func(t *testing.T) {
		arg := &Arg{
			ID:   0,
			Data: []byte{0x12, 0x34, 0x56, 0x78},
		}
		stub, err := Encode(arg)
		require.NoError(t, err)

		binary.LittleEndian.PutUint32(stub[offsetNumArgs:], 0)
		binary.LittleEndian.PutUint32(stub[offsetArgsSize:], 1234)

		checksum := calculateChecksum(stub[:offsetChecksum])
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, checksum)
		copy(stub[offsetChecksum:], buf)

		output, err := Decode(stub)
		require.EqualError(t, err, "invalid argument total size")
		require.Nil(t, output)
	})

	t.Run("invalid num argument", func(t *testing.T) {
		arg := &Arg{
			ID:   0,
			Data: []byte{0x12, 0x34, 0x56, 0x78},
		}
		stub, err := Encode(arg)
		require.NoError(t, err)

		binary.LittleEndian.PutUint32(stub[offsetNumArgs:], 0xFFFFFFFF)

		checksum := calculateChecksum(stub[:offsetChecksum])
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, checksum)
		copy(stub[offsetChecksum:], buf)

		output, err := Decode(stub)
		require.EqualError(t, err, "invalid num argument")
		require.Nil(t, output)
	})

	t.Run("invalid argument data", func(t *testing.T) {
		arg := &Arg{
			ID:   0,
			Data: []byte{0x12, 0x34, 0x56, 0x78},
		}
		stub, err := Encode(arg)
		require.NoError(t, err)

		// corrupt the argument size to be too large
		decryptStub(stub)
		stub = stub[:len(stub)-5]
		encryptStub(stub)

		output, err := Decode(stub)
		require.EqualError(t, err, "invalid argument data")
		require.Nil(t, output)
	})

	t.Run("invalid argument size", func(t *testing.T) {
		arg := &Arg{
			ID:   0,
			Data: []byte{0x12, 0x34, 0x56, 0x78},
		}
		stub, err := Encode(arg)
		require.NoError(t, err)

		// corrupt the argument size to be too large
		decryptStub(stub)
		binary.LittleEndian.PutUint32(stub[offsetFirstArg+4:], 0xFFFFFFFF)
		encryptStub(stub)

		output, err := Decode(stub)
		require.EqualError(t, err, "invalid argument size")
		require.Nil(t, output)

		// corrupt the argument size to be larger than stub
		decryptStub(stub)
		binary.LittleEndian.PutUint32(stub[offsetFirstArg+4:], uint32(len(arg.Data)+1))
		encryptStub(stub)

		output, err = Decode(stub)
		require.EqualError(t, err, "invalid argument size")
		require.Nil(t, output)
	})
}

func TestCompressRatio(t *testing.T) {
	arg := &Arg{
		ID:   0,
		Data: bytes.Repeat([]byte{0x00}, 256*1024),
	}

	for i := 0; i < 100; i++ {
		stub, err := Encode(arg)
		require.NoError(t, err)

		buf := bytes.NewBuffer(make([]byte, 0, 256*1024))
		w, err := flate.NewWriter(buf, flate.BestCompression)
		require.NoError(t, err)
		_, err = w.Write(stub)
		require.NoError(t, err)
		err = w.Close()
		require.NoError(t, err)

		expected := len(stub) * 98 / 100
		require.Greaterf(t, buf.Len(), expected, "bad compress ratio at %d\n", i)
	}
}
