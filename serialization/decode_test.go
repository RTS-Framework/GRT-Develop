package serialization

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnmarshal(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		s1 := testStruct{
			unexported1: 1,

			Arg1: 123,
			Arg2: [2]uint32{456, 789},
			Arg3: nil,
			Arg4: "",
			Arg5: 0x19,
			Arg6: 0x1548,
			Arg7: nil,
			Arg8: "hello",
			Arg9: []byte{0x12, 0x34},

			Arg10: 0x12,
			Arg11: 0x1234,
			Arg12: -0x12345678,
			Arg13: -0x1234567812345678,
			Arg14: 0x12,
			Arg15: 0x1234,
			Arg16: 0x12345678,
			Arg17: 0x1234567812345678,
			Arg18: 0.1234,
			Arg19: 0.123459664,
			Arg20: true,

			unexported2: 2,

			Arg26: [2]uint16{0x1234, 0x5678},
			Arg37: []uint16{0x5678, 0x1234},

			Arg42: []bool{true, false},

			unexported3: 3,
		}
		data, err := Marshal(&s1)
		require.NoError(t, err)

		var s2 testStruct
		err = Unmarshal(data, &s2)
		require.NoError(t, err)

		s1.unexported1 = 0
		s1.unexported2 = 0
		s1.unexported3 = 0
		require.Equal(t, s1, s2)
	})

	t.Run("invalid data length", func(t *testing.T) {
		var s1 testStruct
		err := Unmarshal(nil, &s1)
		require.EqualError(t, err, "invalid data length")
	})

	t.Run("invalid magic number", func(t *testing.T) {
		data := make([]byte, 8)

		var s1 testStruct
		err := Unmarshal(data, &s1)
		require.EqualError(t, err, "invalid magic number")
	})

	t.Run("invalid value type", func(t *testing.T) {
		data := []byte{
			0xEE, 0xFF, 0xFF, 0xAC,
			0x00, 0x00, 0x00, 0x00,
		}

		var s1 int
		err := Unmarshal(data, s1)
		require.EqualError(t, err, "value must be a non-nil pointer")

		err = Unmarshal(data, &s1)
		require.EqualError(t, err, "value must be a pointer to struct")
	})

	t.Run("invalid descriptor", func(t *testing.T) {
		data := make([]byte, 4+3)
		binary.LittleEndian.PutUint32(data, magic)

		var s1 testStruct
		err := Unmarshal(data, &s1)
		require.EqualError(t, err, "unexpected EOF")
	})

	t.Run("structure field overflow", func(t *testing.T) {
		data := []byte{
			0xEE, 0xFF, 0xFF, 0xAC,
			0x02, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x01,
		}
		s := struct {
			Arg1 uint16
			Arg2 uint16
		}{}

		err := Unmarshal(data, &s)
		errStr := "structure field Arg2 is overflow"
		require.EqualError(t, err, errStr)
	})

	t.Run("mismatched field size", func(t *testing.T) {
		data := []byte{
			0xEE, 0xFF, 0xFF, 0xAC,
			0x03, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x01, 0x00, 0x00, 0x00,
		}
		s := struct {
			Arg1 uint16
		}{}

		err := Unmarshal(data, &s)
		errStr := "failed to decode value: invalid field size: 3"
		require.EqualError(t, err, errStr)
	})

	t.Run("invalid raw data size", func(t *testing.T) {
		data := []byte{
			0xEE, 0xFF, 0xFF, 0xAC,
			0x02, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		}
		s := struct {
			Arg1 uint16
		}{}

		err := Unmarshal(data, &s)
		errStr := "failed to decode value: EOF"
		require.EqualError(t, err, errStr)
	})

	t.Run("not supported field type", func(t *testing.T) {
		data := []byte{
			0xEE, 0xFF, 0xFF, 0xAC,
			0x02, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00,
		}
		s := struct {
			Arg1 struct {
				_ uint16
			}
		}{}

		err := Unmarshal(data, &s)
		errStr := "failed to decode value: type of struct is not support"
		require.EqualError(t, err, errStr)
	})

	t.Run("invalid string size", func(t *testing.T) {
		data := []byte{
			0xEE, 0xFF, 0xFF, 0xAC,
			0x04, 0x00, 0x00, 0x80,
			0x00, 0x00, 0x00, 0x00,
		}
		s := struct {
			Arg1 string
		}{}

		err := Unmarshal(data, &s)
		errStr := "failed to decode pointer: EOF"
		require.EqualError(t, err, errStr)
	})

	t.Run("invalid string data", func(t *testing.T) {
		data := []byte{
			0xEE, 0xFF, 0xFF, 0xAC,
			0x03, 0x00, 0x00, 0x80,
			0x00, 0x00, 0x00, 0x00,
			0x12, 0x12, 0x12,
		}
		s := struct {
			Arg1 string
		}{}

		err := Unmarshal(data, &s)
		errStr := "failed to decode pointer: invalid utf16 string"
		require.EqualError(t, err, errStr)
	})

	t.Run("invalid array length", func(t *testing.T) {
		data := []byte{
			0xEE, 0xFF, 0xFF, 0xAC,
			0x08, 0x00, 0x00, 0x80,
			0x00, 0x00, 0x00, 0x00,
			0x12, 0x12, 0x12,
		}
		s := struct {
			Arg1 [2]uint16
		}{}

		err := Unmarshal(data, &s)
		errStr := "failed to decode pointer: invalid array length"
		require.EqualError(t, err, errStr)
	})

	t.Run("invalid array element type", func(t *testing.T) {
		data := []byte{
			0xEE, 0xFF, 0xFF, 0xAC,
			0x03, 0x00, 0x00, 0x80,
			0x00, 0x00, 0x00, 0x00,
			0x12, 0x12, 0x12,
		}
		s := struct {
			Arg1 [2]uint16
		}{}

		err := Unmarshal(data, &s)
		errStr := "failed to decode pointer: invalid array element type: uint16"
		require.EqualError(t, err, errStr)
	})

	t.Run("invalid array data", func(t *testing.T) {
		data := []byte{
			0xEE, 0xFF, 0xFF, 0xAC,
			0x04, 0x00, 0x00, 0x80,
			0x00, 0x00, 0x00, 0x00,
			0x12, 0x12, 0x12,
		}
		s := struct {
			Arg1 [2]uint16
		}{}

		err := Unmarshal(data, &s)
		errStr := "failed to decode pointer: unexpected EOF"
		require.EqualError(t, err, errStr)
	})

	t.Run("invalid slice element type", func(t *testing.T) {
		data := []byte{
			0xEE, 0xFF, 0xFF, 0xAC,
			0x03, 0x00, 0x00, 0x80,
			0x00, 0x00, 0x00, 0x00,
			0x12, 0x12, 0x12,
		}
		s := struct {
			Arg1 []uint16
		}{}

		err := Unmarshal(data, &s)
		errStr := "failed to decode pointer: invalid slice element type: uint16"
		require.EqualError(t, err, errStr)
	})

	t.Run("invalid slice data", func(t *testing.T) {
		data := []byte{
			0xEE, 0xFF, 0xFF, 0xAC,
			0x04, 0x00, 0x00, 0x80,
			0x00, 0x00, 0x00, 0x00,
			0x12, 0x12, 0x12,
		}
		s := struct {
			Arg1 []uint16
		}{}

		err := Unmarshal(data, &s)
		errStr := "failed to decode pointer: unexpected EOF"
		require.EqualError(t, err, errStr)
	})

	t.Run("invalid pointer type", func(t *testing.T) {
		data := []byte{
			0xEE, 0xFF, 0xFF, 0xAC,
			0x02, 0x00, 0x00, 0x80,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00,
		}
		s := struct {
			Arg1 uint16
		}{}

		err := Unmarshal(data, &s)
		errStr := "failed to decode pointer: field type of uint16 is not support"
		require.EqualError(t, err, errStr)
	})
}
