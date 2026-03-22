package serialization

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
	"unsafe"
)

// Unmarshal is used to unserialize binary data to structure.
func Unmarshal(data []byte, v any) error {
	value := reflect.ValueOf(v)
	if value.Kind() != reflect.Ptr || value.IsNil() {
		return errors.New("value must be a non-nil pointer")
	}
	value = value.Elem()
	if value.Kind() != reflect.Struct {
		return errors.New("value must be a pointer to struct")
	}
	if len(data) < 4 {
		return errors.New("invalid data length")
	}
	magic := binary.LittleEndian.Uint32(data)
	if magic != headerMagic {
		return errors.New("invalid magic number")
	}
	// parse descriptors and check the number of the structure fields
	var descriptors []uint32
	reader := bytes.NewReader(data[4:])
	for {
		buf := make([]byte, 4)
		_, err := io.ReadFull(reader, buf)
		if err != nil {
			return err
		}
		desc := binary.LittleEndian.Uint32(buf)
		if desc == itemEnd {
			break
		}
		descriptors = append(descriptors, desc)
	}
	// process the structure value
	var idx int
	num := value.NumField()
	for i := 0; i < num; i++ {
		if !value.Type().Field(i).IsExported() {
			continue
		}
		if idx >= len(descriptors) {
			return errors.New("invalid structure field")
		}
		field := value.Field(i)
		desc := descriptors[idx]
		flag := desc & maskFlag
		size := desc & maskLength
		switch flag {
		case flagValue:
			err := decodeValue(reader, field, size)
			if err != nil {
				return fmt.Errorf("failed to decode value: %s", err)
			}
		case flagPointer:
			err := decodePointer(reader, field, size)
			if err != nil {
				return fmt.Errorf("failed to decode pointer: %s", err)
			}
		}
		idx++
	}
	return nil
}

//gocyclo:ignore
func decodeValue(reader *bytes.Reader, value reflect.Value, size uint32) error {
	typ := value.Type()
	if uint32(typ.Size()) != size { // #nosec G115
		return fmt.Errorf("invalid size: %d", size)
	}
	buf := make([]byte, size)
	_, err := io.ReadFull(reader, buf)
	if err != nil {
		return err
	}
	switch typ.Kind() {
	case reflect.Int8:
		value.SetInt(int64(buf[0]))
	case reflect.Int16:
		val := binary.LittleEndian.Uint16(buf)
		value.SetInt(int64(val))
	case reflect.Int32:
		val := binary.LittleEndian.Uint32(buf)
		value.SetInt(int64(val))
	case reflect.Int64:
		val := binary.LittleEndian.Uint64(buf)
		value.SetInt(int64(val)) // #nosec G115
	case reflect.Uint8:
		value.SetUint(uint64(buf[0]))
	case reflect.Uint16:
		val := binary.LittleEndian.Uint16(buf)
		value.SetUint(uint64(val))
	case reflect.Uint32:
		val := binary.LittleEndian.Uint32(buf)
		value.SetUint(uint64(val))
	case reflect.Uint64:
		val := binary.LittleEndian.Uint64(buf)
		value.SetUint(val)
	case reflect.Float32:
		val := binary.LittleEndian.Uint32(buf)
		n := *(*float32)(unsafe.Pointer(&val)) // #nosec
		value.SetFloat(float64(n))
	case reflect.Float64:
		val := binary.LittleEndian.Uint64(buf)
		n := *(*float64)(unsafe.Pointer(&val)) // #nosec
		value.SetFloat(n)
	case reflect.Bool:
		value.SetBool(buf[0] == 1)
	default:
		return fmt.Errorf("type of %s is not support", value.Kind())
	}
	return nil
}

func decodePointer(reader *bytes.Reader, field reflect.Value, size uint32) error {
	if size == 0 {
		return nil
	}
	var (
		buf []byte
		err error
	)
	switch field.Type().Kind() {
	case reflect.String:
		buf = make([]byte, size)
		_, err = io.ReadFull(reader, buf)
		if err != nil {
			return err
		}
		s, err := utf16ToString(buf)
		if err != nil {
			return err
		}
		field.SetString(s)
	case reflect.Array:
		t := field.Type().Elem()
		s := uint32(t.Size()) // #nosec G115
		if size%s != 0 {
			return fmt.Errorf("invalid array element type: %s", t.Name())
		}
		l := int(size / s)
		array := reflect.New(reflect.ArrayOf(l, t)).Elem()
		for i := 0; i < l; i++ {
			elem := reflect.New(t).Elem()
			err = decodeValue(reader, elem, s)
			if err != nil {
				return err
			}
			array.Index(i).Set(elem)
		}
		field.Set(array)
	case reflect.Slice:
		t := field.Type().Elem()
		s := uint32(t.Size()) // #nosec G115
		if size%s != 0 {
			return fmt.Errorf("invalid slice element type: %s", t.Name())
		}
		l := int(size / s)
		slice := reflect.MakeSlice(reflect.SliceOf(t), l, l)
		for i := 0; i < l; i++ {
			elem := reflect.New(t).Elem()
			err = decodeValue(reader, elem, s)
			if err != nil {
				return err
			}
			slice.Index(i).Set(elem)
		}
		field.Set(slice)
	default:
		return fmt.Errorf("field type of %s is not support", field.Kind())
	}
	return nil
}
