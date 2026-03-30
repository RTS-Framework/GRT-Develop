package serialization

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"reflect"
)

// Marshal is used to serialize structure to binary data.
func Marshal(v any) ([]byte, error) {
	value := reflect.ValueOf(v)
	if value.Kind() == reflect.Ptr {
		if value.IsNil() {
			return nil, errors.New("value is a nil pointer")
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return nil, errors.New("value must be a struct or pointer to struct")
	}
	// generate descriptors and data
	var (
		descriptors []uint32
		dataBlock   []byte
	)
	num := value.NumField()
	for i := 0; i < num; i++ {
		if !value.Type().Field(i).IsExported() {
			continue
		}
		desc, data, err := encodeField(value.Field(i))
		if err != nil {
			return nil, err
		}
		descriptors = append(descriptors, desc)
		dataBlock = append(dataBlock, data...)
	}
	descriptors = append(descriptors, itemEnd)
	// write magic number
	var buffer []byte
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, magic)
	buffer = append(buffer, buf...)
	// write descriptors
	for _, desc := range descriptors {
		binary.LittleEndian.PutUint32(buf, desc)
		buffer = append(buffer, buf...)
	}
	// write raw data
	buffer = append(buffer, dataBlock...)
	return buffer, nil
}

//gocyclo:ignore
func encodeField(field reflect.Value) (uint32, []byte, error) {
	var (
		desc uint32
		data []byte
		err  error
	)
	switch field.Type().Kind() {
	case reflect.Int8:
		desc = typeValue | 1
		data = make([]byte, 1)
		data[0] = uint8(field.Int()) // #nosec G115
	case reflect.Int16:
		desc = typeValue | 2
		data = make([]byte, 2)
		binary.LittleEndian.PutUint16(data, uint16(field.Int())) // #nosec G115
	case reflect.Int32:
		desc = typeValue | 4
		data = make([]byte, 4)
		binary.LittleEndian.PutUint32(data, uint32(field.Int())) // #nosec G115
	case reflect.Int64:
		desc = typeValue | 8
		data = make([]byte, 8)
		binary.LittleEndian.PutUint64(data, uint64(field.Int())) // #nosec G115
	case reflect.Uint8:
		desc = typeValue | 1
		data = make([]byte, 1)
		data[0] = uint8(field.Uint()) // #nosec G115
	case reflect.Uint16:
		desc = typeValue | 2
		data = make([]byte, 2)
		binary.LittleEndian.PutUint16(data, uint16(field.Uint())) // #nosec G115
	case reflect.Uint32:
		desc = typeValue | 4
		data = make([]byte, 4)
		binary.LittleEndian.PutUint32(data, uint32(field.Uint())) // #nosec G115
	case reflect.Uint64:
		desc = typeValue | 8
		data = make([]byte, 8)
		binary.LittleEndian.PutUint64(data, field.Uint())
	case reflect.Float32:
		desc = typeValue | 4
		data = make([]byte, 4)
		f := float32(field.Float())
		n := math.Float32bits(f)
		binary.LittleEndian.PutUint32(data, n)
	case reflect.Float64:
		desc = typeValue | 8
		data = make([]byte, 8)
		f := field.Float()
		n := math.Float64bits(f)
		binary.LittleEndian.PutUint64(data, n)
	case reflect.Bool:
		desc = typeValue | 1
		data = make([]byte, 1)
		if field.Bool() {
			data[0] = 1
		}
	case reflect.String:
		data = stringToUTF16(field.String())
		desc = typePointer | uint32(len(data)) // #nosec G115
	case reflect.Array:
		data, err = encodeArray(field)
		if err != nil {
			return 0, nil, err
		}
		desc = typePointer | uint32(len(data)) // #nosec G115
	case reflect.Slice:
		data, err = encodeSlice(field)
		if err != nil {
			return 0, nil, err
		}
		desc = typePointer | uint32(len(data)) // #nosec G115
	default:
		return 0, nil, fmt.Errorf("field type of %s is not support", field.Kind())
	}
	return desc, data, nil
}

func encodeArray(array reflect.Value) ([]byte, error) {
	output := make([]byte, 0, array.Type().Size())
	n := array.Len()
	for i := 0; i < n; i++ {
		v, err := encodeElement(array.Index(i))
		if err != nil {
			return nil, err
		}
		output = append(output, v...)
	}
	return output, nil
}

func encodeSlice(slice reflect.Value) ([]byte, error) {
	n := slice.Len()
	t := slice.Type().Elem()
	output := make([]byte, 0, n*int(t.Size())) // #nosec G115
	for i := 0; i < n; i++ {
		v, err := encodeElement(slice.Index(i))
		if err != nil {
			return nil, err
		}
		output = append(output, v...)
	}
	return output, nil
}

func encodeElement(elem reflect.Value) ([]byte, error) {
	var data []byte
	switch elem.Type().Kind() {
	case reflect.Int8:
		data = make([]byte, 1)
		data[0] = uint8(elem.Int()) // #nosec G115
	case reflect.Int16:
		data = make([]byte, 2)
		binary.LittleEndian.PutUint16(data, uint16(elem.Int())) // #nosec G115
	case reflect.Int32:
		data = make([]byte, 4)
		binary.LittleEndian.PutUint32(data, uint32(elem.Int())) // #nosec G115
	case reflect.Int64:
		data = make([]byte, 8)
		binary.LittleEndian.PutUint64(data, uint64(elem.Int())) // #nosec G115
	case reflect.Uint8:
		data = make([]byte, 1)
		data[0] = uint8(elem.Uint()) // #nosec G115
	case reflect.Uint16:
		data = make([]byte, 2)
		binary.LittleEndian.PutUint16(data, uint16(elem.Uint())) // #nosec G115
	case reflect.Uint32:
		data = make([]byte, 4)
		binary.LittleEndian.PutUint32(data, uint32(elem.Uint())) // #nosec G115
	case reflect.Uint64:
		data = make([]byte, 8)
		binary.LittleEndian.PutUint64(data, elem.Uint())
	case reflect.Float32:
		data = make([]byte, 4)
		f := float32(elem.Float())
		n := math.Float32bits(f)
		binary.LittleEndian.PutUint32(data, n)
	case reflect.Float64:
		data = make([]byte, 8)
		f := elem.Float()
		n := math.Float64bits(f)
		binary.LittleEndian.PutUint64(data, n)
	case reflect.Bool:
		data = make([]byte, 1)
		if elem.Bool() {
			data[0] = 1
		}
	default:
		return nil, fmt.Errorf("element type of %s is not support", elem.Kind())
	}
	return data, nil
}
