package types

import (
	"errors"
	"strings"
)

// constant for use BOOL easily.
const (
	TRUE  = BOOL(1)
	FALSE = BOOL(0)
)

// BOOL is an int32 for structure alignment.
type BOOL int32

// ToBool is used to convert to go bool.
func (b BOOL) ToBool() bool {
	return b != 0
}

func (b BOOL) String() string {
	if b.ToBool() {
		return "true"
	}
	return "false"
}

// MarshalText is used to implement TextMarshaler interface.
func (b BOOL) MarshalText() ([]byte, error) {
	return []byte(b.String()), nil
}

// UnmarshalText is used to implement TextUnmarshaler interface.
func (b *BOOL) UnmarshalText(data []byte) error {
	switch strings.ToLower(string(data)) {
	case "true":
		*b = BOOL(1)
	case "false":
		*b = BOOL(0)
	default:
		return errors.New("invalid BOOL value")
	}
	return nil
}
