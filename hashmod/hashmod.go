package hashmod

import (
	"unicode/utf16"
)

// Hash is used to calculate the exe or dll name hash for options.
func Hash(module string) uint64 {
	hash := uint64(0xFFFFFFFF)
	s := utf16.Encode([]rune(module))
	for _, c := range s {
		if c >= 'a' && c <= 'z' {
			c -= 0x20
		}
		hash *= ror64(hash|1, 11)
		hash += uint64(c)
		hash ^= ror64(hash|1, 17)
	}
	return hash
}

func ror64(value, bits uint64) uint64 {
	return value>>bits | value<<(64-bits)
}
