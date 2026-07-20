package hashmod

import (
	"testing"
)

func TestHash(t *testing.T) {
	for _, mod := range []string{
		"test.exe",
		"main.exe",
		"test_main.exe",
		"kernel32.dll",
		"ntdll.dll",
	} {
		h := Hash(mod)
		t.Logf("%-16s 0x%X\n", mod+":", h)
	}
}
