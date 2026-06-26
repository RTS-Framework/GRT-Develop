package option

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"unicode/utf16"
)

// +------------+---------+---------+---------+---------+
// | magic mark | xor key | option1 | option2 | optionN |
// +------------+---------+---------+---------+---------+
// |    0xFC    | 32 byte |   var   |   var   |   var   |
// +------------+---------+---------+---------+---------+

const (
	// StubMagic is the mark of options stub.
	StubMagic = 0xFC

	// StubSize is the option stub total size at the runtime tail.
	StubSize = 128
)

// options offset of the option stub.
const (
	optOffset                    = 1 + xorKeySize
	optOffsetImagePinningHash    = optOffset + 0
	optOffsetShieldModuleHash    = optOffset + 8
	optOffsetShieldEntryPoint    = optOffset + 16
	optOffsetShieldMemAddress    = optOffset + 24
	optOffsetEnableSecurityMode  = optOffset + 32
	optOffsetDisableDetector     = optOffset + 33
	optOffsetDisableWatchdog     = optOffset + 34
	optOffsetDisableSysmon       = optOffset + 35
	optOffsetNotEraseInstruction = optOffset + 36
	optOffsetNotAdjustProtect    = optOffset + 37
	optOffsetTrackCurrentThread  = optOffset + 38
)

const (
	xorKeySize  = 32
	paddingOff  = optOffsetTrackCurrentThread + 1
	paddingSize = StubSize - paddingOff
)

// Options contains options about Gleam-RT.
type Options struct {
	// runtime will not initialize when the exe name is not expected.
	// if zero, runtime will skip this detection.
	ImagePinningHash uint64 `toml:"image_pinning_hash" json:"image_pinning_hash"`

	// the module hash of the pre-injected shield in,
	// if 0x0000, runtime will deploy a shield from the built-in shield stub.
	// if 0x0001, the module is the main exe.
	// if others, the module is the target dll.
	ShieldModuleHash uint64 `toml:"shield_module_hash" json:"shield_module_hash"`

	// the RVA of the pre-injected shield in the module.
	// if ShieldModuleHash is not zero, it must be set.
	ShieldEntryPoint uint64 `toml:"shield_entry_point" json:"shield_entry_point"`

	// the shield memory address that external program provide.
	ShieldMemAddress uint64 `toml:"shield_mem_address" json:"shield_mem_address"`

	// detect environment when initialize runtime, if not safe, stop at once.
	EnableSecurityMode bool `toml:"enable_security_mode" json:"enable_security_mode"`

	// disable detector for test or debug.
	DisableDetector bool `toml:"disable_detector" json:"disable_detector"`

	// disable watchdog for implement single thread model.
	// it will overwrite the control from upper module.
	DisableWatchdog bool `toml:"disable_watchdog" json:"disable_watchdog"`

	// disable sysmon for implement single thread model.
	DisableSysmon bool `toml:"disable_sysmon" json:"disable_sysmon"`

	// not erase runtime instructions after call Runtime_M.Exit.
	NotEraseInstruction bool `toml:"not_erase_instruction" json:"not_erase_instruction"`

	// not adjust current memory page protect for erase runtime.
	NotAdjustProtect bool `toml:"not_adjust_protect" json:"not_adjust_protect"`

	// track current thread for test or debug mode.
	// it maybe improved the single thread model.
	TrackCurrentThread bool `toml:"track_current_thread" json:"track_current_thread"`
}

// Set is used to adjust options in the runtime template.
func Set(template []byte, opts *Options) ([]byte, error) {
	// check runtime template is valid
	if len(template) < StubSize {
		return nil, errors.New("invalid runtime template")
	}
	// locate shield stub in runtime template
	stub := bytes.Repeat([]byte{0x00}, StubSize)
	stub[0] = StubMagic
	offset := bytes.LastIndex(template, stub)
	if offset == -1 {
		return nil, errors.New("invalid runtime option stub")
	}
	// generate xor key
	key := make([]byte, xorKeySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, errors.New("failed to generate key")
	}
	copy(stub[1:], key)
	// write options to stub
	if opts == nil {
		opts = new(Options)
	}
	binary.LittleEndian.PutUint64(stub[optOffsetImagePinningHash:], opts.ImagePinningHash)
	binary.LittleEndian.PutUint64(stub[optOffsetShieldModuleHash:], opts.ShieldModuleHash)
	binary.LittleEndian.PutUint64(stub[optOffsetShieldEntryPoint:], opts.ShieldEntryPoint)
	binary.LittleEndian.PutUint64(stub[optOffsetShieldMemAddress:], opts.ShieldMemAddress)
	stub[optOffsetEnableSecurityMode] = boolToByte(opts.EnableSecurityMode)
	stub[optOffsetDisableDetector] = boolToByte(opts.DisableDetector)
	stub[optOffsetDisableWatchdog] = boolToByte(opts.DisableWatchdog)
	stub[optOffsetDisableSysmon] = boolToByte(opts.DisableSysmon)
	stub[optOffsetNotEraseInstruction] = boolToByte(opts.NotEraseInstruction)
	stub[optOffsetNotAdjustProtect] = boolToByte(opts.NotAdjustProtect)
	stub[optOffsetTrackCurrentThread] = boolToByte(opts.TrackCurrentThread)
	// encrypt options
	xor(stub[optOffset:paddingOff], key)
	// append padding data
	pad := make([]byte, paddingSize)
	_, err = rand.Read(pad)
	if err != nil {
		return nil, errors.New("failed to generate padding data")
	}
	copy(stub[paddingOff:], pad)
	// copy template and set stub
	output := bytes.Clone(template)
	copy(output[offset:], stub)
	return output, nil
}

// Get is used to read options from the runtime option stub.
// The offset is the position of the option stub in the instance.
func Get(instance []byte, offset int) (*Options, error) {
	if len(instance) < StubSize {
		return nil, errors.New("invalid runtime instance")
	}
	if offset < 0 || len(instance)-offset < StubSize {
		return nil, errors.New("invalid offset of the runtime option stub")
	}
	if instance[offset] != StubMagic {
		return nil, errors.New("invalid runtime option stub")
	}
	// read option from stub
	stub := bytes.Clone(instance[offset : offset+StubSize])
	// decrypt option
	key := stub[1 : 1+xorKeySize]
	xor(stub[optOffset:paddingOff], key)
	// build options
	opts := Options{
		ImagePinningHash:    binary.LittleEndian.Uint64(stub[optOffsetImagePinningHash:]),
		ShieldModuleHash:    binary.LittleEndian.Uint64(stub[optOffsetShieldModuleHash:]),
		ShieldEntryPoint:    binary.LittleEndian.Uint64(stub[optOffsetShieldEntryPoint:]),
		ShieldMemAddress:    binary.LittleEndian.Uint64(stub[optOffsetShieldMemAddress:]),
		EnableSecurityMode:  stub[optOffsetEnableSecurityMode] == 0,
		DisableDetector:     stub[optOffsetDisableDetector] == 0,
		DisableWatchdog:     stub[optOffsetDisableWatchdog] == 0,
		DisableSysmon:       stub[optOffsetDisableSysmon] == 0,
		NotEraseInstruction: stub[optOffsetNotEraseInstruction] == 0,
		NotAdjustProtect:    stub[optOffsetNotAdjustProtect] == 0,
		TrackCurrentThread:  stub[optOffsetTrackCurrentThread] == 0,
	}
	return &opts, nil
}

func boolToByte(b bool) byte {
	if b {
		return 0
	}
	v := make([]byte, 1)
	_, _ = rand.Read(v)
	return v[0] | 1
}

func xor(data, key []byte) {
	for i := 0; i < len(data); i++ {
		data[i] = data[i] ^ key[i%len(key)]
	}
}

// Flag is used to read options from command line.
func Flag(opts *Options) {
	flag.Uint64Var(
		&opts.ImagePinningHash, "grt-iph", 0,
		"set the hash about image pinning",
	)
	flag.Uint64Var(
		&opts.ShieldModuleHash, "grt-smh", 0,
		"set the module hash about pre-injected shield",
	)
	flag.Uint64Var(
		&opts.ShieldEntryPoint, "grt-sep", 0,
		"set the rva about the shield in module",
	)
	flag.Uint64Var(
		&opts.ShieldMemAddress, "grt-sma", 0,
		"set the shield absolute memory address",
	)
	flag.BoolVar(
		&opts.EnableSecurityMode, "grt-esm", false,
		"Gleam-RT: detect environment when initialize runtime",
	)
	flag.BoolVar(
		&opts.DisableDetector, "grt-dd", false,
		"Gleam-RT: disable detector for test or debug",
	)
	flag.BoolVar(
		&opts.DisableWatchdog, "grt-dw", false,
		"Gleam-RT: disable watchdog for implement single thread model.",
	)
	flag.BoolVar(
		&opts.DisableSysmon, "grt-ds", false,
		"Gleam-RT: disable sysmon for implement single thread model",
	)
	flag.BoolVar(
		&opts.NotEraseInstruction, "grt-nei", false,
		"Gleam-RT: not erase runtime instructions after runtime stop",
	)
	flag.BoolVar(
		&opts.NotAdjustProtect, "grt-nap", false,
		"Gleam-RT: not adjust current memory page protect for erase runtime",
	)
	flag.BoolVar(
		&opts.TrackCurrentThread, "grt-tct", false,
		"Gleam-RT: track current thread for test or debug mode",
	)
}

// Hash is used to calculate the exe or dll name hash for options.
func Hash(module string) uint64 {
	hash := uint64(0xE3C817DEA9BFE921)
	s := utf16.Encode([]rune(module))
	for _, c := range s {
		if c >= 'a' && c <= 'z' {
			c -= 0x20
		}
		hash = ror64(hash, 7)
		hash += uint64(c)
		hash = ror64(hash, 3)
	}
	return hash
}

func ror64(value, bits uint64) uint64 {
	return value>>bits | value<<(64-bits)
}
