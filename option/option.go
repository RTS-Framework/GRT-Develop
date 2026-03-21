package option

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
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
	OptOffsetExePinningHash      = 1
	OptOffsetShieldModuleHash    = 9
	OptOffsetShieldEntryPoint    = 17
	OptOffsetEnableSecurityMode  = 25
	OptOffsetDisableDetector     = 26
	OptOffsetDisableWatchdog     = 27
	OptOffsetDisableSysmon       = 28
	OptOffsetNotEraseInstruction = 29
	OptOffsetNotAdjustProtect    = 30
	OptOffsetTrackCurrentThread  = 31
)

const (
	paddingOff  = OptOffsetTrackCurrentThread + 1
	paddingSize = StubSize - paddingOff
)

// Options contains options about Gleam-RT.
type Options struct {
	// runtime will not initialize when the exe name is not expected.
	// if zero, runtime will skip this detection.
	ExePinningHash uint64 `toml:"exe_pinning_hash" json:"exe_pinning_hash"`

	// the module hash of the pre-injected shield in,
	// if 0x0000, runtime will deploy a shield from the built-in shield stub.
	// if 0x0001, the module is the main exe.
	// if others, the module is the target dll.
	ShieldModuleHash uint64 `toml:"shield_module_hash" json:"shield_module_hash"`

	// the RVA of the pre-injected shield in the module.
	ShieldEntryPoint uint64 `toml:"shield_entry_point" json:"shield_entry_point"`

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
	offset := bytes.Index(template, stub)
	if offset == -1 {
		return nil, errors.New("invalid runtime option stub")
	}
	// write options to stub
	if opts == nil {
		opts = new(Options)
	}
	binary.LittleEndian.PutUint64(stub[OptOffsetExePinningHash:], opts.ExePinningHash)
	binary.LittleEndian.PutUint64(stub[OptOffsetShieldModuleHash:], opts.ShieldModuleHash)
	binary.LittleEndian.PutUint64(stub[OptOffsetShieldEntryPoint:], opts.ShieldEntryPoint)
	stub[OptOffsetEnableSecurityMode] = boolToByte(opts.EnableSecurityMode)
	stub[OptOffsetDisableDetector] = boolToByte(opts.DisableDetector)
	stub[OptOffsetDisableWatchdog] = boolToByte(opts.DisableWatchdog)
	stub[OptOffsetDisableSysmon] = boolToByte(opts.DisableSysmon)
	stub[OptOffsetNotEraseInstruction] = boolToByte(opts.NotEraseInstruction)
	stub[OptOffsetNotAdjustProtect] = boolToByte(opts.NotAdjustProtect)
	stub[OptOffsetTrackCurrentThread] = boolToByte(opts.TrackCurrentThread)
	// append padding data
	pad := make([]byte, paddingSize)
	_, err := rand.Read(pad)
	if err != nil {
		return nil, errors.New("failed to generate padding data")
	}
	copy(stub[paddingOff:], pad)
	// copy template and set stub
	output := make([]byte, len(template))
	copy(output, template)
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
	stub := instance[offset:]
	opts := Options{
		ExePinningHash:      binary.LittleEndian.Uint64(stub[OptOffsetExePinningHash:]),
		ShieldModuleHash:    binary.LittleEndian.Uint64(stub[OptOffsetShieldModuleHash:]),
		ShieldEntryPoint:    binary.LittleEndian.Uint64(stub[OptOffsetShieldEntryPoint:]),
		EnableSecurityMode:  stub[OptOffsetEnableSecurityMode] != 0,
		DisableDetector:     stub[OptOffsetDisableDetector] != 0,
		DisableWatchdog:     stub[OptOffsetDisableWatchdog] != 0,
		DisableSysmon:       stub[OptOffsetDisableSysmon] != 0,
		NotEraseInstruction: stub[OptOffsetNotEraseInstruction] != 0,
		NotAdjustProtect:    stub[OptOffsetNotAdjustProtect] != 0,
		TrackCurrentThread:  stub[OptOffsetTrackCurrentThread] != 0,
	}
	return &opts, nil
}

func boolToByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}

// Flag is used to read options from command line.
func Flag(opts *Options) {
	flag.Uint64Var(
		&opts.ExePinningHash, "grt-mph", 0,
		"set the hash about exe pinning",
	)
	flag.Uint64Var(
		&opts.ShieldModuleHash, "grt-smh", 0,
		"set the module hash about pre-injected shield",
	)
	flag.Uint64Var(
		&opts.ShieldEntryPoint, "grt-sep", 0,
		"set the rva about the shield in module",
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
