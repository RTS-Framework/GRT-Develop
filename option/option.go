package option

import (
	"bytes"
	"errors"
	"flag"
)

// +------------+---------+---------+-----------+
// | magic mark | option1 | option2 | option... |
// +------------+---------+---------+-----------+
// |    0xFC    |   var   |   var   |    var    |
// +------------+---------+---------+-----------+

const (
	// StubMagic is the mark of options stub.
	StubMagic = 0xFC

	// StubSize is the option stub total size at the runtime tail.
	StubSize = 64
)

// options offset of the option stub.
const (
	OptOffsetEnableSecurityMode = iota + 1
	OptOffsetDisableDetector
	OptOffsetDisableWatchdog
	OptOffsetDisableSysmon
	OptOffsetNotEraseInstruction
	OptOffsetNotAdjustProtect
	OptOffsetTrackCurrentThread
)

// Options contains options about Gleam-RT.
type Options struct {
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
	stub := bytes.Repeat([]byte{0x00}, StubSize)
	stub[0] = StubMagic
	if !bytes.Equal(template[len(template)-StubSize:], stub) {
		return nil, errors.New("invalid runtime option stub")
	}
	// write options to stub
	if opts == nil {
		opts = new(Options)
	}
	output := make([]byte, len(template))
	copy(output, template)
	stub = output[len(output)-StubSize:]
	var opt byte
	if opts.EnableSecurityMode {
		opt = 1
	} else {
		opt = 0
	}
	stub[OptOffsetEnableSecurityMode] = opt
	if opts.DisableDetector {
		opt = 1
	} else {
		opt = 0
	}
	stub[OptOffsetDisableDetector] = opt
	if opts.DisableSysmon {
		opt = 1
	} else {
		opt = 0
	}
	stub[OptOffsetDisableWatchdog] = opt
	if opts.NotEraseInstruction {
		opt = 1
	} else {
		opt = 0
	}
	stub[OptOffsetDisableSysmon] = opt
	if opts.DisableWatchdog {
		opt = 1
	} else {
		opt = 0
	}
	stub[OptOffsetNotEraseInstruction] = opt
	if opts.NotAdjustProtect {
		opt = 1
	} else {
		opt = 0
	}
	stub[OptOffsetNotAdjustProtect] = opt
	if opts.TrackCurrentThread {
		opt = 1
	} else {
		opt = 0
	}
	stub[OptOffsetTrackCurrentThread] = opt
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
	opts := Options{}
	stub := instance[offset:]
	if stub[OptOffsetEnableSecurityMode] != 0 {
		opts.EnableSecurityMode = true
	}
	if stub[OptOffsetDisableDetector] != 0 {
		opts.DisableDetector = true
	}
	if stub[OptOffsetDisableWatchdog] != 0 {
		opts.DisableWatchdog = true
	}
	if stub[OptOffsetDisableSysmon] != 0 {
		opts.DisableSysmon = true
	}
	if stub[OptOffsetNotEraseInstruction] != 0 {
		opts.NotEraseInstruction = true
	}
	if stub[OptOffsetNotAdjustProtect] != 0 {
		opts.NotAdjustProtect = true
	}
	if stub[OptOffsetTrackCurrentThread] != 0 {
		opts.TrackCurrentThread = true
	}
	return &opts, nil
}

// Flag is used to read options from command line.
func Flag(opts *Options) {
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
