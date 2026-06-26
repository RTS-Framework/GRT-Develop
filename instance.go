package develop

import (
	"bytes"

	"github.com/RTS-Framework/GRT-Develop/argument"
	"github.com/RTS-Framework/GRT-Develop/option"
	"github.com/RTS-Framework/GRT-Develop/ptrtable"
	"github.com/RTS-Framework/GRT-Develop/shield"
)

// MainModule is used to set ShieldModuleHash with 0x0001 for use "main.exe".
const MainModule = "<main>"

// Options contains the options for instantiate runtime.
type Options struct {
	// runtime will not initialize when the exe name is not expected.
	// if zero, runtime will skip this detection.
	ImagePinningName string `toml:"image_pinning_name" json:"image_pinning_name"`

	// the module name of the pre-injected shield in.
	ShieldModuleName string `toml:"shield_module_name" json:"shield_module_name"`

	// the RVA of the pre-injected shield in the module.
	// if ShieldModuleName is not empty, it must be set.
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

	// set shield instruction to shield stub.
	Shield []byte `toml:"shield" json:"shield"`

	// set decoy instruction to shield stub.
	Decoy []byte `toml:"decoy" json:"decoy"`

	// set argument to template tail.
	Arguments []*argument.Arg `toml:"arguments" json:"arguments"`
}

// Instantiate is used to instantiate runtime from template.
func Instantiate(template []byte, opts *Options) ([]byte, error) {
	if opts == nil {
		opts = new(Options)
	}
	template, err := shield.Set(template, opts.Shield, opts.Decoy)
	if err != nil {
		return nil, err
	}
	template, err = ptrtable.Set(template)
	if err != nil {
		return nil, err
	}
	// build option
	opt := option.Options{
		ImagePinningHash:    hashMod(opts.ImagePinningName),
		ShieldModuleHash:    hashMod(opts.ShieldModuleName),
		ShieldEntryPoint:    opts.ShieldEntryPoint,
		ShieldMemAddress:    opts.ShieldMemAddress,
		EnableSecurityMode:  opts.EnableSecurityMode,
		DisableDetector:     opts.DisableDetector,
		DisableWatchdog:     opts.DisableWatchdog,
		DisableSysmon:       opts.DisableSysmon,
		NotEraseInstruction: opts.NotEraseInstruction,
		NotAdjustProtect:    opts.NotAdjustProtect,
		TrackCurrentThread:  opts.TrackCurrentThread,
	}
	template, err = option.Set(template, &opt)
	if err != nil {
		return nil, err
	}
	stub, err := argument.Encode(opts.Arguments...)
	if err != nil {
		return nil, err
	}
	instance := bytes.NewBuffer(nil)
	instance.Grow(len(template) + len(stub))
	instance.Write(template)
	instance.Write(stub)
	return instance.Bytes(), nil
}

// refence ImagePinningHash and ShieldModuleHash in option.Options.
func hashMod(module string) uint64 {
	if module == "" {
		return 0x0000
	}
	if module == MainModule {
		return 0x0001
	}
	return option.Hash(module)
}
