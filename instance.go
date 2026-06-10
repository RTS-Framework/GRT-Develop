package develop

import (
	"bytes"

	"github.com/RTS-Framework/GRT-Develop/argument"
	"github.com/RTS-Framework/GRT-Develop/option"
	"github.com/RTS-Framework/GRT-Develop/ptrtable"
	"github.com/RTS-Framework/GRT-Develop/shield"
)

// Options contains the options for instantiate runtime.
type Options struct {
	Shield []byte `json:"shield"`
	Decoy  []byte `json:"decoy"`

	option.Options

	Arguments []*argument.Arg `json:"arguments"`
}

// Instantiate is used to instantiate runtime from template.
func Instantiate(template []byte, opts *Options) ([]byte, error) {
	if opts == nil {
		opts = new(Options)
	}
	var err error
	if len(opts.Shield) != 0 {
		template, err = shield.Set(template, opts.Shield, opts.Decoy)
		if err != nil {
			return nil, err
		}
	}
	template, err = ptrtable.Set(template)
	if err != nil {
		return nil, err
	}
	template, err = option.Set(template, &opts.Options)
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
