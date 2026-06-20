package info

// Info contains the raw runtime information.
type Info struct {
	Version uint64 `json:"version"`
	Hash    uint64 `json:"hash"`
	Size    uint32 `json:"size"`
	Flags   uint32 `json:"flags"`
}
