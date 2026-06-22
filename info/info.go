package info

// Info contains the raw runtime information.
type Info struct {
	Version uint64
	Hash    [32]byte
	Size    uint32
	Flags   uint32
}
