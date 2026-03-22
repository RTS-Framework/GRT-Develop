package serialization

//nolint:unused
type testStruct struct {
	unexported1 int

	Arg1 uint32
	Arg2 [2]uint32
	Arg3 []byte
	Arg4 string
	Arg5 uint8
	Arg6 uint16
	Arg7 []uint16
	Arg8 string
	Arg9 []byte

	Arg10 int8
	Arg11 int16
	Arg12 int32
	Arg13 int64
	Arg14 uint8
	Arg15 uint16
	Arg16 uint32
	Arg17 uint64
	Arg18 float32
	Arg19 float64
	Arg20 bool

	unexported2 int

	Arg21 [2]int8
	Arg22 [2]int16
	Arg23 [2]int32
	Arg24 [2]int64
	Arg25 [2]uint8
	Arg26 [2]uint16
	Arg27 [2]uint32
	Arg28 [2]uint64
	Arg29 [2]float32
	Arg30 [2]float64
	Arg31 [2]bool

	Arg32 []int8
	Arg33 []int16
	Arg34 []int32
	Arg35 []int64
	Arg36 []uint8
	Arg37 []uint16
	Arg38 []uint32
	Arg39 []uint64
	Arg40 []float32
	Arg41 []float64
	Arg42 []bool

	unexported3 int
}
