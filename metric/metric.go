package metric

import (
	"errors"
	"strings"
)

// Metrics contains status about runtime submodules.
type Metrics struct {
	Library  LTStatus
	Memory   MTStatus
	Thread   TTStatus
	Resource RTStatus
	Detector DTStatus
	Watchdog WDStatus
	Sysmon   SMStatus
	Shield   SDStatus
}

// LTStatus contains status about library tracker.
type LTStatus struct {
	NumModules    int64
	NumProcedures int64
}

// MTStatus contains status about memory tracker.
type MTStatus struct {
	NumGlobals int64
	NumLocals  int64
	NumBlocks  int64
	NumRegions int64
	NumPages   int64
	NumHeaps   int64
}

// TTStatus contains status about thread tracker.
type TTStatus struct {
	NumThreads  int64
	NumTLSIndex int64
	NumSuspend  int64
}

// RTStatus contains status about resource tracker.
type RTStatus struct {
	NumMutexs         int64
	NumEvents         int64
	NumSemaphores     int64
	NumWaitableTimers int64
	NumFiles          int64
	NumDirectories    int64
	NumIOCPs          int64
	NumRegKeys        int64
	NumSockets        int64
}

// DTStatus contains status about detector.
type DTStatus struct {
	IsEnabled        BOOL
	HasDebugger      BOOL
	HasMemoryScanner BOOL
	InSandbox        BOOL
	InEmulator       BOOL
	InVirtualMachine BOOL
	IsAccelerated    BOOL
	SafeRank         int32
}

// WDStatus contains status about watchdog.
type WDStatus struct {
	IsEnabled BOOL
	Reserved  int32
	NumKick   int64
	NumNormal int64
	NumReset  int64
}

// SMStatus contains status about sysmon.
type SMStatus struct {
	IsEnabled  BOOL
	Reserved   int32
	NumNormal  int64
	NumRecover int64
	NumPanic   int64
}

// SDStatus contains status about shield.
type SDStatus struct {
	EntryPoint  uintptr
	BaseAddress uintptr
	Source      int64
}

// constant for use BOOL easily.
const (
	TRUE  = BOOL(1)
	FALSE = BOOL(0)
)

// BOOL is an int32 for structure align.
type BOOL int32

// ToBool is used to convert to go bool.
func (b BOOL) ToBool() bool {
	return b != 0
}

func (b BOOL) String() string {
	if b.ToBool() {
		return "true"
	}
	return "false"
}

// MarshalText is used to implement TextMarshaler interface.
func (b BOOL) MarshalText() ([]byte, error) {
	return []byte(b.String()), nil
}

// UnmarshalText is used to implement TextUnmarshaler interface.
func (b *BOOL) UnmarshalText(data []byte) error {
	switch strings.ToLower(string(data)) {
	case "true":
		*b = BOOL(1)
	case "false":
		*b = BOOL(0)
	default:
		return errors.New("invalid BOOL value")
	}
	return nil
}
