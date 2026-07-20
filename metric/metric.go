package metric

import (
	"github.com/RTS-Framework/GRT-Develop/types"
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
	IsEnabled        types.BOOL
	HasDebugger      types.BOOL
	HasMemoryScanner types.BOOL
	InSandbox        types.BOOL
	InEmulator       types.BOOL
	InVirtualMachine types.BOOL
	IsAccelerated    types.BOOL
	SafeRank         int32
}

// WDStatus contains status about watchdog.
type WDStatus struct {
	IsEnabled types.BOOL
	Reserved  int32
	NumKick   int64
	NumNormal int64
	NumReset  int64
}

// SMStatus contains status about sysmon.
type SMStatus struct {
	IsEnabled  types.BOOL
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
