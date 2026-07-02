// Package platform provides OS-specific process, file and network
// introspection behind a common interface. Each OS backend lives in a
// file guarded by build tags; New() returns the backend for the current
// platform.
package platform

// ProcessInfo identifies a running process by a stable handle:
// (PID, StartTime) plus the resolved executable path. PID alone is never
// used as identity — it is ephemeral and reused by the OS.
type ProcessInfo struct {
	PID       uint32 `json:"pid"`
	StartTime int64  `json:"start_time"` // platform-specific units, stable for process lifetime
	ExePath   string `json:"exe_path"`
}

// ConnInfo describes one established TCP connection attributed to a process.
type ConnInfo struct {
	Proc       ProcessInfo `json:"proc"`
	RemoteIP   string      `json:"remote_ip"`
	RemotePort uint16      `json:"remote_port"`
}

// Backend is the OS introspection surface used by the detection engine.
type Backend interface {
	// HoldersOfFile returns processes currently holding an open handle /
	// file descriptor for the given path.
	HoldersOfFile(path string) ([]ProcessInfo, error)

	// EstablishedTo returns established TCP connections whose remote IP
	// is in the given set (string form, e.g. "104.18.2.3" or "::1").
	EstablishedTo(remoteIPs map[string]struct{}) ([]ConnInfo, error)

	// Cmdline returns the argument vector of the process, best effort.
	// Used for the interpreter rule (node + script inside install dir).
	Cmdline(pid uint32) ([]string, error)

	// RSSBytes returns the resident set size of the process.
	RSSBytes(pid uint32) (uint64, error)

	// InstancesOf returns running processes whose executable path equals
	// exePath (case-insensitive where the OS is).
	InstancesOf(exePath string) ([]ProcessInfo, error)
}
