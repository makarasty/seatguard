package core

import (
	"fmt"
	"io"
)

// Alert signal kinds.
const (
	SignalCredRead  = "cred_read"  // unknown process holds a credential file open
	SignalAPIEgress = "api_egress" // unknown process has an established conn to an Anthropic endpoint
)

// Alert is the attribution record for one detection. It carries the
// offender's full identity handle: binary path + (pid, start_time).
type Alert struct {
	Signal    string `json:"signal"`
	ExePath   string `json:"exe_path"`
	ExeSHA256 string `json:"exe_sha256,omitempty"`
	PID       uint32 `json:"pid"`
	StartTime int64  `json:"start_time"`
	Target    string `json:"target"` // credential path or remote ip:port
	Reason    string `json:"reason"`
}

func (a *Alert) String() string {
	return fmt.Sprintf("ALERT [%s] exe=%s pid=%d start_time=%d target=%s reason=%s",
		a.Signal, a.ExePath, a.PID, a.StartTime, a.Target, a.Reason)
}

// emitAlert journals the alert and mirrors it to the given writer (stderr).
func emitAlert(j *Journal, w io.Writer, a *Alert) error {
	fmt.Fprintln(w, a.String())
	return j.Append("alert", a)
}
