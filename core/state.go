package core

import (
	"encoding/json"
	"os"
	"time"

	"seatguard/platform"
)

// DaemonState is the single source of truth for the runtime state file the
// daemon writes and the status/dashboard/tray read. Previously this shape
// was redeclared in three places with drifting field names.
type DaemonState struct {
	PID        int       `json:"pid"`
	StartedAt  time.Time `json:"started_at"`
	LastPoll   time.Time `json:"last_poll"`
	Polls      uint64    `json:"polls"`
	AlertCount uint64    `json:"alert_count"`
	PollSecs   int       `json:"poll_secs"`
}

// Write persists the state (0600) and applies the platform file hardening
// (a protected DACL on Windows) so the state file matches the DB/key posture.
func (s *DaemonState) Write(path string) error {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return err
	}
	platform.HardenFile(path) // best effort
	return nil
}

// ReadDaemonState loads the state file.
func ReadDaemonState(path string) (*DaemonState, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s DaemonState
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Running reports whether the state looks live (polled recently).
func (s *DaemonState) Running() bool {
	return time.Since(s.LastPoll) < time.Duration(max(s.PollSecs, 1)*10)*time.Second
}
