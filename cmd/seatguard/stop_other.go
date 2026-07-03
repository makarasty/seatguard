//go:build !windows

package main

import (
	"os"
	"syscall"
)

// stopPID asks the daemon to shut down gracefully — it installs a SIGTERM
// handler (signal.NotifyContext) that journals a clean daemon_stop and exits.
func stopPID(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Signal(syscall.SIGTERM)
}

// stopPIDForce sends SIGKILL to escalate when a graceful SIGTERM did not bring
// the daemon down within the confirmation window.
func stopPIDForce(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Signal(syscall.SIGKILL)
}
