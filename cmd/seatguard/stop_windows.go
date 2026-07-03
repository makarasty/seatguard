//go:build windows

package main

import "os"

// stopPID terminates the daemon. Windows has no graceful signal for a
// console-less background process, so this is an immediate TerminateProcess;
// the daemon's file writes are atomic, so an abrupt stop leaves no torn state.
func stopPID(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}

// stopPIDForce is identical to stopPID on Windows (TerminateProcess is already
// unconditional); it exists so the cross-platform escalation path compiles.
func stopPIDForce(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}
