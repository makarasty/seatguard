//go:build windows

package main

import "os/exec"

// detachChild is a no-op on Windows: hideChildWindow already starts the daemon
// with CREATE_NO_WINDOW, so it has no console attached and does not receive the
// terminal-close / Ctrl+Break events that would otherwise stop it.
func detachChild(cmd *exec.Cmd) {}
