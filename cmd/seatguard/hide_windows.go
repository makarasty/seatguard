//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// hideChildWindow makes a spawned process start without a console window.
func hideChildWindow(cmd *exec.Cmd) {
	const createNoWindow = 0x08000000
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
}
