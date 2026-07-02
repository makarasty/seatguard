//go:build !windows

package main

import "os/exec"

// hideChildWindow is a no-op off Windows.
func hideChildWindow(cmd *exec.Cmd) {}
