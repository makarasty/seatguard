//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

// detachChild puts the background daemon in its own session (setsid) so it has
// no controlling terminal. Without this the daemon stays in the launching
// terminal's process group, and closing that terminal (or dropping the SSH
// session) sends SIGHUP to the whole group and kills the "detached" daemon.
func detachChild(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setsid = true
}
