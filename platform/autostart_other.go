//go:build !windows

package platform

import "errors"

// ErrAutostartUnsupported is returned by the autostart helpers off Windows;
// systemd/launchd unit management is Phase 2.
var ErrAutostartUnsupported = errors.New("autostart install is Windows-only in Phase 1")

func SetAutostart(name, cmdline string) error { return ErrAutostartUnsupported }
func RemoveAutostart(name string) error       { return ErrAutostartUnsupported }
func AutostartInstalled(name string) bool     { return false }
