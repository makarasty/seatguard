//go:build !windows

package platform

import "errors"

// Tray levels (icon color).
const (
	TrayGreen  = 0
	TrayYellow = 1
	TrayRed    = 2
	TrayGrey   = 3
)

// TrayInfo is the snapshot the tray renders each refresh.
type TrayInfo struct {
	Level      int
	Tooltip    string
	AlertCount int
	AlertText  string
}

// ErrTrayUnsupported is returned by RunTray on non-Windows platforms.
var ErrTrayUnsupported = errors.New("system tray is implemented on Windows only in Phase 1")

// HideConsole is a no-op off Windows.
func HideConsole() {}

// RunTray is unsupported off Windows.
func RunTray(title, selfExe string, dashArgs []string, refresh func() TrayInfo, onQuit func()) error {
	return ErrTrayUnsupported
}
