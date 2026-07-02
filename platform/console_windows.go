//go:build windows

package platform

import "golang.org/x/sys/windows"

// EnableANSI turns on VT escape-sequence processing for the console so the
// setup wizard can use colors. Returns false when stdout is not a console
// (piped) or the mode change fails — callers fall back to plain text.
func EnableANSI() bool {
	h := windows.Handle(windows.Stdout)
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return false
	}
	if err := windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING); err != nil {
		return false
	}
	return true
}

// StdinInteractive reports whether stdin is a real console (not piped,
// redirected, or a detached/service context). Callers use this to decide
// whether to watch the keyboard for an interactive quit key.
func StdinInteractive() bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(windows.Stdin), &mode) == nil
}
