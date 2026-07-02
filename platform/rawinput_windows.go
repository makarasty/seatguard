//go:build windows

package platform

import "golang.org/x/sys/windows"

// RawInput switches the console to single-key mode (no line buffering, no
// echo) so a TUI can read hotkeys immediately. Returns a restore func and
// whether it succeeded (false when stdin is not a console).
func RawInput() (restore func(), ok bool) {
	h := windows.Handle(windows.Stdin)
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return func() {}, false
	}
	newMode := mode &^ (windows.ENABLE_LINE_INPUT | windows.ENABLE_ECHO_INPUT)
	if err := windows.SetConsoleMode(h, newMode); err != nil {
		return func() {}, false
	}
	return func() { windows.SetConsoleMode(h, mode) }, true
}
