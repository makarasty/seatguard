//go:build windows

package platform

import "golang.org/x/sys/windows"

// RawInput switches the console to single-key mode (no line buffering, no
// echo) and enables ENABLE_VIRTUAL_TERMINAL_INPUT so special keys — arrows
// in particular — are delivered to ReadFile/os.Stdin as ANSI escape
// sequences (ESC [ A/B/C/D) rather than as KEY_EVENT records that a byte
// read never sees. Without VT input, arrow keys produce nothing on stdin
// while space/letters still arrive as bytes. Returns a restore func and
// whether it succeeded (false when stdin is not a console).
func RawInput() (restore func(), ok bool) {
	h := windows.Handle(windows.Stdin)
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return func() {}, false
	}
	newMode := mode &^ (windows.ENABLE_LINE_INPUT | windows.ENABLE_ECHO_INPUT | windows.ENABLE_PROCESSED_INPUT)
	newMode |= windows.ENABLE_VIRTUAL_TERMINAL_INPUT
	if err := windows.SetConsoleMode(h, newMode); err != nil {
		// VT input may be unavailable on very old consoles; retry without it
		// so at least hotkeys keep working.
		fallback := mode &^ (windows.ENABLE_LINE_INPUT | windows.ENABLE_ECHO_INPUT)
		if err2 := windows.SetConsoleMode(h, fallback); err2 != nil {
			return func() {}, false
		}
	}
	return func() { windows.SetConsoleMode(h, mode) }, true
}
