package platform

import "io"

// Key is a normalized key press from the console, decoded per-OS so the TUI
// gets arrows reliably (Windows delivers arrows as KEY_EVENT records, not as
// escape bytes; POSIX terminals send CSI escape sequences).
type Key int

const (
	KeyNone Key = iota
	KeyUp
	KeyDown
	KeyLeft
	KeyRight
	KeyEnter
	KeySpace
	KeyEsc
	KeyRune // a printable ASCII key; the byte is returned alongside
)

// KeyInput is a blocking source of normalized key presses.
type KeyInput interface {
	// Read blocks for the next key. For KeyRune the second return is the
	// ASCII byte; otherwise it is 0.
	Read() (Key, byte)
	// Close restores the console to its prior mode.
	Close()
}

// readKeyBytes decodes one key from a byte stream (redirected stdin, or a
// POSIX terminal): plain bytes, plus CSI (ESC [ x) and SS3 (ESC O x) escape
// sequences for arrows. Shared by the POSIX reader and the Windows
// non-console fallback so piped input works everywhere.
func readKeyBytes(r io.Reader) (Key, byte) {
	var b [1]byte
	n, err := r.Read(b[:])
	if err != nil || n == 0 {
		return KeyEsc, 0
	}
	switch b[0] {
	case '\r', '\n':
		return KeyEnter, 0
	case ' ':
		return KeySpace, ' '
	case 3, 4: // Ctrl-C / Ctrl-D
		return KeyEsc, 0
	case 0x1b: // ESC — CSI or SS3 arrow, or a lone Escape
		var seq [2]byte
		m, _ := r.Read(seq[:])
		if m >= 2 && (seq[0] == '[' || seq[0] == 'O') {
			switch seq[1] {
			case 'A':
				return KeyUp, 0
			case 'B':
				return KeyDown, 0
			case 'C':
				return KeyRight, 0
			case 'D':
				return KeyLeft, 0
			}
		}
		return KeyEsc, 0
	}
	return KeyRune, b[0]
}
