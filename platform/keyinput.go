package platform

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
