//go:build !windows

package platform

import (
	"os"

	"golang.org/x/sys/unix"
)

// posixKeyInput decodes CSI/SS3 escape sequences from a raw-mode terminal.
type posixKeyInput struct {
	restore func()
	f       *os.File
}

// NewKeyInput puts the terminal in cbreak mode and decodes arrow keys from
// the ESC [ A/B/C/D (CSI) and ESC O A/B/C/D (SS3) sequences POSIX terminals
// emit.
func NewKeyInput() KeyInput {
	restore, _ := RawInput()
	return &posixKeyInput{restore: restore, f: os.Stdin}
}

func (p *posixKeyInput) Read() (Key, byte) {
	var b [1]byte
	n, err := p.f.Read(b[:])
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
	case 0x1b:
		// Distinguish a lone Escape from a CSI/SS3 arrow: a real sequence
		// arrives as a burst, so if nothing more is readable within a short
		// window it was the Escape key alone (which must exit promptly).
		if !p.pending(50) {
			return KeyEsc, 0
		}
		var seq [2]byte
		m, _ := p.f.Read(seq[:])
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

// pending reports whether more input is readable within timeoutMs.
func (p *posixKeyInput) pending(timeoutMs int) bool {
	pfd := []unix.PollFd{{Fd: int32(p.f.Fd()), Events: unix.POLLIN}}
	n, err := unix.Poll(pfd, timeoutMs)
	return err == nil && n > 0 && pfd[0].Revents&unix.POLLIN != 0
}

func (p *posixKeyInput) Close() {
	if p.restore != nil {
		p.restore()
	}
}
