//go:build !windows

package platform

import "os"

// posixKeyInput decodes CSI escape sequences from a raw-mode terminal.
type posixKeyInput struct {
	restore func()
	f       *os.File
}

// NewKeyInput puts the terminal in cbreak mode and decodes arrow keys from
// the ESC [ A/B/C/D sequences that POSIX terminals emit.
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
		var seq [2]byte
		m, _ := p.f.Read(seq[:])
		if m >= 2 && seq[0] == '[' {
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

func (p *posixKeyInput) Close() {
	if p.restore != nil {
		p.restore()
	}
}
