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
	return readKeyBytes(p.f)
}

func (p *posixKeyInput) Close() {
	if p.restore != nil {
		p.restore()
	}
}
