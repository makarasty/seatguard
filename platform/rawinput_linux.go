//go:build linux

package platform

import (
	"os"

	"golang.org/x/sys/unix"
)

// RawInput puts the terminal into cbreak mode (no canonical line editing,
// no echo) for single-key TUI input. Restores the prior termios on close.
func RawInput() (restore func(), ok bool) {
	fd := int(os.Stdin.Fd())
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return func() {}, false
	}
	raw := *old
	raw.Lflag &^= unix.ECHO | unix.ICANON
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &raw); err != nil {
		return func() {}, false
	}
	return func() { unix.IoctlSetTermios(fd, unix.TCSETS, old) }, true
}

// isTTY reports whether fd is a terminal (the termios ioctl only succeeds on
// a real tty, not on /dev/null, pipes or files).
func isTTY(fd int) bool {
	_, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	return err == nil
}
