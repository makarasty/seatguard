//go:build !windows

package platform

import "os"

// EnableANSI reports whether stdout is a real terminal (so ANSI colors and
// cursor control are appropriate). Pipes, files and /dev/null are not.
func EnableANSI() bool {
	return isTTY(int(os.Stdout.Fd()))
}

// StdinInteractive reports whether stdin is a real terminal. It must use a
// true tty check (not merely "is a character device"): a service or the
// acceptance harness launches the daemon with stdin = /dev/null, which IS a
// character device — treating that as interactive would start the keyboard
// watcher, which then reads EOF, mistakes it for Esc, and stops the daemon
// immediately. isTTY is defined per-OS (different termios ioctl).
func StdinInteractive() bool {
	return isTTY(int(os.Stdin.Fd()))
}
