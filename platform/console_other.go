//go:build !windows

package platform

import "os"

// EnableANSI reports whether stdout likely supports ANSI colors. POSIX
// terminals do; pipes do not.
func EnableANSI() bool {
	return isCharDevice(os.Stdout)
}

// StdinInteractive reports whether stdin is a terminal (not piped/redirected
// or a service context).
func StdinInteractive() bool {
	return isCharDevice(os.Stdin)
}

func isCharDevice(f *os.File) bool {
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}
