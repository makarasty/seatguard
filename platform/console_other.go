//go:build !windows

package platform

import "os"

// EnableANSI reports whether stdout likely supports ANSI colors. POSIX
// terminals do; pipes do not.
func EnableANSI() bool {
	st, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}
