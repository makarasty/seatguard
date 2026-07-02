//go:build windows

package platform

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

// CanonPath returns a canonical form of an existing path so that different
// spellings of the same file compare equal. On Windows it expands 8.3 short
// names (e.g. C:\Users\RUNNER~1 → C:\Users\runneradmin, PROGRA~1 → "Program
// Files") via GetLongPathName — without this, the same binary reported one
// way by the process backend and enrolled another way would look foreign and
// trip a false positive. Falls back to Clean when the file can't be resolved.
func CanonPath(p string) string {
	in, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return filepath.Clean(p)
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetLongPathName(in, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || int(n) > len(buf) {
		return filepath.Clean(p)
	}
	return filepath.Clean(windows.UTF16ToString(buf[:n]))
}
