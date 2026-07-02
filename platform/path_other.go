//go:build !windows

package platform

import "path/filepath"

// CanonPath returns a canonical form of an existing path so different
// spellings compare equal. On POSIX it resolves symlinks (e.g. macOS
// /tmp → /private/tmp); falls back to Clean when resolution fails.
func CanonPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return filepath.Clean(p)
}
