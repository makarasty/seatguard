//go:build !windows

package platform

import "os"

// HardenFile tightens on-disk permissions for a sensitive file (DB or HMAC
// key). On POSIX this enforces 0600 (owner read/write only). The directory
// is expected to already be owned by a privileged user, outside any home.
func HardenFile(path string) error {
	return os.Chmod(path, 0o600)
}
