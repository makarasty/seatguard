//go:build !windows

package platform

import "os"

// IsPrivileged reports whether the process runs as root (euid 0).
func IsPrivileged() bool {
	return os.Geteuid() == 0
}
