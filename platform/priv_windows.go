//go:build windows

package platform

import "golang.org/x/sys/windows"

// IsPrivileged reports whether the process runs elevated (Administrator).
// Tamper-evidence assumes the DB/key are owned by a privileged account; when
// this is false, seatguard warns that its on-disk protection is weakened.
func IsPrivileged() bool {
	tok := windows.GetCurrentProcessToken()
	return tok.IsElevated()
}
