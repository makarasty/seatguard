//go:build !windows

package platform

import (
	"os"

	"golang.org/x/sys/unix"
)

// Lock provides single-instance protection keyed by a path (the baseline DB).
// On POSIX it holds an exclusive, non-blocking flock on "<path>.lock", which
// the OS releases automatically if the process dies. Returns (release,
// acquired, err); acquired is false when another instance holds the lock.
func Lock(path string) (func(), bool, error) {
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return func() {}, false, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if err == unix.EWOULDBLOCK {
			return func() {}, false, nil
		}
		return func() {}, false, err
	}
	return func() {
		unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
	}, true, nil
}
