//go:build windows

package platform

import (
	"fmt"
	"hash/fnv"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procCreateMutexW = windows.NewLazySystemDLL("kernel32.dll").NewProc("CreateMutexW")

// Lock provides single-instance protection keyed by a path (the baseline DB),
// so two `seatguard run` daemons never share one baseline/journal — which
// would race the state file and corrupt the journal's HMAC chain. On Windows
// this is a named mutex whose existence signals a live instance. Returns
// (release, acquired, err); acquired is false when another instance holds it.
func Lock(path string) (func(), bool, error) {
	h := fnv.New64a()
	h.Write([]byte(strings.ToLower(filepath.Clean(path))))
	name, err := windows.UTF16PtrFromString(fmt.Sprintf("Local\\seatguard-%016x", h.Sum64()))
	if err != nil {
		return func() {}, false, err
	}
	r, _, callErr := procCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(name)))
	if r == 0 {
		return func() {}, false, callErr
	}
	handle := windows.Handle(r)
	// The named object already existing means another instance is alive.
	if callErr == windows.ERROR_ALREADY_EXISTS {
		windows.CloseHandle(handle)
		return func() {}, false, nil
	}
	return func() { windows.CloseHandle(handle) }, true, nil
}
