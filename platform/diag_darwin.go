//go:build darwin

package platform

import (
	"fmt"
	"os"
	"strings"
)

// SelfDiag reports the raw result of each low-level darwin proc_info call
// against the current process, so CI can show exactly which one is empty.
func SelfDiag() string {
	pid := int32(os.Getpid())
	var b strings.Builder

	// LISTPIDS: nil-buffer size probe vs the real (buffered) call.
	nprobe, e1 := procInfo(callListPIDs, procAllPIDs, 0, 0, nil, 0)
	fmt.Fprintf(&b, "  listpids size-probe: ret=%d err=%v\n", nprobe, e1)
	pids, e2 := listPIDs()
	inSelf := false
	for _, p := range pids {
		if p == pid {
			inSelf = true
		}
	}
	fmt.Fprintf(&b, "  listPIDs: n=%d self-present=%v err=%v\n", len(pids), inSelf, e2)

	// Per-self PIDINFO flavors used by procInfoOf.
	path, e3 := pidPath(pid)
	fmt.Fprintf(&b, "  pidPath(self): %q err=%v\n", path, e3)
	st, e4 := pidStartTime(pid)
	fmt.Fprintf(&b, "  pidStartTime(self): %d err=%v\n", st, e4)

	// FDs (used by HoldersOfFile / EstablishedTo).
	fds, e5 := listFDs(pid)
	var vnodes, sockets int
	for _, f := range fds {
		switch f.fdType {
		case proxFDTypeVnode:
			vnodes++
		case proxFDTypeSocket:
			sockets++
		}
	}
	fmt.Fprintf(&b, "  listFDs(self): n=%d vnodes=%d sockets=%d err=%v\n", len(fds), vnodes, sockets, e5)
	return b.String()
}
