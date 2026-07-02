//go:build windows

package platform

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// windowsBackend uses only documented Win32 / NT APIs via syscalls:
//   - Restart Manager (rstrtmgr.dll) to find processes holding a file open
//   - GetExtendedTcpTable (iphlpapi.dll) for TCP connection → PID mapping
//   - QueryFullProcessImageName + GetProcessTimes for stable identity
//   - PEB read for command lines (best effort)
//   - K32GetProcessMemoryInfo for RSS
type windowsBackend struct{}

// New returns the Windows backend.
func New() Backend { return &windowsBackend{} }

var (
	modRstrtmgr            = windows.NewLazySystemDLL("rstrtmgr.dll")
	procRmStartSession     = modRstrtmgr.NewProc("RmStartSession")
	procRmRegisterResource = modRstrtmgr.NewProc("RmRegisterResources")
	procRmGetList          = modRstrtmgr.NewProc("RmGetList")
	procRmEndSession       = modRstrtmgr.NewProc("RmEndSession")

	modIphlpapi             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modIphlpapi.NewProc("GetExtendedTcpTable")

	modKernel32                = windows.NewLazySystemDLL("kernel32.dll")
	procK32GetProcessMemoryInf = modKernel32.NewProc("K32GetProcessMemoryInfo")
)

const (
	cchRmSessionKey    = 32
	rmRebootReasonNone = 0
)

type rmUniqueProcess struct {
	ProcessID        uint32
	ProcessStartTime windows.Filetime
}

type rmProcessInfo struct {
	Process             rmUniqueProcess
	AppName             [256]uint16
	ServiceShortName    [64]uint16
	ApplicationType     uint32
	AppStatus           uint32
	TSSessionID         uint32
	BServiceRestartable int32
}

// HoldersOfFile uses the Restart Manager to enumerate processes that hold
// an open handle to the file. This is the documented, non-driver way to
// answer "who has this file open" on Windows.
func (b *windowsBackend) HoldersOfFile(path string) ([]ProcessInfo, error) {
	var session uint32
	key := make([]uint16, cchRmSessionKey+1)
	r, _, _ := procRmStartSession.Call(
		uintptr(unsafe.Pointer(&session)),
		0,
		uintptr(unsafe.Pointer(&key[0])),
	)
	if r != 0 {
		return nil, fmt.Errorf("RmStartSession failed: %d", r)
	}
	defer procRmEndSession.Call(uintptr(session))

	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	files := []*uint16{p}
	r, _, _ = procRmRegisterResource.Call(
		uintptr(session),
		1,
		uintptr(unsafe.Pointer(&files[0])),
		0, 0, 0, 0,
	)
	if r != 0 {
		return nil, fmt.Errorf("RmRegisterResources failed: %d", r)
	}

	var needed, count, reason uint32
	count = 16
	for {
		buf := make([]rmProcessInfo, count)
		needed = 0
		r, _, _ = procRmGetList.Call(
			uintptr(session),
			uintptr(unsafe.Pointer(&needed)),
			uintptr(unsafe.Pointer(&count)),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&reason)),
		)
		const errorMoreData = 234
		if r == errorMoreData {
			count = needed
			continue
		}
		if r != 0 {
			return nil, fmt.Errorf("RmGetList failed: %d", r)
		}
		self := uint32(os.Getpid())
		var out []ProcessInfo
		for i := uint32(0); i < count; i++ {
			pid := buf[i].Process.ProcessID
			if pid == self {
				continue
			}
			pi, err := queryProcess(pid)
			if err != nil {
				continue // process exited between snapshot and query
			}
			// Guard against PID reuse: Restart Manager reports the start
			// time it saw; require it to match the live process.
			rmStart := filetimeToInt64(buf[i].Process.ProcessStartTime)
			if pi.StartTime != rmStart {
				continue
			}
			out = append(out, pi)
		}
		return out, nil
	}
}

func filetimeToInt64(ft windows.Filetime) int64 {
	return int64(ft.HighDateTime)<<32 | int64(ft.LowDateTime)
}

// queryProcess resolves PID → (exe path, start time) via OpenProcess with
// limited rights. StartTime is the creation FILETIME (100ns units).
func queryProcess(pid uint32) (ProcessInfo, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ProcessInfo{}, err
	}
	defer windows.CloseHandle(h)

	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return ProcessInfo{}, err
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return ProcessInfo{}, err
	}
	return ProcessInfo{
		PID:       pid,
		StartTime: filetimeToInt64(creation),
		// Canonicalize (expand 8.3 short names) so the path compares equal to
		// the enrolled one regardless of how the process was launched.
		ExePath: CanonPath(windows.UTF16ToString(buf[:size])),
	}, nil
}

// mibTcpRowOwnerPid mirrors MIB_TCPROW_OWNER_PID.
type mibTcpRowOwnerPid struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

// mibTcp6RowOwnerPid mirrors MIB_TCP6ROW_OWNER_PID.
type mibTcp6RowOwnerPid struct {
	LocalAddr     [16]byte
	LocalScopeID  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeID uint32
	RemotePort    uint32
	State         uint32
	OwningPid     uint32
}

const (
	tcpTableOwnerPidConnections = 4 // TCP_TABLE_OWNER_PID_CONNECTIONS
	mibTcpStateEstab            = 5
	afInet                      = 2
	afInet6                     = 23
)

func getTcpTable(family uint32) ([]byte, error) {
	var size uint32
	for i := 0; i < 8; i++ {
		var buf []byte
		var ptr uintptr
		if size > 0 {
			buf = make([]byte, size)
			ptr = uintptr(unsafe.Pointer(&buf[0]))
		}
		r, _, _ := procGetExtendedTcpTable.Call(
			ptr,
			uintptr(unsafe.Pointer(&size)),
			0, // bOrder
			uintptr(family),
			tcpTableOwnerPidConnections,
			0,
		)
		const errorInsufficientBuffer = 122
		if r == errorInsufficientBuffer {
			continue
		}
		if r != 0 {
			return nil, fmt.Errorf("GetExtendedTcpTable failed: %d", r)
		}
		return buf, nil
	}
	return nil, fmt.Errorf("GetExtendedTcpTable: table size kept changing")
}

func (b *windowsBackend) EstablishedTo(remoteIPs map[string]struct{}) ([]ConnInfo, error) {
	type match struct {
		pid  uint32
		ip   string
		port uint16
	}
	var matches []match

	if buf, err := getTcpTable(afInet); err == nil && len(buf) >= 4 {
		n := binary.LittleEndian.Uint32(buf[0:4])
		rowSize := unsafe.Sizeof(mibTcpRowOwnerPid{})
		for i := uint32(0); i < n; i++ {
			off := 4 + uintptr(i)*rowSize
			if off+rowSize > uintptr(len(buf)) {
				break
			}
			row := (*mibTcpRowOwnerPid)(unsafe.Pointer(&buf[off]))
			if row.State != mibTcpStateEstab {
				continue
			}
			ip := net.IPv4(byte(row.RemoteAddr), byte(row.RemoteAddr>>8), byte(row.RemoteAddr>>16), byte(row.RemoteAddr>>24)).String()
			if _, ok := remoteIPs[ip]; ok {
				port := uint16(row.RemotePort>>8) | uint16(row.RemotePort&0xff)<<8
				matches = append(matches, match{pid: row.OwningPid, ip: ip, port: port})
			}
		}
	}
	if buf, err := getTcpTable(afInet6); err == nil && len(buf) >= 4 {
		n := binary.LittleEndian.Uint32(buf[0:4])
		rowSize := unsafe.Sizeof(mibTcp6RowOwnerPid{})
		for i := uint32(0); i < n; i++ {
			off := 4 + uintptr(i)*rowSize
			if off+rowSize > uintptr(len(buf)) {
				break
			}
			row := (*mibTcp6RowOwnerPid)(unsafe.Pointer(&buf[off]))
			if row.State != mibTcpStateEstab {
				continue
			}
			ip := net.IP(row.RemoteAddr[:]).String()
			if _, ok := remoteIPs[ip]; ok {
				port := uint16(row.RemotePort>>8) | uint16(row.RemotePort&0xff)<<8
				matches = append(matches, match{pid: row.OwningPid, ip: ip, port: port})
			}
		}
	}

	self := uint32(os.Getpid())
	var out []ConnInfo
	for _, m := range matches {
		if m.pid == self || m.pid == 0 {
			continue
		}
		pi, err := queryProcess(m.pid)
		if err != nil {
			continue
		}
		out = append(out, ConnInfo{Proc: pi, RemoteIP: m.ip, RemotePort: m.port})
	}
	return out, nil
}

// Cmdline reads the target's PEB → RTL_USER_PROCESS_PARAMETERS → CommandLine.
// Best effort: requires PROCESS_VM_READ; returns an error when unavailable.
func (b *windowsBackend) Cmdline(pid uint32) ([]string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)

	var pbi windows.PROCESS_BASIC_INFORMATION
	var retLen uint32
	if err := windows.NtQueryInformationProcess(h, windows.ProcessBasicInformation, unsafe.Pointer(&pbi), uint32(unsafe.Sizeof(pbi)), &retLen); err != nil {
		return nil, err
	}
	var peb windows.PEB
	if err := readMem(h, uintptr(unsafe.Pointer(pbi.PebBaseAddress)), unsafe.Pointer(&peb), unsafe.Sizeof(peb)); err != nil {
		return nil, err
	}
	var params windows.RTL_USER_PROCESS_PARAMETERS
	if err := readMem(h, uintptr(unsafe.Pointer(peb.ProcessParameters)), unsafe.Pointer(&params), unsafe.Sizeof(params)); err != nil {
		return nil, err
	}
	cl := params.CommandLine
	if cl.Length == 0 {
		return nil, fmt.Errorf("empty command line")
	}
	raw := make([]uint16, cl.Length/2)
	if err := readMem(h, uintptr(unsafe.Pointer(cl.Buffer)), unsafe.Pointer(&raw[0]), uintptr(cl.Length)); err != nil {
		return nil, err
	}
	return splitWindowsCommandLine(windows.UTF16ToString(raw)), nil
}

func readMem(h windows.Handle, addr uintptr, dst unsafe.Pointer, size uintptr) error {
	var read uintptr
	return windows.ReadProcessMemory(h, addr, (*byte)(dst), size, &read)
}

// splitWindowsCommandLine is a minimal CommandLineToArgv-style splitter.
func splitWindowsCommandLine(s string) []string {
	var args []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inQuote = !inQuote
		case (c == ' ' || c == '\t') && !inQuote:
			if cur.Len() > 0 {
				args = append(args, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		args = append(args, cur.String())
	}
	return args
}

// processMemoryCounters mirrors PROCESS_MEMORY_COUNTERS.
type processMemoryCounters struct {
	Cb                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

func (b *windowsBackend) RSSBytes(pid uint32) (uint64, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(h)
	var pmc processMemoryCounters
	pmc.Cb = uint32(unsafe.Sizeof(pmc))
	r, _, e := procK32GetProcessMemoryInf.Call(uintptr(h), uintptr(unsafe.Pointer(&pmc)), uintptr(pmc.Cb))
	if r == 0 {
		return 0, fmt.Errorf("K32GetProcessMemoryInfo failed: %v", e)
	}
	return uint64(pmc.WorkingSetSize), nil
}

func (b *windowsBackend) InstancesOf(exePath string) ([]ProcessInfo, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	var out []ProcessInfo
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		pid := pe.ProcessID
		if pid == 0 || pid == 4 {
			continue
		}
		pi, qerr := queryProcess(pid)
		if qerr != nil {
			continue
		}
		if strings.EqualFold(pi.ExePath, exePath) {
			out = append(out, pi)
		}
	}
	return out, nil
}
