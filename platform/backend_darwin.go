//go:build darwin

package platform

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// darwinBackend is a pure-Go (CGO-free) backend built on the XNU
// proc_info(2) syscall (SYS_proc_info = 336) and sysctl KERN_PROCARGS2.
// It cross-compiles with CGO_ENABLED=0 so the darwin/arm64 target stays a
// single static binary.
//
// VALIDATION STATUS: the struct offsets below are transcribed from XNU
// <sys/proc_info.h>. They are exercised by the same acceptance harness as
// the other platforms, but that harness only runs on the host OS — this
// file has not yet been run on Apple hardware in CI. The offsets are
// annotated so they can be validated field-by-field. Every accessor is
// bounds-checked and degrades to an error rather than misattributing, so a
// layout mismatch fails safe (missed detection) rather than false-positive.
type darwinBackend struct{}

// New returns the Darwin backend.
func New() Backend { return &darwinBackend{} }

// proc_info(2) call numbers and flavors (XNU sys/proc_info.h).
const (
	sysProcInfo = 336

	callListPIDs  = 1 // PROC_INFO_CALL_LISTPIDS
	callPIDInfo   = 2 // PROC_INFO_CALL_PIDINFO
	callPIDFDInfo = 3 // PROC_INFO_CALL_PIDFDINFO

	procAllPIDs = 1 // PROC_ALL_PIDS

	flavorPIDPathInfo  = 11 // PROC_PIDPATHINFO
	flavorPIDTBSDInfo  = 3  // PROC_PIDTBSDINFO
	flavorPIDTaskInfo  = 4  // PROC_PIDTASKINFO
	flavorPIDListFDs   = 1  // PROC_PIDLISTFDS
	flavorFDVnodePath  = 2  // PROC_PIDFDVNODEPATHINFO
	flavorFDSocketInfo = 3  // PROC_PIDFDSOCKETINFO
	pidPathInfoMaxsize = 4096
	proxFDTypeVnode    = 1 // PROX_FDTYPE_VNODE
	proxFDTypeSocket   = 2 // PROX_FDTYPE_SOCKET
)

// procInfo is the raw proc_info(2) wrapper. The meaning of the 2nd/3rd
// args depends on the call number (pid/flavor for PIDINFO, type/typeinfo
// for LISTPIDS, pid/flavor with arg=fd for PIDFDINFO).
func procInfo(callnum, a2 int32, a3 uint32, arg uint64, buf unsafe.Pointer, size int32) (int32, error) {
	r1, _, errno := unix.Syscall6(
		sysProcInfo,
		uintptr(callnum),
		uintptr(a2),
		uintptr(a3),
		uintptr(arg),
		uintptr(buf),
		uintptr(size),
	)
	if errno != 0 {
		return 0, errno
	}
	return int32(r1), nil
}

func listPIDs() ([]int32, error) {
	// A size-probe (nil buffer) is unreliable here across OS versions, so
	// grow the buffer until the result isn't truncated. Start generous.
	size := 4096
	for {
		buf := make([]int32, size)
		got, err := procInfo(callListPIDs, procAllPIDs, 0, 0, unsafe.Pointer(&buf[0]), int32(size*4))
		if err != nil {
			return nil, err
		}
		count := int(got) / 4
		if count >= size && size < 1<<20 {
			size *= 2 // buffer was full → possibly truncated; grow and retry
			continue
		}
		out := make([]int32, 0, count)
		for i := 0; i < count; i++ {
			if buf[i] != 0 {
				out = append(out, buf[i])
			}
		}
		return out, nil
	}
}

func pidPath(pid int32) (string, error) {
	buf := make([]byte, pidPathInfoMaxsize)
	n, err := procInfo(callPIDInfo, pid, flavorPIDPathInfo, 0, unsafe.Pointer(&buf[0]), int32(len(buf)))
	if err != nil {
		return "", err
	}
	if n <= 0 {
		return "", fmt.Errorf("empty path for pid %d", pid)
	}
	return string(buf[:clen(buf[:n])]), nil
}

// pidStartTime returns start_time in microseconds since epoch — a stable
// per-process handle (proc_bsdinfo.pbi_start_tvsec/usec).
func pidStartTime(pid int32) (int64, error) {
	const size = 136 // sizeof(struct proc_bsdinfo)
	buf := make([]byte, size)
	n, err := procInfo(callPIDInfo, pid, flavorPIDTBSDInfo, 0, unsafe.Pointer(&buf[0]), size)
	if err != nil {
		return 0, err
	}
	if n < size {
		return 0, fmt.Errorf("short proc_bsdinfo for pid %d", pid)
	}
	sec := binary.LittleEndian.Uint64(buf[120:128])  // pbi_start_tvsec
	usec := binary.LittleEndian.Uint64(buf[128:136]) // pbi_start_tvusec
	return int64(sec)*1_000_000 + int64(usec), nil
}

func (b *darwinBackend) procInfoOf(pid int32) (ProcessInfo, error) {
	path, err := pidPath(pid)
	if err != nil {
		return ProcessInfo{}, err
	}
	st, err := pidStartTime(pid)
	if err != nil {
		return ProcessInfo{}, err
	}
	return ProcessInfo{PID: uint32(pid), StartTime: st, ExePath: path}, nil
}

// listFDs returns (fd, fdtype) pairs for a pid via PROC_PIDLISTFDS. Uses a
// grow-loop rather than trusting a nil-buffer size probe.
func listFDs(pid int32) ([]procFDInfo, error) {
	const fdSize = 8 // sizeof(struct proc_fdinfo)
	size := 256 * fdSize
	for {
		buf := make([]byte, size)
		got, err := procInfo(callPIDInfo, pid, flavorPIDListFDs, 0, unsafe.Pointer(&buf[0]), int32(size))
		if err != nil {
			return nil, err
		}
		count := int(got) / fdSize
		if count*fdSize >= size && size < 1<<20 {
			size *= 2 // possibly truncated; grow and retry
			continue
		}
		out := make([]procFDInfo, 0, count)
		for i := 0; i < count; i++ {
			off := i * fdSize
			out = append(out, procFDInfo{
				fd:     int32(binary.LittleEndian.Uint32(buf[off : off+4])),
				fdType: binary.LittleEndian.Uint32(buf[off+4 : off+8]),
			})
		}
		return out, nil
	}
}

type procFDInfo struct {
	fd     int32
	fdType uint32
}

// fdVnodePath resolves an fd to its filesystem path via
// PROC_PIDFDVNODEPATHINFO. Path offset in struct vnode_fdinfowithpath:
// proc_fileinfo(24) + vinfo_stat(136) = 160; buffer is 160 + MAXPATHLEN.
func fdVnodePath(pid, fd int32) (string, error) {
	const pathOff = 160
	const size = pathOff + 1024
	buf := make([]byte, size)
	n, err := procInfo(callPIDFDInfo, pid, flavorFDVnodePath, uint64(fd), unsafe.Pointer(&buf[0]), size)
	if err != nil {
		return "", err
	}
	if n < pathOff {
		return "", fmt.Errorf("short vnode path info")
	}
	p := buf[pathOff:]
	return string(p[:clen(p)]), nil
}

func (b *darwinBackend) HoldersOfFile(path string) ([]ProcessInfo, error) {
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		target = filepath.Clean(path)
	}
	pids, err := listPIDs()
	if err != nil {
		return nil, err
	}
	self := int32(os.Getpid())
	var out []ProcessInfo
	for _, pid := range pids {
		if pid == self || pid == 0 {
			continue
		}
		fds, err := listFDs(pid)
		if err != nil {
			continue // permission denied or gone; poll again next tick
		}
		for _, fd := range fds {
			if fd.fdType != proxFDTypeVnode {
				continue
			}
			p, err := fdVnodePath(pid, fd.fd)
			if err != nil {
				continue
			}
			if p == target || p == path {
				if pi, err := b.procInfoOf(pid); err == nil {
					out = append(out, pi)
				}
				break
			}
		}
	}
	return out, nil
}

// Socket parsing offsets within struct socket_fdinfo (proc_fileinfo is 24
// bytes; struct socket_info follows). See <sys/proc_info.h>.
const (
	sockFileInfo = 24  // sizeof(proc_fileinfo)
	soiKindOff   = 232 // socket_info.soi_kind, relative to socket_info start
	soiProtoOff  = 240 // socket_info.soi_proto (union) start
	sockInfoIn   = 1   // SOCKINFO_IN
	sockInfoTCP  = 2   // SOCKINFO_TCP
	iniFportOff  = 0   // in_sockinfo.insi_fport
	iniVflagOff  = 24  // in_sockinfo.insi_vflag
	iniFaddrOff  = 32  // in_sockinfo.insi_faddr (union, 16 bytes)
	iniIPv4      = 0x1 // INI_IPV4
	iniIPv6      = 0x2 // INI_IPV6
)

// fdRemote resolves an fd's established TCP peer, or ("",0,false).
func fdRemote(pid, fd int32) (ip string, port uint16, ok bool) {
	const bufSize = 2048 // sizeof(struct socket_fdinfo) is well under this
	buf := make([]byte, bufSize)
	n, err := procInfo(callPIDFDInfo, pid, flavorFDSocketInfo, uint64(fd), unsafe.Pointer(&buf[0]), bufSize)
	if err != nil || int(n) < soiProtoOff+iniFaddrOff+16 {
		return "", 0, false
	}
	si := buf[sockFileInfo:] // socket_info
	kind := int32(binary.LittleEndian.Uint32(si[soiKindOff : soiKindOff+4]))
	if kind != sockInfoIn && kind != sockInfoTCP {
		return "", 0, false
	}
	ini := si[soiProtoOff:] // in_sockinfo (also the head of tcp_sockinfo)
	// insi_fport holds the port in network byte order in its low 16 bits.
	port = binary.BigEndian.Uint16(ini[iniFportOff : iniFportOff+2])
	vflag := ini[iniVflagOff]
	faddr := ini[iniFaddrOff : iniFaddrOff+16]
	switch {
	case vflag&iniIPv4 != 0:
		// union in4in6_addr: v4 in_addr sits after 3 pad words (offset 12).
		v4 := net.IPv4(faddr[12], faddr[13], faddr[14], faddr[15])
		return v4.String(), port, true
	case vflag&iniIPv6 != 0:
		return net.IP(faddr).String(), port, true
	}
	return "", 0, false
}

func (b *darwinBackend) EstablishedTo(remoteIPs map[string]struct{}) ([]ConnInfo, error) {
	pids, err := listPIDs()
	if err != nil {
		return nil, err
	}
	self := int32(os.Getpid())
	var out []ConnInfo
	for _, pid := range pids {
		if pid == self || pid == 0 {
			continue
		}
		fds, err := listFDs(pid)
		if err != nil {
			continue
		}
		var pi *ProcessInfo
		for _, fd := range fds {
			if fd.fdType != proxFDTypeSocket {
				continue
			}
			ip, port, ok := fdRemote(pid, fd.fd)
			if !ok {
				continue
			}
			if _, want := remoteIPs[ip]; !want {
				continue
			}
			if pi == nil {
				p, err := b.procInfoOf(pid)
				if err != nil {
					break
				}
				pi = &p
			}
			out = append(out, ConnInfo{Proc: *pi, RemoteIP: ip, RemotePort: port})
		}
	}
	return out, nil
}

// Cmdline reads the argv via sysctl KERN_PROCARGS2, which returns:
// [int argc][exec_path\0][padding\0...][argv[0]\0 argv[1]\0 ...].
func (b *darwinBackend) Cmdline(pid uint32) ([]string, error) {
	raw, err := unix.SysctlRaw("kern.procargs2", int(pid))
	if err != nil {
		return nil, err
	}
	if len(raw) < 4 {
		return nil, fmt.Errorf("short procargs2")
	}
	argc := int(binary.LittleEndian.Uint32(raw[:4]))
	rest := raw[4:]
	// Skip exec_path and the NUL padding that follows it.
	i := 0
	for i < len(rest) && rest[i] != 0 {
		i++
	}
	for i < len(rest) && rest[i] == 0 {
		i++
	}
	var args []string
	for len(args) < argc && i < len(rest) {
		start := i
		for i < len(rest) && rest[i] != 0 {
			i++
		}
		args = append(args, string(rest[start:i]))
		i++ // skip NUL
	}
	return args, nil
}

func (b *darwinBackend) RSSBytes(pid uint32) (uint64, error) {
	const size = 232 // sizeof(struct proc_taskinfo) (>= resident field)
	buf := make([]byte, size)
	n, err := procInfo(callPIDInfo, int32(pid), flavorPIDTaskInfo, 0, unsafe.Pointer(&buf[0]), size)
	if err != nil {
		return 0, err
	}
	if n < 16 {
		return 0, fmt.Errorf("short proc_taskinfo for pid %d", pid)
	}
	// pti_resident_size is the 2nd uint64 (after pti_virtual_size).
	return binary.LittleEndian.Uint64(buf[8:16]), nil
}

func (b *darwinBackend) InstancesOf(exePath string) ([]ProcessInfo, error) {
	target := filepath.Clean(exePath)
	pids, err := listPIDs()
	if err != nil {
		return nil, err
	}
	var out []ProcessInfo
	for _, pid := range pids {
		if pid == 0 {
			continue
		}
		pi, err := b.procInfoOf(pid)
		if err != nil {
			continue
		}
		if filepath.Clean(pi.ExePath) == target {
			out = append(out, pi)
		}
	}
	return out, nil
}

// clen returns the length of the NUL-terminated prefix of b.
func clen(b []byte) int {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		return i
	}
	return len(b)
}
