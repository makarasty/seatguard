//go:build linux

package platform

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// linuxBackend is a pure-Go /proc scanner. No cgo, no external tools.
type linuxBackend struct{}

// New returns the Linux backend.
func New() Backend { return &linuxBackend{} }

func listPIDs() ([]uint32, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	pids := make([]uint32, 0, len(ents))
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		n, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		pids = append(pids, uint32(n))
	}
	return pids, nil
}

// procInfo resolves /proc/<pid> into a ProcessInfo. StartTime is field 22
// of /proc/<pid>/stat (clock ticks since boot) — stable for the process
// lifetime and, combined with PID, a unique handle.
func procInfo(pid uint32) (ProcessInfo, error) {
	base := fmt.Sprintf("/proc/%d", pid)
	exe, err := os.Readlink(base + "/exe")
	if err != nil {
		return ProcessInfo{}, err
	}
	stat, err := os.ReadFile(base + "/stat")
	if err != nil {
		return ProcessInfo{}, err
	}
	// comm may contain spaces/parens; start after the last ')'.
	i := bytes.LastIndexByte(stat, ')')
	if i < 0 || i+2 > len(stat) {
		return ProcessInfo{}, fmt.Errorf("malformed stat for pid %d", pid)
	}
	fields := strings.Fields(string(stat[i+2:]))
	// fields[0] is stat field 3 (state); start_time is stat field 22 → index 19.
	if len(fields) < 20 {
		return ProcessInfo{}, fmt.Errorf("short stat for pid %d", pid)
	}
	st, err := strconv.ParseInt(fields[19], 10, 64)
	if err != nil {
		return ProcessInfo{}, err
	}
	return ProcessInfo{PID: pid, StartTime: st, ExePath: exe}, nil
}

func (b *linuxBackend) HoldersOfFile(path string) ([]ProcessInfo, error) {
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		target = filepath.Clean(path)
	}
	pids, err := listPIDs()
	if err != nil {
		return nil, err
	}
	self := uint32(os.Getpid())
	var out []ProcessInfo
	for _, pid := range pids {
		if pid == self {
			continue
		}
		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // permission denied or gone; poll again next tick
		}
		for _, fd := range fds {
			dst, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if dst == target || dst == path {
				pi, err := procInfo(pid)
				if err == nil {
					out = append(out, pi)
				}
				break
			}
		}
	}
	return out, nil
}

// tcpEntry is one parsed row of /proc/net/tcp{,6}.
type tcpEntry struct {
	remoteIP   net.IP
	remotePort uint16
	inode      string
}

func parseProcNetTCP(file string, v6 bool) ([]tcpEntry, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []tcpEntry
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		if fields[3] != "01" { // TCP_ESTABLISHED
			continue
		}
		rem := strings.Split(fields[2], ":")
		if len(rem) != 2 {
			continue
		}
		ip, err := hexToIP(rem[0], v6)
		if err != nil {
			continue
		}
		port, err := strconv.ParseUint(rem[1], 16, 16)
		if err != nil {
			continue
		}
		out = append(out, tcpEntry{remoteIP: ip, remotePort: uint16(port), inode: fields[9]})
	}
	return out, sc.Err()
}

// hexToIP decodes the kernel's little-endian-per-word hex address format.
func hexToIP(h string, v6 bool) (net.IP, error) {
	raw, err := hexDecode(h)
	if err != nil {
		return nil, err
	}
	if !v6 {
		if len(raw) != 4 {
			return nil, fmt.Errorf("bad v4 addr")
		}
		v := binary.LittleEndian.Uint32(raw)
		return net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24)).To4(), nil
	}
	if len(raw) != 16 {
		return nil, fmt.Errorf("bad v6 addr")
	}
	ip := make(net.IP, 16)
	for i := 0; i < 4; i++ {
		w := binary.LittleEndian.Uint32(raw[i*4 : i*4+4])
		binary.BigEndian.PutUint32(ip[i*4:i*4+4], w)
	}
	return ip, nil
}

func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd hex")
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		v, err := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
		if err != nil {
			return nil, err
		}
		out[i] = byte(v)
	}
	return out, nil
}

func (b *linuxBackend) EstablishedTo(remoteIPs map[string]struct{}) ([]ConnInfo, error) {
	var matched []tcpEntry
	for _, spec := range []struct {
		file string
		v6   bool
	}{{"/proc/net/tcp", false}, {"/proc/net/tcp6", true}} {
		ents, err := parseProcNetTCP(spec.file, spec.v6)
		if err != nil {
			continue // tcp6 may be absent
		}
		for _, e := range ents {
			if _, ok := remoteIPs[e.remoteIP.String()]; ok {
				matched = append(matched, e)
			}
		}
	}
	if len(matched) == 0 {
		return nil, nil
	}
	// Map socket inodes to owning processes via /proc/<pid>/fd.
	want := make(map[string]tcpEntry, len(matched))
	for _, m := range matched {
		want["socket:["+m.inode+"]"] = m
	}
	pids, err := listPIDs()
	if err != nil {
		return nil, err
	}
	self := uint32(os.Getpid())
	var out []ConnInfo
	for _, pid := range pids {
		if pid == self {
			continue
		}
		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			dst, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if e, ok := want[dst]; ok {
				pi, err := procInfo(pid)
				if err == nil {
					out = append(out, ConnInfo{Proc: pi, RemoteIP: e.remoteIP.String(), RemotePort: e.remotePort})
				}
			}
		}
	}
	return out, nil
}

func (b *linuxBackend) Cmdline(pid uint32) ([]string, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return nil, err
	}
	parts := bytes.Split(bytes.TrimRight(raw, "\x00"), []byte{0})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, string(p))
	}
	return out, nil
}

func (b *linuxBackend) RSSBytes(pid uint32) (uint64, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, err := strconv.ParseUint(fields[1], 10, 64)
				if err != nil {
					return 0, err
				}
				return kb * 1024, nil
			}
		}
	}
	return 0, fmt.Errorf("VmRSS not found for pid %d", pid)
}

func (b *linuxBackend) InstancesOf(exePath string) ([]ProcessInfo, error) {
	target := filepath.Clean(exePath)
	pids, err := listPIDs()
	if err != nil {
		return nil, err
	}
	var out []ProcessInfo
	for _, pid := range pids {
		pi, err := procInfo(pid)
		if err != nil {
			continue
		}
		if filepath.Clean(pi.ExePath) == target {
			out = append(out, pi)
		}
	}
	return out, nil
}
