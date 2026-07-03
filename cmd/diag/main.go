// diag exercises the platform Backend and prints what each method returns.
// It is a CI/debugging aid, especially for the unvalidated macOS backend:
// comparing macOS output against Linux/Windows pinpoints which syscall path
// is broken. The Backend intentionally skips the caller's own process for
// file/connection lookups, so those are tested against a spawned child.
package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"time"

	"seatguard/platform"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "child" {
		child(os.Args[2], os.Args[3]) // holdFile, dialAddr
		return
	}

	be := platform.New()
	pid := uint32(os.Getpid())
	self, _ := os.Executable()
	self = platform.CanonPath(self)
	fmt.Printf("== backend diag: os=%s pid=%d ==\n", runtime.GOOS, pid)

	// --- baseline: procInfo on self (RSS, cmdline, InstancesOf) ---
	if rss, err := be.RSSBytes(pid); err != nil {
		fmt.Printf("RSSBytes(self):   ERR %v\n", err)
	} else {
		fmt.Printf("RSSBytes(self):   %d bytes\n", rss)
	}
	if cl, err := be.Cmdline(pid); err != nil {
		fmt.Printf("Cmdline(self):    ERR %v\n", err)
	} else {
		fmt.Printf("Cmdline(self):    %v\n", cl)
	}
	inst, err := be.InstancesOf(self)
	fmt.Printf("InstancesOf(self): n=%d err=%v\n", len(inst), err)
	for _, p := range inst {
		if p.PID == pid {
			fmt.Printf("  FOUND self: start_time=%d exe=%s\n", p.StartTime, p.ExePath)
		}
	}

	// --- spawn a child that holds a file and a loopback connection ---
	holdFile, _ := os.CreateTemp("", "seatguard-diag")
	holdFile.Close()
	defer os.Remove(holdFile.Name())
	target := platform.CanonPath(holdFile.Name())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Println("listen err:", err)
		return
	}
	defer ln.Close()
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go func() { b := make([]byte, 1); c.Read(b) }()
		}
	}()

	cmd := exec.Command(self, "child", holdFile.Name(), ln.Addr().String())
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		fmt.Println("spawn child err:", err)
		return
	}
	defer cmd.Process.Kill()
	childPID := waitReady(stdout)
	fmt.Printf("child pid=%d holding %s + conn to %s\n", childPID, target, ln.Addr())
	time.Sleep(500 * time.Millisecond)

	// --- HoldersOfFile (§6.3 path) ---
	holders, herr := be.HoldersOfFile(target)
	fmt.Printf("HoldersOfFile:    n=%d err=%v\n", len(holders), herr)
	hit := false
	for _, p := range holders {
		if p.PID == childPID {
			hit = true
			fmt.Printf("  FOUND child: start_time=%d exe=%s\n", p.StartTime, p.ExePath)
		}
	}
	if !hit {
		fmt.Printf("  child NOT found holding the file (listFDs/vnode path broken)\n")
	}

	// --- EstablishedTo (§6.4 path) ---
	conns, cerr := be.EstablishedTo(map[string]struct{}{"127.0.0.1": {}})
	fmt.Printf("EstablishedTo:    n=%d err=%v\n", len(conns), cerr)
	hit = false
	for _, c := range conns {
		if c.Proc.PID == childPID {
			hit = true
			fmt.Printf("  FOUND child conn: remote=%s:%d\n", c.RemoteIP, c.RemotePort)
		}
	}
	if !hit {
		fmt.Printf("  child conn NOT found (listFDs/socket peer parsing broken)\n")
	}
}

// child opens holdFile, dials addr, prints its pid, and holds both open.
func child(holdFile, addr string) {
	f, err := os.Open(holdFile)
	if err == nil {
		defer f.Close()
	}
	conn, derr := net.Dial("tcp", addr)
	if derr == nil {
		defer conn.Close()
		conn.Write([]byte{1})
	}
	fmt.Printf("ready %d\n", os.Getpid())
	os.Stdout.Sync()
	time.Sleep(15 * time.Second)
}

func waitReady(r interface{ Read([]byte) (int, error) }) uint32 {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		var pid int
		if _, err := fmt.Sscanf(sc.Text(), "ready %d", &pid); err == nil {
			return uint32(pid)
		}
	}
	return 0
}
