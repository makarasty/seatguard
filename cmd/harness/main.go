// harness runs the §6 binary acceptance checks for seatguard without any
// manual steps. Run from the repo root:
//
//	go run ./cmd/harness
//
// Exit code 0 iff all nine checks pass.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"seatguard/platform"
)

// stubIP is a dedicated loopback address so the fake "Anthropic endpoint"
// never collides with unrelated 127.0.0.1 traffic on the machine.
const stubIP = "127.209.31.7"

const rssBudget = 15 * 1024 * 1024
const rssWindow = 60 * time.Second

type check struct {
	n      int
	name   string
	pass   bool
	detail string
}

type harness struct {
	goBin     string
	repo      string
	work      string
	exe       string // ".exe" on windows
	seatguard string
	claudeBin string // enrolled "simulated Claude" binary
	rogueBin  string
	nodeBin   string // rogue copy renamed to node
	decoyCred string
	dbPath    string
	keyPath   string
	journal   string
	statePath string
	daemon    *exec.Cmd
	daemonPID uint32
	daemonErr *os.File
	backend   platform.Backend
	results   []check
	keepWork  bool
}

func main() {
	keep := flag.Bool("keep", false, "keep the work directory for inspection")
	flag.Parse()

	h := &harness{backend: platform.New(), keepWork: *keep}
	if err := h.setup(); err != nil {
		fmt.Fprintf(os.Stderr, "harness setup failed: %v\n", err)
		os.Exit(1)
	}
	defer h.cleanup()

	h.checkBuild()       // §6.1
	h.checkEnroll()      // §6.2
	if h.startDaemon() { // needed by 3,4,5,8,9
		h.checkRSS()      // §6.8 (idle window first, before any events)
		h.checkCredRead() // §6.3
		h.checkEgress()   // §6.4
		h.checkRenamed()  // §6.9
		h.checkNoFalse()  // §6.5
		h.stopDaemon()
	} else {
		h.fail(8, "idle RSS", "daemon failed to start")
		h.fail(3, "cred-read detection", "daemon failed to start")
		h.fail(4, "egress detection", "daemon failed to start")
		h.fail(9, "identity-not-name", "daemon failed to start")
		h.fail(5, "zero false positives", "daemon failed to start")
	}
	h.checkDBIntegrity()  // §6.6
	h.checkJournalChain() // §6.7

	os.Exit(h.report())
}

func (h *harness) fail(n int, name, detail string) {
	h.results = append(h.results, check{n: n, name: name, pass: false, detail: detail})
}

func (h *harness) pass(n int, name, detail string) {
	h.results = append(h.results, check{n: n, name: name, pass: true, detail: detail})
}

// ---------- setup ----------

func (h *harness) setup() error {
	if runtime.GOOS == "windows" {
		h.exe = ".exe"
	}
	if p, err := exec.LookPath("go"); err == nil {
		h.goBin = p
	} else {
		h.goBin = filepath.Join(runtime.GOROOT(), "bin", "go"+h.exe)
	}
	repo, err := os.Getwd()
	if err != nil {
		return err
	}
	h.repo = repo
	work, err := os.MkdirTemp("", "seatguard-harness-")
	if err != nil {
		return err
	}
	h.work = work
	fmt.Printf("harness workdir: %s\n", work)

	h.seatguard = filepath.Join(work, "bin", "seatguard"+h.exe)
	h.claudeBin = filepath.Join(work, "claude-install", "claude"+h.exe)
	h.rogueBin = filepath.Join(work, "rogue", "stealer"+h.exe)
	h.nodeBin = filepath.Join(work, "rogue2", "node"+h.exe)
	h.dbPath = filepath.Join(work, "data", "baseline.db")
	h.keyPath = filepath.Join(work, "keys", "hmac.key") // separate dir from DB, per §3
	h.journal = filepath.Join(work, "data", "journal.log")
	h.statePath = filepath.Join(work, "data", "state.json")

	// Decoy credential file — a fake token, never a real one.
	h.decoyCred = filepath.Join(work, "home", ".credentials.json")
	if err := os.MkdirAll(filepath.Dir(h.decoyCred), 0o700); err != nil {
		return err
	}
	decoy := `{"claudeAiOauth":{"accessToken":"sk-ant-oat01-DECOY-not-a-real-token","expiresAt":1}}`
	return os.WriteFile(h.decoyCred, []byte(decoy), 0o600)
}

func (h *harness) cleanup() {
	if h.daemon != nil && h.daemon.Process != nil {
		h.daemon.Process.Kill()
	}
	if h.keepWork {
		fmt.Printf("workdir kept: %s\n", h.work)
		return
	}
	os.RemoveAll(h.work)
}

func (h *harness) goEnv(goos, goarch string) []string {
	env := os.Environ()
	env = append(env, "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
	return env
}

func (h *harness) build(out, pkg, ldflags, goos, goarch string) error {
	args := []string{"build", "-trimpath"}
	if ldflags != "" {
		args = append(args, "-ldflags", ldflags)
	}
	args = append(args, "-o", out, pkg)
	cmd := exec.Command(h.goBin, args...)
	cmd.Dir = h.repo
	cmd.Env = h.goEnv(goos, goarch)
	raw, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("go build %s (%s/%s): %v\n%s", pkg, goos, goarch, err, raw)
	}
	return nil
}

// ---------- §6.1 build ----------

func (h *harness) checkBuild() {
	targets := []struct{ goos, goarch string }{
		{"linux", "amd64"}, {"darwin", "arm64"}, {"windows", "amd64"},
	}
	var fails []string
	for _, t := range targets {
		out := filepath.Join(h.work, "dist", fmt.Sprintf("seatguard-%s-%s", t.goos, t.goarch))
		if t.goos == "windows" {
			out += ".exe"
		}
		if err := h.build(out, "./cmd/seatguard", "-s -w", t.goos, t.goarch); err != nil {
			fails = append(fails, err.Error())
			continue
		}
		if st, err := os.Stat(out); err != nil || st.Size() == 0 {
			fails = append(fails, out+": missing or empty")
		}
	}
	// Host binaries for the live tests (CGO_ENABLED=0 as well).
	if err := h.build(h.seatguard, "./cmd/seatguard", "", runtime.GOOS, runtime.GOARCH); err != nil {
		fails = append(fails, "host seatguard: "+err.Error())
	}
	if err := h.build(h.claudeBin, "./cmd/helper", "-X main.variant=legit-claude", runtime.GOOS, runtime.GOARCH); err != nil {
		fails = append(fails, "helper(legit): "+err.Error())
	}
	if err := h.build(h.rogueBin, "./cmd/helper", "-X main.variant=rogue", runtime.GOOS, runtime.GOARCH); err != nil {
		fails = append(fails, "helper(rogue): "+err.Error())
	}
	// §6.9 twin: same rogue bytes, renamed to "node", different path.
	if raw, err := os.ReadFile(h.rogueBin); err == nil {
		os.MkdirAll(filepath.Dir(h.nodeBin), 0o700)
		if err := os.WriteFile(h.nodeBin, raw, 0o755); err != nil {
			fails = append(fails, "node copy: "+err.Error())
		}
	} else {
		fails = append(fails, "read rogue for node copy: "+err.Error())
	}

	if len(fails) > 0 {
		h.fail(1, "cross-target static build", strings.Join(fails, "; "))
		fmt.Fprintln(os.Stderr, "build failures:\n"+strings.Join(fails, "\n"))
		os.Exit(h.report())
	}
	// Canonicalize the just-built binary paths (expand 8.3 short names /
	// resolve symlinks) so our attribution assertions compare against the
	// same canonical form the daemon's backend reports.
	h.claudeBin = platform.CanonPath(h.claudeBin)
	h.rogueBin = platform.CanonPath(h.rogueBin)
	h.nodeBin = platform.CanonPath(h.nodeBin)
	h.pass(1, "cross-target static build", "linux/amd64, darwin/arm64, windows/amd64 with CGO_ENABLED=0")
}

// ---------- §6.2 enroll ----------

func (h *harness) seatguardArgs(cmd string, extra ...string) []string {
	base := []string{cmd, "--db", h.dbPath, "--key", h.keyPath, "--journal", h.journal, "--state", h.statePath}
	return append(base, extra...)
}

func (h *harness) checkEnroll() {
	// Keep a live instance of the simulated Claude running during enroll so
	// the identity record captures its (pid, start_time) handle.
	live := exec.Command(h.claudeBin, "--hold", "30")
	stdout, _ := live.StdoutPipe()
	if err := live.Start(); err != nil {
		h.fail(2, "enroll", "cannot start simulated Claude: "+err.Error())
		return
	}
	defer func() {
		live.Process.Kill()
		live.Wait()
	}()
	waitReady(stdout, 10*time.Second)

	out, err := exec.Command(h.seatguard, h.seatguardArgs("enroll",
		"--claude-path", h.claudeBin,
		"--claude-dir", filepath.Dir(h.claudeBin),
		"--cred", h.decoyCred,
		"--api-host", "-",
		"--api-ip", stubIP,
		"--poll", "1",
		"--no-discover",
	)...).CombinedOutput()
	if err != nil {
		h.fail(2, "enroll", fmt.Sprintf("exit err %v: %s", err, out))
		return
	}

	// Inspect the identity records straight from the DB payload.
	ids, err := readBaselineIdentities(h.dbPath)
	if err != nil {
		h.fail(2, "enroll", "cannot read baseline: "+err.Error())
		return
	}
	for _, id := range ids {
		if id.Path != "" && len(id.SHA256) == 64 && id.ObservedStartTime > 0 {
			h.pass(2, "enroll", fmt.Sprintf("identity %s hash=%s... pid=%d start_time=%d",
				id.Path, id.SHA256[:12], id.ObservedPID, id.ObservedStartTime))
			return
		}
	}
	h.fail(2, "enroll", fmt.Sprintf("no identity with path+hash+start_time among %d records", len(ids)))
}

type identityRec struct {
	Path              string `json:"path"`
	SHA256            string `json:"sha256"`
	ObservedPID       uint32 `json:"observed_pid"`
	ObservedStartTime int64  `json:"observed_start_time"`
}

func readBaselineIdentities(dbPath string) ([]identityRec, error) {
	raw, err := os.ReadFile(dbPath)
	if err != nil {
		return nil, err
	}
	var env struct {
		Payload []byte `json:"payload"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	var b struct {
		Identities []identityRec `json:"identities"`
	}
	if err := json.Unmarshal(env.Payload, &b); err != nil {
		return nil, err
	}
	return b.Identities, nil
}

// ---------- daemon lifecycle ----------

func (h *harness) startDaemon() bool {
	errFile, err := os.Create(filepath.Join(h.work, "daemon.stderr"))
	if err != nil {
		return false
	}
	h.daemonErr = errFile
	cmd := exec.Command(h.seatguard, h.seatguardArgs("run")...)
	cmd.Stderr = errFile
	cmd.Stdout = errFile
	if err := cmd.Start(); err != nil {
		return false
	}
	h.daemon = cmd
	h.daemonPID = uint32(cmd.Process.Pid)
	// Wait for the first state write.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(h.statePath); err == nil {
			return true
		}
		if cmd.ProcessState != nil {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	fmt.Fprintln(os.Stderr, "daemon did not write state file; stderr:")
	tailFile(h.daemonErr.Name())
	return false
}

func (h *harness) stopDaemon() {
	if h.daemon != nil && h.daemon.Process != nil {
		h.daemon.Process.Kill()
		h.daemon.Wait()
	}
	if h.daemonErr != nil {
		h.daemonErr.Close()
	}
}

func tailFile(path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) > 20 {
		lines = lines[len(lines)-20:]
	}
	fmt.Fprintln(os.Stderr, strings.Join(lines, "\n"))
}

// ---------- alert inspection via `seatguard log --json` ----------

type alertRec struct {
	Signal    string `json:"signal"`
	ExePath   string `json:"exe_path"`
	PID       uint32 `json:"pid"`
	StartTime int64  `json:"start_time"`
	Target    string `json:"target"`
}

func (h *harness) alerts() ([]alertRec, error) {
	out, err := exec.Command(h.seatguard, h.seatguardArgs("log", "--json")...).Output()
	if err != nil {
		return nil, err
	}
	var alerts []alertRec
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var e struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.Type != "alert" {
			continue
		}
		var a alertRec
		if json.Unmarshal(e.Data, &a) == nil {
			alerts = append(alerts, a)
		}
	}
	return alerts, nil
}

func alertsForPID(all []alertRec, pid uint32, signal string) []alertRec {
	var out []alertRec
	for _, a := range all {
		if a.PID == pid && a.Signal == signal {
			out = append(out, a)
		}
	}
	return out
}

// runHelper starts bin with args, waits for its "ready" line, then waits
// long enough for several poll ticks plus dedup to settle, then reaps it.
func (h *harness) runHelper(bin string, args ...string) (pid uint32, err error) {
	cmd := exec.Command(bin, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	pid = uint32(cmd.Process.Pid)
	if !waitReady(stdout, 10*time.Second) {
		cmd.Process.Kill()
		cmd.Wait()
		return 0, fmt.Errorf("helper %s never became ready", bin)
	}
	// Helper holds resources 6s at 1s polling: several snapshots see it,
	// dedup must still yield exactly one alert.
	time.Sleep(9 * time.Second)
	cmd.Wait()
	time.Sleep(2 * time.Second) // let the last poll tick flush
	return pid, nil
}

func waitReady(r interface{ Read([]byte) (int, error) }, timeout time.Duration) bool {
	done := make(chan bool, 1)
	go func() {
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), "ready") {
				done <- true
				return
			}
		}
		done <- false
	}()
	select {
	case ok := <-done:
		return ok
	case <-time.After(timeout):
		return false
	}
}

// ---------- §6.8 idle RSS ----------

func (h *harness) checkRSS() {
	fmt.Printf("sampling daemon RSS for %s (idle)...\n", rssWindow)
	var max uint64
	deadline := time.Now().Add(rssWindow)
	for time.Now().Before(deadline) {
		rss, err := h.backend.RSSBytes(h.daemonPID)
		if err != nil {
			h.fail(8, "idle RSS", "cannot sample daemon RSS: "+err.Error())
			return
		}
		if rss > max {
			max = rss
		}
		time.Sleep(5 * time.Second)
	}
	detail := fmt.Sprintf("max RSS over %s = %.1f MB (budget 15 MB)", rssWindow, float64(max)/1024/1024)
	if max <= rssBudget {
		h.pass(8, "idle RSS", detail)
	} else {
		h.fail(8, "idle RSS", detail)
	}
}

// ---------- §6.3 cred read ----------

func (h *harness) checkCredRead() {
	pid, err := h.runHelper(h.rogueBin, "--cred", h.decoyCred, "--hold", "6")
	if err != nil {
		h.fail(3, "cred-read detection", err.Error())
		return
	}
	all, err := h.alerts()
	if err != nil {
		h.fail(3, "cred-read detection", "cannot read journal: "+err.Error())
		return
	}
	got := alertsForPID(all, pid, "cred_read")
	switch {
	case len(got) == 0:
		h.fail(3, "cred-read detection", fmt.Sprintf("no alert for rogue pid %d", pid))
	case len(got) > 1:
		h.fail(3, "cred-read detection", fmt.Sprintf("%d alerts, want exactly 1", len(got)))
	case !samePathLoose(got[0].ExePath, h.rogueBin) || got[0].StartTime <= 0:
		h.fail(3, "cred-read detection", fmt.Sprintf("bad attribution: exe=%s start_time=%d", got[0].ExePath, got[0].StartTime))
	default:
		h.pass(3, "cred-read detection", fmt.Sprintf("1 alert: exe=%s pid=%d start_time=%d", got[0].ExePath, pid, got[0].StartTime))
	}
}

// ---------- §6.4 egress ----------

func (h *harness) checkEgress() {
	ln, err := net.Listen("tcp", stubIP+":0")
	if err != nil {
		h.fail(4, "egress detection", "cannot bind stub listener on "+stubIP+": "+err.Error())
		return
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(io.Discard, c) // hold the conn open until the peer closes
				c.Close()
			}()
		}
	}()
	addr := ln.Addr().String()

	pid, err := h.runHelper(h.rogueBin, "--connect", addr, "--hold", "6")
	if err != nil {
		h.fail(4, "egress detection", err.Error())
		return
	}
	all, err := h.alerts()
	if err != nil {
		h.fail(4, "egress detection", "cannot read journal: "+err.Error())
		return
	}
	got := alertsForPID(all, pid, "api_egress")
	switch {
	case len(got) == 0:
		h.fail(4, "egress detection", fmt.Sprintf("no egress alert for rogue pid %d (target %s)", pid, addr))
	case len(got) > 1:
		h.fail(4, "egress detection", fmt.Sprintf("%d alerts, want exactly 1", len(got)))
	case !samePathLoose(got[0].ExePath, h.rogueBin) || got[0].StartTime <= 0:
		h.fail(4, "egress detection", fmt.Sprintf("bad attribution: exe=%s start_time=%d", got[0].ExePath, got[0].StartTime))
	default:
		h.pass(4, "egress detection", fmt.Sprintf("1 alert: exe=%s pid=%d target=%s", got[0].ExePath, pid, got[0].Target))
	}
}

// ---------- §6.9 renamed-to-node ----------

func (h *harness) checkRenamed() {
	pid, err := h.runHelper(h.nodeBin, "--cred", h.decoyCred, "--hold", "6")
	if err != nil {
		h.fail(9, "identity-not-name", err.Error())
		return
	}
	all, err := h.alerts()
	if err != nil {
		h.fail(9, "identity-not-name", "cannot read journal: "+err.Error())
		return
	}
	got := alertsForPID(all, pid, "cred_read")
	switch {
	case len(got) != 1:
		h.fail(9, "identity-not-name", fmt.Sprintf("%d alerts for node-named rogue, want exactly 1", len(got)))
	case !samePathLoose(got[0].ExePath, h.nodeBin):
		h.fail(9, "identity-not-name", "alert attributed to wrong binary: "+got[0].ExePath)
	default:
		h.pass(9, "identity-not-name", fmt.Sprintf("rogue renamed to %s still alerted (matching is by path+hash, not name)", filepath.Base(h.nodeBin)))
	}
}

// ---------- §6.5 zero false positives ----------

func (h *harness) checkNoFalse() {
	ln, err := net.Listen("tcp", stubIP+":0")
	if err != nil {
		h.fail(5, "zero false positives", "cannot bind stub listener: "+err.Error())
		return
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(io.Discard, c) // hold the conn open until the peer closes
				c.Close()
			}()
		}
	}()

	pid, err := h.runHelper(h.claudeBin, "--cred", h.decoyCred, "--connect", ln.Addr().String(), "--hold", "6")
	if err != nil {
		h.fail(5, "zero false positives", err.Error())
		return
	}
	all, err := h.alerts()
	if err != nil {
		h.fail(5, "zero false positives", "cannot read journal: "+err.Error())
		return
	}
	var hits []alertRec
	for _, a := range all {
		if a.PID == pid {
			hits = append(hits, a)
		}
	}
	if len(hits) > 0 {
		h.fail(5, "zero false positives", fmt.Sprintf("enrolled Claude twin triggered %d alerts: %+v", len(hits), hits[0]))
		return
	}
	h.pass(5, "zero false positives", "enrolled twin read creds and connected: 0 alerts")
}

// ---------- §6.6 DB integrity ----------

func (h *harness) checkDBIntegrity() {
	orig, err := os.ReadFile(h.dbPath)
	if err != nil {
		h.fail(6, "DB integrity", "cannot read DB: "+err.Error())
		return
	}
	defer os.WriteFile(h.dbPath, orig, 0o600) // restore for the next check

	tampered := flipInsidePayload(orig)
	if tampered == nil {
		h.fail(6, "DB integrity", "could not locate payload region to tamper")
		return
	}
	if err := os.WriteFile(h.dbPath, tampered, 0o600); err != nil {
		h.fail(6, "DB integrity", err.Error())
		return
	}

	// verify must exit nonzero and name the violation.
	out, err := exec.Command(h.seatguard, h.seatguardArgs("verify")...).CombinedOutput()
	if err == nil {
		h.fail(6, "DB integrity", "verify exited 0 on a tampered DB")
		return
	}
	if !bytes.Contains(bytes.ToLower(out), []byte("integrity")) &&
		!bytes.Contains(bytes.ToLower(out), []byte("hmac")) {
		h.fail(6, "DB integrity", "verify failed but did not report an integrity violation: "+string(out))
		return
	}

	// run must refuse to start (fail-safe) with a loud alert.
	runCmd := exec.Command(h.seatguard, h.seatguardArgs("run")...)
	var runOut bytes.Buffer
	runCmd.Stderr = &runOut
	runCmd.Stdout = &runOut
	if err := runCmd.Start(); err != nil {
		h.fail(6, "DB integrity", err.Error())
		return
	}
	done := make(chan error, 1)
	go func() { done <- runCmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			h.fail(6, "DB integrity", "run exited 0 on a tampered DB")
			return
		}
	case <-time.After(15 * time.Second):
		runCmd.Process.Kill()
		h.fail(6, "DB integrity", "run kept running on a tampered DB (fail-open)")
		return
	}
	if !bytes.Contains(bytes.ToLower(runOut.Bytes()), []byte("alert")) {
		h.fail(6, "DB integrity", "run refused but produced no alert output")
		return
	}
	h.pass(6, "DB integrity", "1-byte flip → verify nonzero with integrity report; run refuses to start (fail-safe)")
}

// flipInsidePayload flips one base64 character inside the "payload" field.
func flipInsidePayload(db []byte) []byte {
	marker := []byte(`"payload":"`)
	i := bytes.Index(db, marker)
	if i < 0 {
		return nil
	}
	pos := i + len(marker) + 24 // well inside the payload
	if pos >= len(db) {
		return nil
	}
	out := bytes.Clone(db)
	if out[pos] == 'A' {
		out[pos] = 'B'
	} else {
		out[pos] = 'A'
	}
	return out
}

// ---------- §6.7 journal chain ----------

func (h *harness) checkJournalChain() {
	orig, err := os.ReadFile(h.journal)
	if err != nil {
		h.fail(7, "append-only journal", "cannot read journal: "+err.Error())
		return
	}
	defer os.WriteFile(h.journal, orig, 0o600)

	lines := bytes.Split(bytes.TrimRight(orig, "\n"), []byte("\n"))
	if len(lines) < 3 {
		h.fail(7, "append-only journal", fmt.Sprintf("journal too short to test (%d records)", len(lines)))
		return
	}
	// Rewrite a middle record retroactively, keeping it valid JSON.
	mid := len(lines) / 2
	var rec map[string]any
	if err := json.Unmarshal(lines[mid], &rec); err != nil {
		h.fail(7, "append-only journal", "cannot parse middle record: "+err.Error())
		return
	}
	rec["type"] = "rewritten-by-attacker"
	forged, _ := json.Marshal(rec)
	lines[mid] = forged
	if err := os.WriteFile(h.journal, append(bytes.Join(lines, []byte("\n")), '\n'), 0o600); err != nil {
		h.fail(7, "append-only journal", err.Error())
		return
	}

	out, err := exec.Command(h.seatguard, h.seatguardArgs("verify")...).CombinedOutput()
	if err == nil {
		h.fail(7, "append-only journal", "verify exited 0 after a journal record was rewritten")
		return
	}
	if !bytes.Contains(bytes.ToLower(out), []byte("chain")) {
		h.fail(7, "append-only journal", "verify failed but did not report a chain break: "+string(out))
		return
	}
	h.pass(7, "append-only journal", fmt.Sprintf("rewriting record %d detected as chain break by verify", mid+1))
}

// ---------- report ----------

func samePathLoose(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

func (h *harness) report() int {
	// Order by §6 item number.
	byN := map[int]check{}
	for _, r := range h.results {
		byN[r.n] = r
	}
	fmt.Println("\n=== §6 acceptance results ===")
	allPass := true
	for n := 1; n <= 9; n++ {
		r, ok := byN[n]
		if !ok {
			r = check{n: n, name: "(not run)", pass: false, detail: "check did not run"}
		}
		status := "PASS"
		if !r.pass {
			status = "FAIL"
			allPass = false
		}
		fmt.Printf("%d. [%s] %-24s %s\n", n, status, r.name, r.detail)
	}
	if allPass {
		fmt.Println("\nALL CHECKS PASSED")
		return 0
	}
	fmt.Println("\nSOME CHECKS FAILED")
	return 1
}
