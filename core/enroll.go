package core

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"seatguard/platform"
)

// EnrollOptions configures baseline creation.
type EnrollOptions struct {
	ExtraBinaries []string // explicit binaries to enroll (e.g. a simulated Claude)
	InstallDirs   []string // explicit Claude install dirs
	CredPaths     []string
	APIHosts      []string
	APIIPs        []string
	PollSecs      int
	NoDiscover    bool // skip auto-discovery (hermetic tests)
}

// Enroll builds and persists the protected baseline. It requires at least
// one identity — an empty baseline would make every later verdict "rogue".
func Enroll(paths Paths, be platform.Backend, opts EnrollOptions) (*Baseline, error) {
	key, err := EnsureKey(paths.Key)
	if err != nil {
		return nil, err
	}

	b := &Baseline{
		Version:   1,
		CreatedAt: time.Now().UTC(),
		CredPaths: opts.CredPaths,
		APIHosts:  opts.APIHosts,
		APIIPs:    opts.APIIPs,
		PollSecs:  opts.PollSecs,
	}
	if len(b.CredPaths) == 0 {
		b.CredPaths = DefaultCredPaths()
	}
	if b.PollSecs <= 0 {
		b.PollSecs = 4
	}

	seen := map[string]bool{}
	add := func(path string, interpreter bool) error {
		abs, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		if resolved, err := filepath.EvalSymlinks(abs); err == nil {
			abs = resolved
		}
		if seen[abs] {
			return nil
		}
		h, size, err := HashFile(abs)
		if err != nil {
			return fmt.Errorf("enroll %s: %w", abs, err)
		}
		seen[abs] = true
		sig, _ := platform.SignerOf(abs) // best effort; "unsigned" when absent
		if sig == "" {
			sig = "unsigned"
		}
		b.Identities = append(b.Identities, Identity{
			Path:        abs,
			SHA256:      h,
			Size:        size,
			Signature:   sig,
			Interpreter: interpreter,
		})
		return nil
	}

	for _, p := range opts.ExtraBinaries {
		if err := add(p, false); err != nil {
			return nil, err
		}
	}
	for _, d := range opts.InstallDirs {
		abs, err := filepath.Abs(d)
		if err == nil {
			b.InstallDirs = append(b.InstallDirs, abs)
		}
	}

	if !opts.NoDiscover {
		discoverClaude(b, add)
	}

	if len(b.Identities) == 0 {
		return nil, fmt.Errorf("no Claude installation found and no --claude-path given; nothing to enroll")
	}

	// Capture the stable (pid, start_time) handle of any live instance of
	// each enrolled binary. Best effort — enrolled software need not run.
	if be != nil {
		for i := range b.Identities {
			inst, err := be.InstancesOf(b.Identities[i].Path)
			if err == nil && len(inst) > 0 {
				b.Identities[i].ObservedPID = inst[0].PID
				b.Identities[i].ObservedStartTime = inst[0].StartTime
			}
		}
	}

	// The daemon verifies itself at startup against this hash.
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	selfHash, _, err := HashFile(self)
	if err != nil {
		return nil, fmt.Errorf("hash own binary: %w", err)
	}
	b.DaemonHash = selfHash

	if err := SaveBaseline(paths.DB, key, b); err != nil {
		return nil, err
	}
	j, err := OpenJournal(paths.Journal, key)
	if err != nil {
		return nil, err
	}
	if err := j.Append("enrolled", map[string]any{
		"identities": len(b.Identities), "cred_paths": b.CredPaths,
	}); err != nil {
		return nil, err
	}
	return b, nil
}

// discoverClaude enrolls what a real machine typically has: the claude
// launcher, the node binary it runs under, and the install dirs holding
// the CLI's JS entrypoints.
func discoverClaude(b *Baseline, add func(string, bool) error) {
	if p, err := exec.LookPath("claude"); err == nil {
		add(p, false)
	}
	if p, err := exec.LookPath("node"); err == nil {
		add(p, true)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	candidates := []string{
		filepath.Join(home, ".claude", "local"),
		filepath.Join(home, ".local", "share", "claude"),
	}
	if runtime.GOOS == "windows" {
		candidates = append(candidates, filepath.Join(home, "AppData", "Roaming", "npm", "node_modules", "@anthropic-ai", "claude-code"))
	} else {
		candidates = append(candidates, "/usr/local/lib/node_modules/@anthropic-ai/claude-code")
	}
	for _, d := range candidates {
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			b.InstallDirs = append(b.InstallDirs, d)
		}
	}
}
