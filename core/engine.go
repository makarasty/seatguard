package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"seatguard/platform"
)

// Engine is the polling detection loop (Phase 1). Event-driven backends
// (eBPF / ETW / ESF) are explicitly out of scope for this phase.
type Engine struct {
	Backend  platform.Backend
	Baseline *Baseline
	Journal  *Journal
	Stderr   *os.File
	Paths    Paths

	ips     *ipSet
	hashes  *hashCache
	alerted map[string]struct{} // dedup: exactly one alert per (signal, pid, start_time, target-kind)
	polls   uint64
	nAlerts uint64
	started time.Time
}

// state.json contents, consumed by `seatguard status`.
type daemonState struct {
	PID        int       `json:"pid"`
	StartedAt  time.Time `json:"started_at"`
	LastPoll   time.Time `json:"last_poll"`
	Polls      uint64    `json:"polls"`
	AlertCount uint64    `json:"alert_count"`
	PollSecs   int       `json:"poll_secs"`
}

// Run executes the poll loop until ctx is cancelled.
func (e *Engine) Run(ctx context.Context) error {
	e.hashes = newHashCache()
	e.alerted = make(map[string]struct{})
	e.ips = newIPSet(e.Baseline.APIIPs, e.Baseline.APIHosts)
	e.started = time.Now()

	poll := time.Duration(e.Baseline.PollSecs) * time.Second
	if poll <= 0 {
		poll = 4 * time.Second
	}
	// Keep the heap tight: the idle-RSS budget is 15 MB.
	debug.SetGCPercent(50)

	e.Journal.Append("daemon_start", map[string]any{
		"pid": os.Getpid(), "poll_secs": int(poll.Seconds()),
	})
	e.writeState(poll)

	tick := time.NewTicker(poll)
	defer tick.Stop()
	dnsTick := time.NewTicker(5 * time.Minute)
	defer dnsTick.Stop()
	memTick := time.NewTicker(30 * time.Second)
	defer memTick.Stop()

	for {
		select {
		case <-ctx.Done():
			e.Journal.Append("daemon_stop", map[string]any{"pid": os.Getpid()})
			return nil
		case <-dnsTick.C:
			if len(e.Baseline.APIHosts) > 0 {
				e.ips.refresh(ctx)
			}
		case <-memTick.C:
			debug.FreeOSMemory()
		case <-tick.C:
			e.pollOnce()
			e.polls++
			if e.polls%5 == 0 {
				e.writeState(poll)
			}
		}
	}
}

func (e *Engine) writeState(poll time.Duration) {
	st := daemonState{
		PID:        os.Getpid(),
		StartedAt:  e.started,
		LastPoll:   time.Now(),
		Polls:      e.polls,
		AlertCount: e.nAlerts,
		PollSecs:   int(poll.Seconds()),
	}
	raw, err := json.MarshalIndent(&st, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(e.Paths.State, raw, 0o600)
}

// pollOnce takes one snapshot of both signals.
func (e *Engine) pollOnce() {
	// Signal A: who holds a credential file open.
	for _, cred := range e.Baseline.CredPaths {
		if _, err := os.Stat(cred); err != nil {
			continue
		}
		holders, err := e.Backend.HoldersOfFile(cred)
		if err != nil {
			continue // transient; next tick retries
		}
		for _, p := range holders {
			e.judge(p, SignalCredRead, cred)
		}
	}
	// Signal B: who has an established connection to an Anthropic endpoint.
	conns, err := e.Backend.EstablishedTo(e.ips.snapshot())
	if err == nil {
		for _, c := range conns {
			e.judge(c.Proc, SignalAPIEgress, fmt.Sprintf("%s:%d", c.RemoteIP, c.RemotePort))
		}
	}
}

// judge decides legitimacy for one observed process and alerts if rogue.
func (e *Engine) judge(p platform.ProcessInfo, signal, target string) {
	// Dedup on the stable handle, not the ephemeral PID alone.
	key := fmt.Sprintf("%s|%d|%d", signal, p.PID, p.StartTime)
	if _, seen := e.alerted[key]; seen {
		return
	}
	legit, hash, reason := e.isLegit(p)
	if legit {
		return
	}
	e.alerted[key] = struct{}{}
	e.nAlerts++
	emitAlert(e.Journal, e.Stderr, &Alert{
		Signal:    signal,
		ExePath:   p.ExePath,
		ExeSHA256: hash,
		PID:       p.PID,
		StartTime: p.StartTime,
		Target:    target,
		Reason:    reason,
	})
}

// isLegit implements the identity rule: legit ⇔ enrolled path AND enrolled
// content hash (plus, for interpreters like node, main script inside an
// enrolled install dir). Never by process name.
func (e *Engine) isLegit(p platform.ProcessInfo) (ok bool, hash string, reason string) {
	hash, hashErr := e.hashes.Hash(p.ExePath)
	for i := range e.Baseline.Identities {
		id := &e.Baseline.Identities[i]
		if !SamePath(id.Path, p.ExePath) {
			continue
		}
		if hashErr != nil {
			return false, "", fmt.Sprintf("enrolled path but binary unreadable for hashing: %v", hashErr)
		}
		if hash != id.SHA256 {
			return false, hash, "binary at enrolled path has different hash (replaced?)"
		}
		if id.Interpreter {
			return e.judgeInterpreter(p, hash)
		}
		return true, hash, ""
	}
	return false, hash, "binary not in enrolled baseline"
}

// judgeInterpreter: a real node binary is only legit when its main script
// lives inside an enrolled Claude install dir.
func (e *Engine) judgeInterpreter(p platform.ProcessInfo, hash string) (bool, string, string) {
	argv, err := e.Backend.Cmdline(p.PID)
	if err != nil || len(argv) < 2 {
		// Deliberate fail-open for the interpreter *sub*-rule only: this
		// branch is reached solely after the binary already matched an
		// enrolled interpreter by path AND hash, so an arbitrary rogue
		// "node" is still caught upstream by the hash check. When we
		// merely cannot read the script argument (permissions, races), we
		// journal a warning rather than flood alerts on legitimate node
		// processes whose cmdline is momentarily unreadable.
		e.Journal.Append("warning", map[string]any{
			"msg": "interpreter cmdline unavailable; skipping script check",
			"pid": p.PID, "exe": p.ExePath,
		})
		return true, hash, ""
	}
	script := argv[1]
	if !filepath.IsAbs(script) {
		return true, hash, "" // relative script path: cannot attribute reliably in Phase 1
	}
	for _, dir := range e.Baseline.InstallDirs {
		if strings.HasPrefix(strings.ToLower(filepath.Clean(script)), strings.ToLower(filepath.Clean(dir))) {
			return true, hash, ""
		}
	}
	return false, hash, fmt.Sprintf("enrolled interpreter running foreign script %s", script)
}
