package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Severity of a single posture check.
type Severity int

const (
	SevOK Severity = iota
	SevWarn
	SevFail
)

func (s Severity) String() string {
	switch s {
	case SevOK:
		return "ok"
	case SevWarn:
		return "warn"
	default:
		return "fail"
	}
}

// PostureCheck is one line item in the security assessment.
type PostureCheck struct {
	Name   string
	Status Severity
	Detail string
}

// Level is the overall headline posture.
type Level int

const (
	LevelUnprotected Level = iota // integrity broken, or not running / not enrolled
	LevelAtRisk                   // an unresolved detection alert exists
	LevelWarning                  // coverage gaps: stale baseline, unenrolled installs
	LevelProtected                // everything green
)

func (l Level) String() string {
	switch l {
	case LevelProtected:
		return "PROTECTED"
	case LevelWarning:
		return "NEEDS ATTENTION"
	case LevelAtRisk:
		return "AT RISK"
	default:
		return "UNPROTECTED"
	}
}

// Posture is the full security assessment shown in the dashboard, tray and
// `status` output.
type Posture struct {
	Level              Level
	Score              int // 0..100
	Checks             []PostureCheck
	Running            bool
	StartedAt          time.Time
	LastPoll           time.Time
	Polls              uint64
	PollSecs           int
	Identities         int
	Alerts             int
	LastAlert          *Alert
	UnenrolledInstalls []string // Claude binaries on disk not in the baseline
	StaleBinaries      []string // enrolled binaries whose hash changed (updated?)
	IntegrityOK        bool
	GeneratedAt        time.Time
}

// ComputePosture assembles the current security posture. It never returns
// an error for a missing/broken baseline — that condition IS the posture
// (Unprotected). A non-nil error means the paths themselves are unusable.
func ComputePosture(paths Paths) *Posture {
	p := &Posture{GeneratedAt: time.Now()}
	hc := newHashCache()

	key, keyErr := LoadKey(paths.Key)
	if keyErr != nil {
		p.add("Key file", SevFail, "HMAC key missing — run enroll/setup")
		p.Level = LevelUnprotected
		p.Score = 0
		return p
	}

	// --- Integrity: baseline HMAC, journal chain, daemon self-hash ---
	baseline, bErr := LoadBaseline(paths.DB, key)
	integrityOK := true
	if bErr != nil {
		p.add("Baseline integrity", SevFail, "HMAC invalid — database modified outside seatguard")
		integrityOK = false
	} else {
		p.add("Baseline integrity", SevOK, fmt.Sprintf("HMAC valid, %d enrolled identities", len(baseline.Identities)))
		p.Identities = len(baseline.Identities)
	}

	entries, jErr := VerifyJournal(paths.Journal, key)
	if jErr != nil {
		p.add("Journal chain", SevFail, "hash chain broken — a record was rewritten")
		integrityOK = false
	} else {
		p.add("Journal chain", SevOK, fmt.Sprintf("append-only chain intact (%d records)", len(entries)))
	}

	if self, err := os.Executable(); err == nil && baseline != nil {
		if resolved, rerr := filepath.EvalSymlinks(self); rerr == nil {
			self = resolved
		}
		if h, _, herr := HashFile(self); herr == nil {
			if baseline.DaemonHash != "" && h != baseline.DaemonHash {
				p.add("Daemon self-check", SevFail, "seatguard binary hash differs from enrolled")
				integrityOK = false
			} else {
				p.add("Daemon self-check", SevOK, "binary matches enrolled hash")
			}
		}
	}
	p.IntegrityOK = integrityOK

	// --- Daemon liveness ---
	if st, err := readState(paths.State); err == nil {
		p.Running = time.Since(st.LastPoll) < time.Duration(maxInt(st.PollSecs, 1)*10)*time.Second
		p.StartedAt, p.LastPoll = st.StartedAt, st.LastPoll
		p.Polls, p.PollSecs = st.Polls, st.PollSecs
		if p.Running {
			p.add("Monitor daemon", SevOK, fmt.Sprintf("running, %d polls, last %s ago",
				st.Polls, time.Since(st.LastPoll).Round(time.Second)))
		} else {
			p.add("Monitor daemon", SevFail, "not running — start protection to monitor")
		}
	} else {
		p.add("Monitor daemon", SevFail, "never started")
	}

	// --- Credential coverage ---
	if baseline != nil {
		present, missing := 0, 0
		for _, c := range baseline.CredPaths {
			if _, err := os.Stat(c); err == nil {
				present++
			} else {
				missing++
			}
		}
		switch {
		case present == 0:
			p.add("Credential watch", SevWarn, "no credential files found on disk yet")
		default:
			p.add("Credential watch", SevOK, fmt.Sprintf("%d credential file(s) watched", present))
		}
	}

	// --- Alerts ---
	for i := range entries {
		if entries[i].Type != "alert" {
			continue
		}
		p.Alerts++
		var a Alert
		if json.Unmarshal(entries[i].Data, &a) == nil {
			ac := a
			p.LastAlert = &ac
		}
	}
	if p.Alerts > 0 {
		det := fmt.Sprintf("%d detection alert(s) recorded", p.Alerts)
		if p.LastAlert != nil {
			det = fmt.Sprintf("%d alert(s); latest: %s reading %s", p.Alerts, filepath.Base(p.LastAlert.ExePath), p.LastAlert.Target)
		}
		p.add("Detections", SevFail, det)
	} else {
		p.add("Detections", SevOK, "no unauthorized access detected")
	}

	// --- Coverage gaps: unenrolled Claude installs & stale binaries ---
	// These two checks are expensive (DiscoverInstalls may spawn the OS
	// package manager; freshness re-hashes every enrolled binary), so the
	// result is cached: a 1.5s dashboard refresh must not re-scan the disk.
	if baseline != nil {
		unenrolled, stale := coverage(baseline, hc)
		p.UnenrolledInstalls, p.StaleBinaries = unenrolled, stale
		if n := len(unenrolled); n > 0 {
			p.add("Install coverage", SevWarn, fmt.Sprintf("%d Claude binary(ies) on disk not enrolled — will look foreign", n))
		} else {
			p.add("Install coverage", SevOK, "all discovered Claude installs are enrolled")
		}
		if n := len(stale); n > 0 {
			p.add("Baseline freshness", SevWarn, fmt.Sprintf("%d enrolled binary(ies) changed on disk — likely a Claude update; re-run setup", n))
		} else if len(baseline.Identities) > 0 {
			p.add("Baseline freshness", SevOK, "all enrolled binaries unchanged")
		}
	}

	p.finalize()
	return p
}

// coverage computes (unenrolled installs, stale binaries), cached for 30s
// so live dashboards/tray refreshes don't repeatedly scan the disk or
// spawn the package manager.
var (
	covMu         sync.Mutex
	covAt         time.Time
	covUnenrolled []string
	covStale      []string
)

func coverage(baseline *Baseline, hc *hashCache) (unenrolled, stale []string) {
	covMu.Lock()
	defer covMu.Unlock()
	if !covAt.IsZero() && time.Since(covAt) < 30*time.Second {
		return covUnenrolled, covStale
	}

	enrolled := map[string]bool{}
	for _, id := range baseline.Identities {
		enrolled[normPath(id.Path)] = true
	}
	var un []string
	for _, f := range DiscoverInstalls() {
		if !enrolled[normPath(f.Path)] {
			un = append(un, f.Path)
		}
	}
	var st []string
	for _, id := range baseline.Identities {
		h, err := hc.Hash(id.Path)
		if err != nil {
			st = append(st, id.Path+" (missing)")
			continue
		}
		if h != id.SHA256 {
			st = append(st, id.Path)
		}
	}
	covUnenrolled, covStale, covAt = un, st, time.Now()
	return un, st
}

func (p *Posture) add(name string, sev Severity, detail string) {
	p.Checks = append(p.Checks, PostureCheck{Name: name, Status: sev, Detail: detail})
}

// finalize derives the score and headline level from the checks.
func (p *Posture) finalize() {
	score := 100
	fail, warn := 0, 0
	for _, c := range p.Checks {
		switch c.Status {
		case SevFail:
			fail++
			score -= 22
		case SevWarn:
			warn++
			score -= 8
		}
	}
	if score < 0 {
		score = 0
	}
	p.Score = score

	switch {
	case !p.IntegrityOK || !p.Running || p.Identities == 0:
		p.Level = LevelUnprotected
	case p.Alerts > 0:
		p.Level = LevelAtRisk
	case warn > 0:
		p.Level = LevelWarning
	default:
		p.Level = LevelProtected
	}
}

// stateSnapshot mirrors the daemon's state.json.
type stateSnapshot struct {
	PID       int       `json:"pid"`
	StartedAt time.Time `json:"started_at"`
	LastPoll  time.Time `json:"last_poll"`
	Polls     uint64    `json:"polls"`
	Alerts    uint64    `json:"alert_count"`
	PollSecs  int       `json:"poll_secs"`
}

func readState(path string) (stateSnapshot, error) {
	var st stateSnapshot
	raw, err := os.ReadFile(path)
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(raw, &st)
}

func normPath(p string) string {
	c := filepath.Clean(p)
	if runtime.GOOS == "windows" {
		return strings.ToLower(c)
	}
	return c
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
