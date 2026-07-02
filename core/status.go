package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"seatguard/platform"
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

	key, keyErr := LoadKey(paths.Key)
	if keyErr != nil {
		p.add("Key file", SevFail, "HMAC key missing — run enroll/setup")
		p.Level = LevelUnprotected
		p.Score = 0
		return p
	}

	// --- Integrity: baseline HMAC, journal chain, daemon self-hash ---
	// All three are cached so a 1.5s dashboard refresh doesn't re-read+re-MAC
	// the DB and whole journal or re-hash the daemon's own 3+ MB binary every
	// frame (see the cache helpers below).
	baseline, bErr := cachedBaseline(paths, key)
	integrityOK := true
	if bErr != nil {
		p.add("Baseline integrity", SevFail, "HMAC invalid — database modified outside seatguard")
		integrityOK = false
	} else {
		p.add("Baseline integrity", SevOK, fmt.Sprintf("HMAC valid, %d enrolled identities", len(baseline.Identities)))
		p.Identities = len(baseline.Identities)
	}

	jstat := cachedJournalStat(paths, key)
	if jstat.err != nil {
		p.add("Journal chain", SevFail, "hash chain broken — a record was rewritten")
		integrityOK = false
	} else {
		p.add("Journal chain", SevOK, fmt.Sprintf("append-only chain intact (%d records)", jstat.records))
	}

	if baseline != nil {
		if h, herr := cachedSelfHash(); herr == nil {
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
	if st, err := ReadDaemonState(paths.State); err == nil {
		p.Running = st.Running()
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
		present := 0
		for _, c := range baseline.CredPaths {
			if _, err := os.Stat(c); err == nil {
				present++
			}
		}
		if present == 0 {
			p.add("Credential watch", SevWarn, "no credential files found on disk yet")
		} else {
			p.add("Credential watch", SevOK, fmt.Sprintf("%d credential file(s) watched", present))
		}
	}

	// --- Alerts (from the cached journal scan) ---
	p.Alerts = jstat.alertCount
	p.LastAlert = jstat.lastAlert
	if p.Alerts > 0 {
		det := fmt.Sprintf("%d detection alert(s) recorded", p.Alerts)
		if p.LastAlert != nil {
			det = fmt.Sprintf("%d alert(s); latest: %s reading %s", p.Alerts, filepath.Base(p.LastAlert.ExePath), p.LastAlert.Target)
		}
		p.add("Detections", SevFail, det)
	} else {
		p.add("Detections", SevOK, "no unauthorized access detected")
	}

	// --- Privilege / DB location (tamper-evidence assumptions) ---
	// The DB must be owned by a privileged account and live outside the
	// user's home for tamper-evidence to mean anything. We can't enforce
	// ownership without breaking unprivileged dev use, so we surface it.
	priv := platform.IsPrivileged()
	home, _ := os.UserHomeDir()
	dbInHome := home != "" && strings.HasPrefix(NormPath(paths.DB), NormPath(home))
	switch {
	case !priv && dbInHome:
		p.add("Privilege", SevWarn, "unprivileged and DB under your home — anyone as you can replace it; run elevated with the default DB path")
	case !priv:
		p.add("Privilege", SevWarn, "running unprivileged — DB/journal not owner-protected; run elevated for full tamper-evidence")
	case dbInHome:
		p.add("Privilege", SevWarn, "DB is under your home directory — use the default (privileged) location")
	default:
		p.add("Privilege", SevOK, "privileged; DB outside home directory")
	}

	// --- Coverage gaps: unenrolled Claude installs & stale binaries ---
	// These two checks are expensive (DiscoverInstalls may spawn the OS
	// package manager; freshness re-hashes every enrolled binary), so the
	// result is cached: a 1.5s dashboard refresh must not re-scan the disk.
	if baseline != nil {
		unenrolled, stale := coverage(baseline)
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

// covHash persists across coverage() calls so the once-per-30s freshness
// re-hash of enrolled binaries is stat-only after the first pass.
var covHash = newHashCache()

func coverage(baseline *Baseline) (unenrolled, stale []string) {
	covMu.Lock()
	defer covMu.Unlock()
	if !covAt.IsZero() && time.Since(covAt) < 30*time.Second {
		return covUnenrolled, covStale
	}

	enrolled := map[string]bool{}
	for _, id := range baseline.Identities {
		enrolled[NormPath(id.Path)] = true
	}
	var un []string
	for _, f := range DiscoverInstalls() {
		if !enrolled[NormPath(f.Path)] {
			un = append(un, f.Path)
		}
	}
	var st []string
	for _, id := range baseline.Identities {
		h, err := covHash.Hash(id.Path)
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

// --- hot-path caches for the live viewers ---------------------------------
//
// The dashboard (1.5s) and tray (3s) call ComputePosture continuously. These
// caches turn the per-frame cost from "re-read+re-MAC the DB and the whole
// journal, and re-hash the daemon's own binary" into a few os.Stat calls when
// nothing changed. The authoritative full checks still run in `seatguard
// verify` and at daemon startup.

var (
	postureMu sync.Mutex

	selfHashVal, selfHashKey string

	blVal *Baseline
	blErr error
	blKey string

	jrnlStatCache journalStat
	jrnlKey       int64 = -1
)

// fileKey is a cheap change token: modtime + size. Empty on stat error.
func fileKey(path string) string {
	st, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d|%d", st.ModTime().UnixNano(), st.Size())
}

// cachedSelfHash hashes the daemon's own binary once per process. The running
// executable cannot change on disk without changing its modtime/size, so
// after the first call this is a single os.Stat.
func cachedSelfHash() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, rerr := filepath.EvalSymlinks(self); rerr == nil {
		self = resolved
	}
	k := fileKey(self)
	postureMu.Lock()
	defer postureMu.Unlock()
	if k != "" && k == selfHashKey && selfHashVal != "" {
		return selfHashVal, nil
	}
	h, _, herr := HashFile(self)
	if herr != nil {
		return "", herr
	}
	selfHashVal, selfHashKey = h, k
	return h, nil
}

// cachedBaseline re-loads+re-verifies the DB only when its modtime/size change.
func cachedBaseline(paths Paths, key []byte) (*Baseline, error) {
	k := fileKey(paths.DB)
	postureMu.Lock()
	defer postureMu.Unlock()
	if k != "" && k == blKey && (blVal != nil || blErr != nil) {
		return blVal, blErr
	}
	b, err := LoadBaseline(paths.DB, key)
	blVal, blErr, blKey = b, err, k
	return b, err
}

type journalStat struct {
	records    int
	alertCount int
	lastAlert  *Alert
	err        error
}

// cachedJournalStat re-verifies the journal only when its size changes. The
// journal grows only when the daemon appends a record, so between events this
// is a single os.Stat. (A same-size mid-file rewrite is still caught by
// `seatguard verify` and at startup — the authoritative full checks.)
func cachedJournalStat(paths Paths, key []byte) journalStat {
	var size int64 = -1
	if st, err := os.Stat(paths.Journal); err == nil {
		size = st.Size()
	}
	postureMu.Lock()
	defer postureMu.Unlock()
	if size >= 0 && size == jrnlKey {
		return jrnlStatCache
	}
	entries, verr := VerifyJournal(paths.Journal, key)
	js := journalStat{records: len(entries), err: verr}
	for i := range entries {
		if entries[i].Type != "alert" {
			continue
		}
		js.alertCount++
		var a Alert
		if json.Unmarshal(entries[i].Data, &a) == nil {
			ac := a
			js.lastAlert = &ac
		}
	}
	jrnlStatCache, jrnlKey = js, size
	return js
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
