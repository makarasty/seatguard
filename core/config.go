package core

import (
	"os"
	"path/filepath"
	"runtime"
)

// Paths bundles the file locations seatguard operates on. Defaults put
// the DB outside any user home directory, owned by a privileged user,
// and the HMAC key in a *different* directory from the DB so that write
// access to one location is not enough to forge both.
type Paths struct {
	DB      string
	Key     string
	Journal string
	State   string
}

// Args returns the four location flags in CLI form, so callers that spawn or
// re-invoke seatguard don't hand-build (and risk desyncing) the slice.
func (p Paths) Args() []string {
	return []string{"--db", p.DB, "--key", p.Key, "--journal", p.Journal, "--state", p.State}
}

// DefaultPaths returns per-OS privileged locations.
func DefaultPaths() Paths {
	switch runtime.GOOS {
	case "windows":
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return Paths{
			DB:      filepath.Join(pd, "seatguard", "baseline.db"),
			Key:     filepath.Join(pd, "seatguard-key", "hmac.key"),
			Journal: filepath.Join(pd, "seatguard", "journal.log"),
			State:   filepath.Join(pd, "seatguard", "state.json"),
		}
	case "darwin":
		return Paths{
			DB:      "/Library/Application Support/seatguard/baseline.db",
			Key:     "/etc/seatguard/hmac.key",
			Journal: "/Library/Application Support/seatguard/journal.log",
			State:   "/Library/Application Support/seatguard/state.json",
		}
	default: // linux and friends
		return Paths{
			DB:      "/var/lib/seatguard/baseline.db",
			Key:     "/etc/seatguard/hmac.key",
			Journal: "/var/lib/seatguard/journal.log",
			State:   "/var/lib/seatguard/state.json",
		}
	}
}

// DefaultCredPaths returns the well-known Claude credential locations.
func DefaultCredPaths() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return []string{
		filepath.Join(home, ".claude", ".credentials.json"),
		filepath.Join(home, ".claude.json"),
	}
}

// DefaultAPIHosts are resolved at runtime — Cloudflare rotates the IPs,
// so hardcoding addresses would silently rot.
func DefaultAPIHosts() []string {
	return []string{"api.anthropic.com", "claude.ai"}
}
