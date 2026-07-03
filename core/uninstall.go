package core

import (
	"os"
	"path/filepath"

	"seatguard/platform"
)

// UninstallResult reports what Uninstall removed.
type UninstallResult struct {
	Removed          []string          // files successfully deleted
	Failed           map[string]string // path -> error for files that could not be deleted
	AutostartRemoved bool
}

// Uninstall removes seatguard's autostart entry and every data file it owns
// (baseline, HMAC key, journal + rotated archive, state, and the POSIX lock).
// It deliberately does NOT delete the seatguard executable — a running program
// cannot reliably remove its own binary — so the caller should tell the user
// they can delete it manually.
//
// Stop any running daemon before calling this: otherwise the daemon may
// recreate the state/journal files right after they are deleted.
func Uninstall(paths Paths) UninstallResult {
	res := UninstallResult{Failed: map[string]string{}}

	if err := platform.RemoveAutostart("seatguard"); err == nil {
		res.AutostartRemoved = true
	}

	targets := []string{
		paths.State,
		paths.Journal,
		paths.Journal + ".1", // rotated archive
		paths.DB,
		paths.DB + ".lock", // POSIX single-instance lock file
		paths.Key,
	}
	for _, t := range targets {
		switch err := os.Remove(t); {
		case err == nil:
			res.Removed = append(res.Removed, t)
		case os.IsNotExist(err):
			// already gone — not a failure
		default:
			res.Failed[t] = err.Error()
		}
	}

	// Best effort: drop now-empty parent directories (os.Remove only succeeds
	// on an empty dir, so shared/occupied locations are left untouched).
	for _, d := range parentDirs(paths) {
		_ = os.Remove(d)
	}
	return res
}

func parentDirs(paths Paths) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range []string{paths.DB, paths.Journal, paths.State, paths.Key} {
		d := filepath.Dir(f)
		if d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}
