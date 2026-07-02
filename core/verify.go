package core

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// VerifyAll checks (1) baseline HMAC, (2) journal hash chain, (3) the
// daemon binary against its enrolled hash. Reports every failure to w and
// returns ErrIntegrity-wrapped error if anything is off. Fail-safe: callers
// must treat any error as "do not operate".
func VerifyAll(paths Paths, w io.Writer) (*Baseline, error) {
	key, err := LoadKey(paths.Key)
	if err != nil {
		fmt.Fprintf(w, "FAIL key: %v\n", err)
		return nil, err
	}
	var firstErr error

	b, err := LoadBaseline(paths.DB, key)
	if err != nil {
		fmt.Fprintf(w, "FAIL baseline: %v\n", err)
		firstErr = err
	} else {
		fmt.Fprintf(w, "ok baseline: %d identities, HMAC valid\n", len(b.Identities))
	}

	if _, err := VerifyJournal(paths.Journal, key); err != nil {
		fmt.Fprintf(w, "FAIL journal: %v\n", err)
		if firstErr == nil {
			firstErr = err
		}
	} else {
		fmt.Fprintln(w, "ok journal: hash chain intact")
	}

	if b != nil {
		self, err := os.Executable()
		if err == nil {
			if resolved, rerr := filepath.EvalSymlinks(self); rerr == nil {
				self = resolved
			}
			h, _, herr := HashFile(self)
			switch {
			case herr != nil:
				fmt.Fprintf(w, "FAIL self-check: %v\n", herr)
				if firstErr == nil {
					firstErr = fmt.Errorf("%w: cannot hash own binary: %v", ErrIntegrity, herr)
				}
			case h != b.DaemonHash:
				err := fmt.Errorf("%w: seatguard binary hash differs from enrolled hash — binary was replaced or DB is stale", ErrIntegrity)
				fmt.Fprintf(w, "FAIL self-check: %v\n", err)
				if firstErr == nil {
					firstErr = err
				}
			default:
				fmt.Fprintln(w, "ok self-check: daemon binary matches enrolled hash")
			}
		}
	}
	return b, firstErr
}
