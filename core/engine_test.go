package core

import (
	"os"
	"path/filepath"
	"testing"

	"seatguard/platform"
)

// TestIsLegit pins the core detection invariant: a process is legitimate
// only when its binary matches an enrolled path AND content hash — never by
// name. This is the unit-level counterpart to §6.5 (no false positives) and
// §6.9 (identity, not name).
func TestIsLegit(t *testing.T) {
	dir := t.TempDir()
	claude := filepath.Join(dir, "claude.exe")
	if err := os.WriteFile(claude, []byte("CLAUDE-BINARY-V1"), 0o755); err != nil {
		t.Fatal(err)
	}
	h, _, err := HashFile(claude)
	if err != nil {
		t.Fatal(err)
	}
	eng := &Engine{
		Baseline: &Baseline{Identities: []Identity{{Path: claude, SHA256: h}}},
		hashes:   newHashCache(),
	}

	// Exact match → legit.
	if ok, _, reason := eng.isLegit(platform.ProcessInfo{ExePath: claude}); !ok {
		t.Fatalf("enrolled binary judged rogue: %s", reason)
	}

	// Same path, different bytes (replaced/trojaned) → rogue.
	if err := os.WriteFile(claude, []byte("TROJANED-DIFFERENT-SIZE"), 0o755); err != nil {
		t.Fatal(err)
	}
	if ok, _, _ := eng.isLegit(platform.ProcessInfo{ExePath: claude}); ok {
		t.Fatal("replaced binary at enrolled path judged legit")
	}

	// Different path, even if named like a legit process → rogue.
	rogue := filepath.Join(dir, "node.exe")
	if err := os.WriteFile(rogue, []byte("ROGUE"), 0o755); err != nil {
		t.Fatal(err)
	}
	if ok, _, _ := eng.isLegit(platform.ProcessInfo{ExePath: rogue}); ok {
		t.Fatal("unenrolled binary judged legit")
	}
}
