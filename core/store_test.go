package core

import (
	"os"
	"path/filepath"
	"testing"
)

func testPaths(t *testing.T) (Paths, []byte) {
	t.Helper()
	dir := t.TempDir()
	p := Paths{
		DB:      filepath.Join(dir, "db", "baseline.db"),
		Key:     filepath.Join(dir, "keys", "hmac.key"), // separate dir, per §3
		Journal: filepath.Join(dir, "db", "journal.log"),
		State:   filepath.Join(dir, "db", "state.json"),
	}
	key, err := EnsureKey(p.Key)
	if err != nil {
		t.Fatalf("EnsureKey: %v", err)
	}
	return p, key
}

func TestBaselineRoundTrip(t *testing.T) {
	p, key := testPaths(t)
	in := &Baseline{
		Version:    1,
		Identities: []Identity{{Path: "/usr/bin/node", SHA256: "abc", Size: 10}},
		CredPaths:  []string{"/home/u/.claude/.credentials.json"},
		PollSecs:   4,
	}
	if err := SaveBaseline(p.DB, key, in); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}
	out, err := LoadBaseline(p.DB, key)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	if len(out.Identities) != 1 || out.Identities[0].Path != "/usr/bin/node" {
		t.Fatalf("round-trip mismatch: %+v", out.Identities)
	}
}

func TestBaselineTamperDetected(t *testing.T) {
	p, key := testPaths(t)
	if err := SaveBaseline(p.DB, key, &Baseline{Version: 1, Identities: []Identity{{Path: "x", SHA256: "y"}}}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p.DB)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte well inside the file and write it back.
	raw[len(raw)/2] ^= 0xff
	if err := os.WriteFile(p.DB, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBaseline(p.DB, key); err == nil {
		t.Fatal("expected integrity error on tampered DB, got nil")
	}
}

func TestBaselineWrongKeyRejected(t *testing.T) {
	p, key := testPaths(t)
	if err := SaveBaseline(p.DB, key, &Baseline{Version: 1, Identities: []Identity{{Path: "x", SHA256: "y"}}}); err != nil {
		t.Fatal(err)
	}
	wrong := make([]byte, len(key))
	copy(wrong, key)
	wrong[0] ^= 0x01
	if _, err := LoadBaseline(p.DB, wrong); err == nil {
		t.Fatal("expected HMAC mismatch with wrong key, got nil")
	}
}
