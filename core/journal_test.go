package core

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestJournalAppendAndVerify(t *testing.T) {
	p, key := testPaths(t)
	j, err := OpenJournal(p.Journal, key)
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	for i := 0; i < 5; i++ {
		if err := j.Append("alert", map[string]any{"n": i}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	entries, err := VerifyJournal(p.Journal, key)
	if err != nil {
		t.Fatalf("VerifyJournal on intact chain: %v", err)
	}
	if len(entries) != 5 {
		t.Fatalf("want 5 entries, got %d", len(entries))
	}
}

func TestJournalRotationPreservesChain(t *testing.T) {
	p, key := testPaths(t)
	j, err := OpenJournal(p.Journal, key)
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	j.SetMaxBytes(2 << 10) // 2 KiB — small so it rotates quickly

	for i := 0; i < 200; i++ {
		if err := j.Append("alert", map[string]any{"n": i, "pad": "xxxxxxxxxxxxxxxxxxxxxxxxxxxx"}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}

	// An archive must have been created, and the live file must be smaller
	// than the total written (i.e. rotation actually happened).
	if _, err := os.Stat(p.Journal + ".1"); err != nil {
		t.Fatalf("expected archive %s.1 after rotation: %v", p.Journal, err)
	}

	// The current segment must verify (chain seeded from the rotated genesis).
	entries, err := VerifyJournal(p.Journal, key)
	if err != nil {
		t.Fatalf("VerifyJournal after rotation: %v", err)
	}
	if len(entries) == 0 || entries[0].Type != "rotated" {
		t.Fatalf("expected a 'rotated' genesis as first record, got %+v", entries)
	}

	// A fresh Journal reopened on the rotated file must continue the chain.
	j2, err := OpenJournal(p.Journal, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := j2.Append("alert", map[string]any{"n": "post-reopen"}); err != nil {
		t.Fatalf("Append after reopen: %v", err)
	}
	if _, err := VerifyJournal(p.Journal, key); err != nil {
		t.Fatalf("VerifyJournal after reopen+append: %v", err)
	}
}

func TestJournalRotatedTamperDetected(t *testing.T) {
	p, key := testPaths(t)
	j, _ := OpenJournal(p.Journal, key)
	j.SetMaxBytes(2 << 10)
	for i := 0; i < 200; i++ {
		j.Append("alert", map[string]any{"n": i, "pad": "xxxxxxxxxxxxxxxxxxxxxxxxxxxx"})
	}
	// Rewrite a record in the rotated (current) segment → must be detected.
	raw, err := os.ReadFile(p.Journal)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n"))
	if len(lines) < 3 {
		t.Fatalf("current segment too short (%d)", len(lines))
	}
	var rec map[string]json.RawMessage
	json.Unmarshal(lines[len(lines)-1], &rec)
	rec["data"] = json.RawMessage(`{"n":99999}`)
	lines[len(lines)-1], _ = json.Marshal(rec)
	os.WriteFile(p.Journal, append(bytes.Join(lines, []byte("\n")), '\n'), 0o600)

	if _, err := VerifyJournal(p.Journal, key); err == nil {
		t.Fatal("expected chain-break error after rewriting a rotated-segment record")
	}
}

func TestJournalRewriteBreaksChain(t *testing.T) {
	p, key := testPaths(t)
	j, _ := OpenJournal(p.Journal, key)
	for i := 0; i < 4; i++ {
		j.Append("alert", map[string]any{"n": i})
	}
	raw, err := os.ReadFile(p.Journal)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n"))

	// Retroactively rewrite the "data" of the 2nd record, keeping valid JSON.
	var rec map[string]json.RawMessage
	if err := json.Unmarshal(lines[1], &rec); err != nil {
		t.Fatal(err)
	}
	rec["data"] = json.RawMessage(`{"n":999}`)
	lines[1], _ = json.Marshal(rec)
	if err := os.WriteFile(p.Journal, append(bytes.Join(lines, []byte("\n")), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := VerifyJournal(p.Journal, key); err == nil {
		t.Fatal("expected chain-break error after rewrite, got nil")
	}
}
