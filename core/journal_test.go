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
