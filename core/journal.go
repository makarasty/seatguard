package core

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"seatguard/platform"
)

// Entry is one journal record. Records form an HMAC chain: each MAC
// covers the previous record's MAC, so rewriting any past record breaks
// every MAC after it. The key is stored separately from the journal.
type Entry struct {
	Seq  uint64          `json:"seq"`
	TS   string          `json:"ts"` // RFC3339Nano; kept as string so verification is byte-exact
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
	MAC  string          `json:"mac"`
}

func entryMAC(key []byte, prevMAC string, e *Entry) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("seatguard-journal-v1\n"))
	m.Write([]byte(prevMAC))
	m.Write([]byte{'\n'})
	m.Write([]byte(strconv.FormatUint(e.Seq, 10)))
	m.Write([]byte{'\n'})
	m.Write([]byte(e.TS))
	m.Write([]byte{'\n'})
	m.Write([]byte(e.Type))
	m.Write([]byte{'\n'})
	m.Write(e.Data)
	return hex.EncodeToString(m.Sum(nil))
}

// Journal is an append-only, hash-chained event log.
type Journal struct {
	mu       sync.Mutex
	path     string
	key      []byte
	lastSeq  uint64
	lastMAC  string
	hardened bool
}

// OpenJournal opens (creating if needed) the journal and loads chain state.
// It does NOT fully verify on open; use Verify for that.
func OpenJournal(path string, key []byte) (*Journal, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	j := &Journal{path: path, key: key}
	entries, err := readEntries(path)
	if err != nil {
		return nil, err
	}
	if n := len(entries); n > 0 {
		j.lastSeq = entries[n-1].Seq
		j.lastMAC = entries[n-1].MAC
	}
	// Match the DB/key on-disk posture (protected DACL on Windows) once the
	// file exists; a fresh journal is hardened on first Append.
	if _, statErr := os.Stat(path); statErr == nil {
		platform.HardenFile(path)
		j.hardened = true
	}
	return j, nil
}

func readEntries(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return out, fmt.Errorf("%w: journal line %d is not valid JSON", ErrIntegrity, len(out)+1)
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// Append writes one record and advances the chain.
func (j *Journal) Append(typ string, data any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	e := Entry{
		Seq:  j.lastSeq + 1,
		TS:   time.Now().UTC().Format(time.RFC3339Nano),
		Type: typ,
		Data: raw,
	}
	e.MAC = entryMAC(j.key, j.lastMAC, &e)
	line, err := json.Marshal(&e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(j.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	j.lastSeq = e.Seq
	j.lastMAC = e.MAC
	if !j.hardened {
		platform.HardenFile(j.path) // restrict DACL on the freshly created file
		j.hardened = true
	}
	return nil
}

// VerifyJournal re-walks the whole chain. Returns the entries and an
// ErrIntegrity-wrapped error pointing at the first broken record.
func VerifyJournal(path string, key []byte) ([]Entry, error) {
	entries, err := readEntries(path)
	if err != nil {
		return entries, err
	}
	prevMAC := ""
	for i := range entries {
		e := &entries[i]
		if e.Seq != uint64(i+1) {
			return entries, fmt.Errorf("%w: journal chain break at record %d — sequence gap (got seq %d)", ErrIntegrity, i+1, e.Seq)
		}
		want := entryMAC(key, prevMAC, e)
		if !hmac.Equal([]byte(want), []byte(e.MAC)) {
			return entries, fmt.Errorf("%w: journal chain break at record %d — record was rewritten or reordered", ErrIntegrity, i+1)
		}
		prevMAC = e.MAC
	}
	return entries, nil
}
