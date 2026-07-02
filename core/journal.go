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

// defaultJournalMax bounds the live journal file; when exceeded it rotates
// (one archive kept), so a long-running daemon doesn't grow it without limit.
const defaultJournalMax = 4 << 20 // 4 MiB

// rotationAnchor is the payload of the "rotated" genesis record that starts a
// fresh journal segment and links it to the archived tail's chain.
type rotationAnchor struct {
	PrevSeq uint64 `json:"prev_seq"`
	PrevMAC string `json:"prev_mac"`
	Archive string `json:"archive"`
}

// Journal is an append-only, hash-chained event log.
type Journal struct {
	mu       sync.Mutex
	path     string
	key      []byte
	lastSeq  uint64
	lastMAC  string
	hardened bool
	maxBytes int64
}

// SetMaxBytes overrides the rotation threshold (0 disables rotation).
func (j *Journal) SetMaxBytes(n int64) { j.maxBytes = n }

// OpenJournal opens (creating if needed) the journal and loads chain state.
// It does NOT fully verify on open; use Verify for that.
func OpenJournal(path string, key []byte) (*Journal, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	j := &Journal{path: path, key: key, maxBytes: defaultJournalMax}
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

	// Rotate before appending when the file has grown past the cap.
	if j.maxBytes > 0 && j.lastSeq > 0 {
		if st, serr := os.Stat(j.path); serr == nil && st.Size() >= j.maxBytes {
			j.rotate() // best effort; on failure we keep appending to the current file
		}
	}

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

// rotate archives the current journal and starts a fresh segment with a
// "rotated" genesis record whose MAC chains from the archived tail — so the
// new file is independently verifiable yet cryptographically linked to the
// history it replaced. One archive ("<journal>.1") is kept. Caller holds mu.
func (j *Journal) rotate() {
	archive := j.path + ".1"
	os.Remove(archive) // Windows os.Rename won't overwrite an existing file
	if err := os.Rename(j.path, archive); err != nil {
		return // keep appending to the current file
	}
	anchor, _ := json.Marshal(rotationAnchor{PrevSeq: j.lastSeq, PrevMAC: j.lastMAC, Archive: filepath.Base(archive)})
	g := Entry{Seq: 1, TS: time.Now().UTC().Format(time.RFC3339Nano), Type: "rotated", Data: anchor}
	g.MAC = entryMAC(j.key, j.lastMAC, &g)
	line, _ := json.Marshal(&g)
	f, err := os.OpenFile(j.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	f.Write(append(line, '\n'))
	f.Close()
	platform.HardenFile(j.path)
	j.hardened = true
	j.lastSeq = g.Seq
	j.lastMAC = g.MAC
}

// VerifyJournal re-walks the chain of the current journal segment. A
// "rotated" genesis record seeds the chain from the archived tail's MAC, so a
// rotated journal still verifies. Returns the entries and an
// ErrIntegrity-wrapped error pointing at the first broken record.
func VerifyJournal(path string, key []byte) ([]Entry, error) {
	entries, err := readEntries(path)
	if err != nil {
		return entries, err
	}
	prevMAC := ""
	for i := range entries {
		e := &entries[i]
		if i == 0 && e.Type == "rotated" {
			var a rotationAnchor
			if json.Unmarshal(e.Data, &a) == nil {
				prevMAC = a.PrevMAC // seed from the archived segment's tail
			}
		}
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
