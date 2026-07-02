package core

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"seatguard/platform"
)

// Baseline is the protected reference database: enrolled identities,
// watched credential paths and the Anthropic endpoint set. The token
// itself is NEVER stored — only metadata and hashes.
type Baseline struct {
	Version     int        `json:"version"`
	CreatedAt   time.Time  `json:"created_at"`
	DaemonHash  string     `json:"daemon_hash"` // hash of the seatguard binary itself
	Identities  []Identity `json:"identities"`
	InstallDirs []string   `json:"install_dirs"` // legit Claude install dirs (interpreter rule)
	CredPaths   []string   `json:"cred_paths"`
	APIHosts    []string   `json:"api_hosts"` // resolved to IPs at runtime; never hardcode IPs
	APIIPs      []string   `json:"api_ips"`   // static extras (used by the test harness)
	PollSecs    int        `json:"poll_secs"`
}

// dbFile is the on-disk envelope: payload bytes + HMAC-SHA256 over them.
// Any single-byte modification breaks either JSON parsing or the MAC.
type dbFile struct {
	Payload []byte `json:"payload"` // baseline JSON, base64-encoded by encoding/json
	MAC     string `json:"mac"`
}

// ErrIntegrity is returned when the DB or journal fails verification.
var ErrIntegrity = errors.New("integrity violation")

// LoadKey reads the 32-byte HMAC key (hex) from its file. The key lives
// in a separate location from the DB so that tampering with the DB file
// alone cannot be re-MACed.
func LoadKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	key, err := hex.DecodeString(string(bytes.TrimRight(raw, "\r\n ")))
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("malformed key file %s", path)
	}
	return key, nil
}

// EnsureKey creates a random key at path (0600) if absent, then loads it.
func EnsureKey(path string) ([]byte, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, []byte(hex.EncodeToString(key)), 0o600); err != nil {
			return nil, err
		}
		// os.WriteFile perm bits are advisory on Windows; set a real ACL.
		platform.HardenFile(path) // best effort — HMAC is the primary guard
	}
	return LoadKey(path)
}

func dbMAC(key, payload []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("seatguard-db-v1\n"))
	m.Write(payload)
	return hex.EncodeToString(m.Sum(nil))
}

// SaveBaseline writes the baseline with its HMAC, mode 0600.
func SaveBaseline(path string, key []byte, b *Baseline) error {
	payload, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	env := dbFile{Payload: payload, MAC: dbMAC(key, payload)}
	out, err := json.Marshal(&env)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return err
	}
	platform.HardenFile(path) // best effort — restrict DACL on Windows
	return nil
}

// LoadBaseline reads and verifies the baseline. Fail-safe: any parse or
// MAC failure returns ErrIntegrity — callers must refuse to operate.
func LoadBaseline(path string, key []byte) (*Baseline, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	var env dbFile
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("%w: baseline file is not valid JSON (%v)", ErrIntegrity, err)
	}
	if !hmac.Equal([]byte(dbMAC(key, env.Payload)), []byte(env.MAC)) {
		return nil, fmt.Errorf("%w: baseline HMAC mismatch — database was modified outside seatguard", ErrIntegrity)
	}
	var b Baseline
	if err := json.Unmarshal(env.Payload, &b); err != nil {
		return nil, fmt.Errorf("%w: baseline payload corrupt (%v)", ErrIntegrity, err)
	}
	return &b, nil
}
