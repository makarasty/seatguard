package core

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Identity is the enrolled fingerprint of a legitimate binary.
// Process identity is NEVER a bare PID and NEVER a process name:
// it is path + content hash (+ signature where available), with
// (pid, start_time) used only as a stable runtime handle.
type Identity struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	// Signature is the resolved code-signing identity captured at enroll:
	// Authenticode signer CN + trust on Windows, codesign Authority on
	// macOS, "unsigned" on Linux or when absent. Supplementary metadata —
	// the enforced integrity check is the content hash above.
	Signature string `json:"signature"`
	// Interpreter marks binaries like node: legitimacy additionally
	// requires the main script to live inside an enrolled install dir.
	Interpreter bool `json:"interpreter,omitempty"`
	// ObservedPID/ObservedStartTime capture the live instance of this
	// binary seen at enroll time — the stable (pid, start_time) handle.
	// Zero when the binary was not running during enroll.
	ObservedPID       uint32 `json:"observed_pid,omitempty"`
	ObservedStartTime int64  `json:"observed_start_time,omitempty"`
}

// HashFile returns hex(SHA-256) and size of the file at path.
func HashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// SamePath compares two executable paths, case-insensitively on Windows.
func SamePath(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// hashCache avoids rehashing the same unchanged binary every poll tick.
type hashCache struct {
	mu sync.Mutex
	m  map[string]hashCacheEntry
}

type hashCacheEntry struct {
	mtime time.Time
	size  int64
	hash  string
}

func newHashCache() *hashCache {
	return &hashCache{m: make(map[string]hashCacheEntry)}
}

// Hash returns the SHA-256 of path, cached by (mtime, size).
func (c *hashCache) Hash(path string) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	e, ok := c.m[path]
	c.mu.Unlock()
	if ok && e.mtime.Equal(st.ModTime()) && e.size == st.Size() {
		return e.hash, nil
	}
	h, size, err := HashFile(path)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	// Bound the cache; the daemon must stay under the RSS budget.
	if len(c.m) > 256 {
		c.m = make(map[string]hashCacheEntry)
	}
	c.m[path] = hashCacheEntry{mtime: st.ModTime(), size: size, hash: h}
	c.mu.Unlock()
	return h, nil
}
