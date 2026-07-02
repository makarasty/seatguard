package core

import (
	"context"
	"net"
	"sync"
	"time"
)

// ipSet maintains the current set of Anthropic endpoint IPs: static
// entries (from the baseline, used by tests) plus periodically re-resolved
// host addresses (Cloudflare rotates them, so we refresh instead of pinning).
type ipSet struct {
	mu     sync.RWMutex
	static []string
	hosts  []string
	ips    map[string]struct{}
}

func newIPSet(static, hosts []string) *ipSet {
	s := &ipSet{static: static, hosts: hosts, ips: make(map[string]struct{})}
	s.refresh(context.Background())
	return s
}

// refresh re-resolves hosts and rebuilds the set. DNS failures keep the
// previous host-derived entries (better stale than empty).
func (s *ipSet) refresh(ctx context.Context) {
	next := make(map[string]struct{})
	for _, ip := range s.static {
		if p := net.ParseIP(ip); p != nil {
			next[p.String()] = struct{}{}
		}
	}
	resolver := &net.Resolver{}
	failed := false
	for _, h := range s.hosts {
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		addrs, err := resolver.LookupIP(rctx, "ip", h)
		cancel()
		if err != nil {
			failed = true
			continue
		}
		for _, a := range addrs {
			next[a.String()] = struct{}{}
		}
	}
	s.mu.Lock()
	if failed {
		for ip := range s.ips {
			next[ip] = struct{}{}
		}
	}
	s.ips = next
	s.mu.Unlock()
}

// snapshot returns a copy of the current set for one poll tick.
func (s *ipSet) snapshot() map[string]struct{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]struct{}, len(s.ips))
	for ip := range s.ips {
		out[ip] = struct{}{}
	}
	return out
}
