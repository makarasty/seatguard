//go:build linux

package platform

import "testing"

// TestHexToIPv4 locks the /proc/net/tcp IPv4 byte order — the bug that made
// egress detection miss connections on Linux (the address came out reversed).
func TestHexToIPv4(t *testing.T) {
	cases := map[string]string{
		"0100007F": "127.0.0.1",    // loopback
		"071FD17F": "127.209.31.7", // the harness's stub Anthropic endpoint
		"0101A8C0": "192.168.1.1",  // typical LAN
		"08080808": "8.8.8.8",      // symmetric sanity check
	}
	for hexAddr, want := range cases {
		ip, err := hexToIP(hexAddr, false)
		if err != nil {
			t.Fatalf("hexToIP(%q): %v", hexAddr, err)
		}
		if ip.String() != want {
			t.Errorf("hexToIP(%q) = %s, want %s", hexAddr, ip.String(), want)
		}
	}
}
