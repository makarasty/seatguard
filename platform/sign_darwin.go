//go:build darwin

package platform

import (
	"os/exec"
	"strings"
)

// SignerOf returns the Authority chain of a Mach-O code signature via the
// system codesign tool (no cgo). Returns "unsigned" when the binary is not
// signed or codesign is unavailable.
func SignerOf(path string) (string, error) {
	// codesign writes the signature details to stderr.
	out, err := exec.Command("/usr/bin/codesign", "-dvv", path).CombinedOutput()
	if err != nil {
		return "unsigned", nil
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "Authority=") {
			return strings.TrimPrefix(line, "Authority="), nil
		}
	}
	return "unsigned", nil
}
