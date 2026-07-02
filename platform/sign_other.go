//go:build !windows && !darwin

package platform

// SignerOf returns the code-signing identity of a binary. On Linux there
// is no ubiquitous per-binary signing scheme, so this reports "unsigned".
func SignerOf(path string) (string, error) { return "unsigned", nil }
