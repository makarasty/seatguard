//go:build !darwin

package platform

// SelfDiag returns detailed low-level diagnostics on darwin only.
func SelfDiag() string { return "  (detailed self-diagnostics are darwin-only)\n" }
