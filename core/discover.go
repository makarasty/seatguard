package core

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// FoundInstall is one discovered Claude-related binary or install dir.
type FoundInstall struct {
	Path        string // absolute path to the executable
	Source      string // human-readable provenance, e.g. "PATH", "MSIX package"
	Interpreter bool   // true for node: legitimacy also requires the script rule
	InstallDir  string // optional JS install dir tied to this find
}

// DiscoverInstalls scans every known Claude installation location for the
// current OS and returns deduplicated candidates. It never fails — an
// unreadable location is simply skipped.
func DiscoverInstalls() []FoundInstall {
	var out []FoundInstall
	seen := map[string]bool{}

	add := func(path, source string, interpreter bool, installDir string) {
		if path == "" {
			return
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return
		}
		if resolved, err := filepath.EvalSymlinks(abs); err == nil {
			abs = resolved
		}
		st, err := os.Stat(abs)
		if err != nil || st.IsDir() {
			return
		}
		key := abs
		if runtime.GOOS == "windows" {
			key = strings.ToLower(abs)
		}
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, FoundInstall{Path: abs, Source: source, Interpreter: interpreter, InstallDir: installDir})
	}

	// Everywhere: whatever `claude` resolves to on PATH.
	if p, err := exec.LookPath("claude"); err == nil {
		add(p, "PATH", false, "")
	}

	home, _ := os.UserHomeDir()

	switch runtime.GOOS {
	case "windows":
		discoverWindows(home, add)
	case "darwin":
		add("/Applications/Claude.app/Contents/MacOS/Claude", "Claude.app", false, "")
		addGlob(add, filepath.Join(home, ".local", "bin", "claude"), ".local/bin", false)
		addNpmGlobal(home, add)
	default: // linux
		addGlob(add, filepath.Join(home, ".local", "bin", "claude"), ".local/bin", false)
		add("/usr/local/bin/claude", "/usr/local/bin", false, "")
		addNpmGlobal(home, add)
	}

	// The interpreter Claude Code runs under. Enrolled with the script
	// rule: only legit when its main script is inside an install dir.
	if p, err := exec.LookPath("node"); err == nil {
		add(p, "node interpreter", true, "")
	}

	return out
}

// discoverWindows checks Windows-specific locations:
//   - %USERPROFILE%\.local\bin (claude-code native installer)
//   - %LOCALAPPDATA%\Claude-Profiles\**  (multi-profile setups)
//   - MSIX packages (Claude Desktop from the Store), via Get-AppxPackage
//     because the WindowsApps root is not listable by regular users
//   - %LOCALAPPDATA%\AnthropicClaude (legacy Squirrel desktop layout)
//   - npm global prefix
func discoverWindows(home string, add func(string, string, bool, string)) {
	local := os.Getenv("LOCALAPPDATA")
	appdata := os.Getenv("APPDATA")

	addGlob(add, filepath.Join(home, ".local", "bin", "claude.exe"), ".local/bin", false)

	if local != "" {
		profiles := filepath.Join(local, "Claude-Profiles")
		addGlob(add, filepath.Join(profiles, "*", "claude.exe"), "Claude-Profiles", false)
		addGlob(add, filepath.Join(profiles, "*", "claude-code", "*", "claude.exe"), "Claude-Profiles", false)
		addGlob(add, filepath.Join(local, "AnthropicClaude", "claude.exe"), "AnthropicClaude", false)
		addGlob(add, filepath.Join(local, "AnthropicClaude", "app-*", "claude.exe"), "AnthropicClaude", false)
		addGlob(add, filepath.Join(local, "Programs", "claude*", "claude.exe"), "LocalAppData\\Programs", false)
	}

	// MSIX: ask the package manager, then probe the known exe layouts.
	for _, root := range msixInstallLocations() {
		add(filepath.Join(root, "app", "claude.exe"), "MSIX package", false, "")
		add(filepath.Join(root, "claude.exe"), "MSIX package", false, "")
	}

	// npm-global Claude Code: enroll node (added by caller) + install dir.
	if appdata != "" {
		dir := filepath.Join(appdata, "npm", "node_modules", "@anthropic-ai", "claude-code")
		if st, err := os.Stat(dir); err == nil && st.IsDir() {
			if p, err := exec.LookPath("node"); err == nil {
				add(p, "npm global (via node)", true, dir)
			}
		}
	}
}

// msixInstallLocations returns InstallLocation for every *Claude* MSIX
// package of the current user. Uses powershell because the AppX repository
// has no stable public file/registry layout and the WindowsApps directory
// itself denies listing to non-admins (direct paths still resolve).
func msixInstallLocations() []string {
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		return nil
	}
	cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command",
		`(Get-AppxPackage -Name *Claude* -ErrorAction SilentlyContinue).InstallLocation`)
	raw, err := cmd.Output()
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func addGlob(add func(string, string, bool, string), pattern, source string, interpreter bool) {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return
	}
	for _, m := range matches {
		add(m, source, interpreter, "")
	}
}

func addNpmGlobal(home string, add func(string, string, bool, string)) {
	for _, dir := range []string{
		"/usr/local/lib/node_modules/@anthropic-ai/claude-code",
		"/usr/lib/node_modules/@anthropic-ai/claude-code",
		filepath.Join(home, ".npm-global", "lib", "node_modules", "@anthropic-ai", "claude-code"),
	} {
		if st, err := os.Stat(dir); err == nil && st.IsDir() {
			if p, err := exec.LookPath("node"); err == nil {
				add(p, "npm global (via node)", true, dir)
			}
		}
	}
}
