package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"seatguard/core"
	"seatguard/platform"
)

// cmdSetup is the first-run entry point: if there is no baseline yet (or
// --reconfigure is given) it runs the discovery-and-enroll wizard, then hands
// off to the control center — the single screen from which everything else is
// managed. Also runs when seatguard is launched with no arguments (e.g.
// double-clicked).
func cmdSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	paths := pathFlags(fs)
	poll := fs.Int("poll", 4, "poll interval, seconds (3-5 recommended)")
	reconfigure := fs.Bool("reconfigure", false, "force re-selection even if already configured")
	fs.Parse(args)

	initColors()
	if !platform.StdinInteractive() {
		fmt.Fprintln(os.Stderr, "seatguard setup needs an interactive terminal.")
		fmt.Fprintln(os.Stderr, "for non-interactive/service use: seatguard enroll … then seatguard run")
		return nil
	}

	existing := loadExisting(*paths)
	if existing == nil || *reconfigure {
		var pre map[string]bool
		if existing != nil {
			pre = enrolledSet(existing)
		}
		b, err := firstRunWizard(*paths, *poll, pre)
		if err != nil {
			return err
		}
		if b == nil && existing == nil {
			// Cancelled on a fresh machine → nothing to manage; exit.
			fmt.Print(scrClear)
			fmt.Println("  aborted; nothing was written.")
			return nil
		}
		// A cancelled reconfigure (b == nil) with an existing baseline simply
		// falls through to the control center with the current configuration.
	}
	return runControlCenter(*paths, false)
}

// firstRunWizard opens its own key reader, runs the discovery checklist and
// enrolls the chosen binaries, then closes the reader (so the control center
// can own the console cleanly afterwards). Returns the new baseline, or nil if
// the user cancelled.
func firstRunWizard(paths core.Paths, poll int, preChecked map[string]bool) (*core.Baseline, error) {
	kr := newKeyReader()
	defer kr.close()
	return selectAndEnroll(kr.next, paths, poll, preChecked)
}

// selectAndEnroll runs the discovery checklist and enrolls the chosen
// binaries. preChecked (nil = all) decides which rows start ticked. Returns
// (nil, nil) if the user cancelled.
func selectAndEnroll(next func() keyEvent, paths core.Paths, poll int, preChecked map[string]bool) (*core.Baseline, error) {
	fmt.Print(scrClear, banner())
	fmt.Printf("\n  %s◇%s scanning for Claude installations…\n", cCyan, cReset)
	found := core.DiscoverInstalls()
	if len(found) == 0 {
		fmt.Printf("\n  %s✗ no Claude installation found.%s\n", cRed, cReset)
		fmt.Println("  Install Claude Code / Claude Desktop first, or enroll explicitly:")
		fmt.Println("    seatguard enroll --claude-path <path-to-claude>")
		return nil, fmt.Errorf("nothing to enroll")
	}

	items := make([]checkItem, len(found))
	for i, f := range found {
		sub := f.Source
		if f.Interpreter {
			sub += " · interpreter (script rule)"
		}
		checked := preChecked == nil || preChecked[core.NormPath(f.Path)]
		items[i] = checkItem{label: shortPath(f.Path), sub: sub, checked: checked}
	}
	sub := fmt.Sprintf("%d found · pick which binaries are your legitimate Claude", len(found))
	mask, ok := runChecklist(next, "Select Claude installations", sub, items)
	if !ok {
		fmt.Print(scrClear)
		fmt.Println("  aborted; nothing was written")
		return nil, nil
	}

	opts := core.EnrollOptions{PollSecs: poll, NoDiscover: true}
	for i, f := range found {
		if !mask[i] {
			continue
		}
		opts.ExtraBinaries = append(opts.ExtraBinaries, f.Path)
		if f.InstallDir != "" {
			opts.InstallDirs = append(opts.InstallDirs, f.InstallDir)
		}
	}
	if len(opts.ExtraBinaries) == 0 {
		fmt.Print(scrClear)
		return nil, fmt.Errorf("no binaries selected; nothing to enroll")
	}
	return enrollAndReport(next, paths, opts)
}

func enrollAndReport(next func() keyEvent, paths core.Paths, opts core.EnrollOptions) (*core.Baseline, error) {
	fmt.Print(scrClear)
	fmt.Printf("\n  %s◇%s enrolling %d binaries…\n", cCyan, cReset, len(opts.ExtraBinaries))
	b, err := core.Enroll(paths, platform.New(), opts)
	if err != nil {
		return nil, err
	}
	fmt.Printf("\n  %s✓ enrolled %d identities%s  %s→ %s%s\n", cGreen, len(b.Identities), cReset, cMuted, paths.DB, cReset)
	for _, id := range b.Identities {
		fmt.Printf("    %s%s%s  %ssha256 %s…%s\n", cReset, shortPath(id.Path), cReset, cMuted, id.SHA256[:12], cReset)
	}
	fmt.Printf("  %swatching:%s %s\n", cMuted, cReset, strings.Join(shortPaths(b.CredPaths), ", "))
	fmt.Printf("\n  %spress any key to continue…%s", cMuted, cReset)
	next()
	return b, nil
}

// loadExisting loads and verifies the current baseline, or returns nil.
func loadExisting(paths core.Paths) *core.Baseline {
	key, err := core.LoadKey(paths.Key)
	if err != nil {
		return nil
	}
	b, err := core.LoadBaseline(paths.DB, key)
	if err != nil {
		return nil
	}
	return b
}

func enrolledSet(b *core.Baseline) map[string]bool {
	m := make(map[string]bool, len(b.Identities))
	for _, id := range b.Identities {
		m[core.NormPath(id.Path)] = true
	}
	return m
}

// startBackgroundDaemon launches `seatguard run` as a detached background
// process (no visible window on Windows), so the foreground can show the
// dashboard attached to its state file. Skips if a daemon already appears
// to be running.
func startBackgroundDaemon(commonFlags []string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(self, append([]string{"run"}, commonFlags...)...)
	hideChildWindow(cmd) // Windows: no console window
	detachChild(cmd)     // POSIX: own session, survives terminal close
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	if err := cmd.Start(); err != nil {
		return err
	}
	// Detach so it keeps running after this process exits.
	go func() { _ = cmd.Process.Release() }()
	return nil
}

// installAutostart registers a logon task via the Windows Task Scheduler.
// Other platforms get printed instructions instead (systemd / launchd
// service management is Phase 2).
func installAutostart(paths core.Paths) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	self, _ = filepath.Abs(self)

	if runtime.GOOS != "windows" {
		fmt.Println("Autostart install is currently implemented for Windows only.")
		fmt.Println("On Linux, create a systemd unit that runs:")
		fmt.Printf("  %s run\n", self)
		return nil
	}

	// Register a per-user logon entry (HKCU\...\Run) — writable without
	// elevation, unlike a Task Scheduler /RL HIGHEST task. Runs in the tray
	// so there's a visible status icon at logon.
	cmdline := fmt.Sprintf(`"%s" run --tray --db "%s" --key "%s" --journal "%s" --state "%s"`,
		self, paths.DB, paths.Key, paths.Journal, paths.State)
	if err := platform.SetAutostart("seatguard", cmdline); err != nil {
		fmt.Printf("%sautostart install failed:%s %v\n", cRed, cReset, err)
		return err
	}
	fmt.Printf("%s✓ autostart installed%s — runs in the tray at every logon.\n", cGreen, cReset)

	// Start it now (detached) so the tray icon appears immediately — unless a
	// monitor is already running, since a second instance would just be
	// refused by the single-instance lock.
	if daemonRunning(paths) {
		fmt.Println("  protection is already running.")
	} else if err := startBackgroundDaemon(append(paths.Args(), "--tray")); err != nil {
		fmt.Printf("  %sit will start at next logon (couldn't launch now: %v)%s\n", cYell, err, cReset)
	} else {
		fmt.Println("  started now — look for the tray icon near the clock.")
	}
	fmt.Println("  remove any time with:  seatguard autostart remove")
	return nil
}

// cmdAutostart installs or removes the logon autostart entry.
//
//	seatguard autostart [install|remove] [--db … --key … …]
func cmdAutostart(args []string) error {
	sub, rest := "install", args
	if len(args) > 0 && (args[0] == "install" || args[0] == "remove" || args[0] == "off" || args[0] == "on") {
		sub, rest = args[0], args[1:]
	}
	fs := flag.NewFlagSet("autostart", flag.ExitOnError)
	paths := pathFlags(fs)
	fs.Parse(rest)
	initColors()

	if sub == "remove" || sub == "off" {
		if err := platform.RemoveAutostart("seatguard"); err != nil {
			return fmt.Errorf("remove autostart: %w", err)
		}
		fmt.Println("autostart removed.")
		return nil
	}
	return installAutostart(*paths)
}

// banner renders the wizard splash header.
func banner() string {
	return "\n" +
		"  " + cCyan + cBold + "seatguard" + cReset + "  " + cMuted + "· Claude subscription-token guard" + cReset + "\n" +
		"  " + cMuted + "detects unknown software using your Claude token — locally" + cReset + "\n"
}

// shortPath trims a long path for display, keeping the last few segments.
func shortPath(p string) string {
	const maxLen = 52
	if len(p) <= maxLen {
		return p
	}
	sep := string(filepath.Separator)
	parts := strings.Split(p, sep)
	out := parts[len(parts)-1]
	for i := len(parts) - 2; i >= 0; i-- {
		cand := parts[i] + sep + out
		if len(cand)+1 > maxLen {
			return "…" + sep + out
		}
		out = cand
	}
	return p
}

func shortPaths(ps []string) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = shortPath(p)
	}
	return out
}
