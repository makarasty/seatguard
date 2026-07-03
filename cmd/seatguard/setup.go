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

// cmdSetup is the interactive, fully keyboard-driven setup wizard: discover
// every Claude install, confirm the selection with an arrow-key checklist,
// enroll, then pick how to start protection from an arrow-key menu. Also
// runs when seatguard is launched with no arguments (e.g. double-clicked).
func cmdSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	paths := pathFlags(fs)
	poll := fs.Int("poll", 4, "poll interval, seconds (3-5 recommended)")
	reconfigure := fs.Bool("reconfigure", false, "force full re-selection even if already configured")
	fs.Parse(args)

	initColors()
	kr := newKeyReader()
	defer kr.close()
	fmt.Print(scrClear)
	fmt.Print(banner())

	// Navigation loop: each step can return "back" (Esc) to re-show the
	// previous one instead of exiting. Once a baseline exists (fresh enroll or
	// pre-existing), the entry point is the "already configured" menu.
	for {
		b, back, done, err := selectStep(kr, *paths, *poll, *reconfigure)
		*reconfigure = false // only forces the FIRST pass
		if err != nil || done {
			return err
		}
		if back || b == nil {
			// Nothing selected (cancelled on a fresh machine) → exit.
			if loadExisting(*paths) == nil {
				fmt.Print(scrClear)
				fmt.Println("  aborted; nothing was written")
				return nil
			}
			continue // re-show the configured menu
		}
		err, back = startProtection(kr, *paths, b)
		if back {
			continue // Esc in the start menu → back to the configured/select step
		}
		return err
	}
}

// selectStep runs one iteration of the "what to enroll" step and returns the
// resulting baseline. done=true means the user already made a terminal choice
// (e.g. Quit) and the wizard should exit.
func selectStep(kr *keyReader, paths core.Paths, poll int, reconfigure bool) (b *core.Baseline, back, done bool, err error) {
	existing := loadExisting(paths)
	if existing != nil && len(existing.Identities) > 0 && !reconfigure {
		eb, action := configuredMenu(kr, paths, existing)
		switch action {
		case actStart:
			return eb, false, false, nil
		case actQuit:
			fmt.Print(scrClear)
			fmt.Println("  no changes. seatguard is still configured.")
			return nil, false, true, nil
		case actRescan:
			nb, e := reenrollAll(paths, poll)
			return nb, false, false, e
		default: // actEdit — checklist pre-checked from the current baseline
			nb, e := selectAndEnroll(kr.next, paths, poll, enrolledSet(existing))
			return nb, nb == nil && e == nil, false, e // nb==nil (Esc) → back
		}
	}
	// Fresh setup: full checklist, everything pre-selected.
	nb, e := selectAndEnroll(kr.next, paths, poll, nil)
	return nb, nb == nil && e == nil, false, e
}

// setup action from the "already configured" menu.
type setupAction int

const (
	actStart setupAction = iota
	actRescan
	actEdit
	actQuit
)

// configuredMenu is shown when a valid baseline already exists. It returns
// the loaded baseline and the chosen action.
func configuredMenu(kr *keyReader, paths core.Paths, b *core.Baseline) (*core.Baseline, setupAction) {
	// Detect drift: new Claude installs on disk, or enrolled binaries changed.
	enrolled := enrolledSet(b)
	newCount := 0
	for _, f := range core.DiscoverInstalls() {
		if !enrolled[core.NormPath(f.Path)] {
			newCount++
		}
	}
	stale := 0
	for _, id := range b.Identities {
		if h, _, err := core.HashFile(id.Path); err != nil || h != id.SHA256 {
			stale++
		}
	}

	sub := fmt.Sprintf("%d Claude binaries enrolled", len(b.Identities))
	rescanDesc := "no changes detected on disk"
	if newCount > 0 || stale > 0 {
		sub = fmt.Sprintf("%d enrolled · %s%d new, %d changed%s — update recommended",
			len(b.Identities), cYell, newCount, stale, cReset)
		rescanDesc = fmt.Sprintf("%d new install(s), %d changed", newCount, stale)
	}

	menu := []menuItem{
		{label: "Start protection", desc: "use the current baseline", hot: 's'},
		{label: "Re-scan & update", desc: rescanDesc, hot: 'r'},
		{label: "Edit selection", desc: "choose which binaries are enrolled", hot: 'e'},
		{label: "Quit", desc: "leave configuration unchanged", hot: 'q'},
	}
	switch runMenu(kr.next, "seatguard is already configured", sub, menu) {
	case 0:
		return b, actStart
	case 1:
		return b, actRescan
	case 2:
		return b, actEdit
	default:
		return b, actQuit
	}
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

// reenrollAll re-enrolls every discovered install without prompting (the
// "nothing changed but refresh hashes" path after a Claude update).
func reenrollAll(paths core.Paths, poll int) (*core.Baseline, error) {
	fmt.Print(scrClear, banner())
	fmt.Printf("\n  %s◇%s re-scanning and updating baseline…\n", cCyan, cReset)
	b, err := core.Enroll(paths, platform.New(), core.EnrollOptions{PollSecs: poll})
	if err != nil {
		return nil, err
	}
	fmt.Printf("\n  %s✓ baseline updated: %d identities%s\n", cGreen, len(b.Identities), cReset)
	return b, nil
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

// startProtection shows the "how to run" menu and launches the chosen mode.
// Returns back=true when the user pressed Esc to return to the previous step
// (so the wizard can re-show it) rather than choosing a run mode.
func startProtection(kr *keyReader, paths core.Paths, b *core.Baseline) (err error, back bool) {
	commonFlags := paths.Args()
	trayDesc := "run hidden with a status icon"
	if runtime.GOOS != "windows" {
		trayDesc = "background (tray icon: Windows only)"
	}
	menu := []menuItem{
		{label: "Live dashboard", desc: "start protection + open the live view", hot: 'd'},
		{label: "System tray", desc: trayDesc, hot: 't'},
		{label: "Foreground", desc: "run here, stream alerts", hot: 'r'},
		{label: "Autostart at logon", desc: "run in the tray at every logon", hot: 'i'},
		{label: "Exit", desc: "enrolled; start later", hot: 'x'},
	}
	choice := runMenu(kr.next, "Start protection", fmt.Sprintf("%d identities enrolled — Esc to go back", len(b.Identities)), menu)
	if choice == -1 {
		return nil, true // Esc → back to the previous step
	}
	fmt.Print(scrClear, curShow)
	// Restore the console (line mode, echo, Ctrl+C-as-signal) BEFORE handing
	// off: the next command opens its own key source, and a foreground `run`
	// needs Ctrl+C to work. Without this the wizard's raw mode would linger.
	kr.close()
	switch choice {
	case 0: // dashboard
		if e := startBackgroundDaemon(commonFlags); e != nil {
			fmt.Printf("%scould not start background daemon: %v%s\n", cYell, e, cReset)
			fmt.Println("Falling back to foreground run (Esc or Ctrl+C to stop).")
			return cmdRun(commonFlags), false
		}
		return cmdDashboard(commonFlags), false
	case 1: // tray
		return cmdRun(append(commonFlags, "--tray")), false
	case 2: // foreground
		fmt.Printf("\n%sRunning. Alerts appear below. Esc or Ctrl+C to stop.%s\n", cBold, cReset)
		return cmdRun(commonFlags), false
	case 3: // autostart
		return installAutostart(paths), false
	default: // Exit
		fmt.Println("\n  Setup complete. Start any time with:")
		fmt.Printf("    %sseatguard dashboard%s   live view\n", cCyan, cReset)
		fmt.Printf("    %sseatguard run --tray%s  background (Windows)\n", cCyan, cReset)
		return nil, false
	}
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
	hideChildWindow(cmd)
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

	// Start it now (detached) so the tray icon appears immediately.
	commonFlags := append(paths.Args(), "--tray")
	if err := startBackgroundDaemon(commonFlags); err != nil {
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
