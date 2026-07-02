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

	// If a valid baseline already exists, don't re-ask everything: offer to
	// start straight away, and only re-scan/edit on request.
	if existing := loadExisting(*paths); existing != nil && len(existing.Identities) > 0 && !*reconfigure {
		b, action := configuredMenu(kr, *paths, existing)
		switch action {
		case actStart:
			return startProtection(kr, *paths, b)
		case actQuit:
			fmt.Print(scrClear)
			fmt.Println("  no changes. seatguard is still configured.")
			return nil
		case actEdit, actRescan:
			// fall through to selection (edit) or auto re-enroll (rescan)
		}
		if action == actRescan {
			nb, err := reenrollAll(*paths, *poll)
			if err != nil {
				return err
			}
			return startProtection(kr, *paths, nb)
		}
		// actEdit: run the checklist pre-checked from the current baseline.
		nb, err := selectAndEnroll(kr, *paths, *poll, enrolledSet(existing))
		if err != nil || nb == nil {
			return err
		}
		return startProtection(kr, *paths, nb)
	}

	// Fresh setup: full checklist, everything pre-selected.
	b, err := selectAndEnroll(kr, *paths, *poll, nil)
	if err != nil || b == nil {
		return err
	}
	return startProtection(kr, *paths, b)
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
	switch runMenu(kr, "seatguard is already configured", sub, menu) {
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
func selectAndEnroll(kr *keyReader, paths core.Paths, poll int, preChecked map[string]bool) (*core.Baseline, error) {
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
	mask, ok := runChecklist(kr, "Select Claude installations", sub, items)
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
	return enrollAndReport(kr, paths, opts)
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

func enrollAndReport(kr *keyReader, paths core.Paths, opts core.EnrollOptions) (*core.Baseline, error) {
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
	kr.next()
	return b, nil
}

// startProtection shows the "how to run" menu and launches the chosen mode.
func startProtection(kr *keyReader, paths core.Paths, b *core.Baseline) error {
	commonFlags := paths.Args()
	trayDesc := "run hidden with a status icon"
	if runtime.GOOS != "windows" {
		trayDesc = "background (tray icon: Windows only)"
	}
	menu := []menuItem{
		{label: "Live dashboard", desc: "start protection + open the live view", hot: 'd'},
		{label: "System tray", desc: trayDesc, hot: 't'},
		{label: "Foreground", desc: "run here, stream alerts", hot: 'r'},
		{label: "Autostart at logon", desc: "install a startup task", hot: 'i'},
		{label: "Exit", desc: "enrolled; start later", hot: 'x'},
	}
	choice := runMenu(kr, "Start protection", fmt.Sprintf("%d identities enrolled — choose how to run it", len(b.Identities)), menu)
	fmt.Print(scrClear, curShow)
	// Restore the console (line mode, echo, Ctrl+C-as-signal) BEFORE handing
	// off: the next command opens its own key source, and a foreground `run`
	// needs Ctrl+C to work. Without this the wizard's raw mode would linger.
	kr.close()
	switch choice {
	case 0: // dashboard
		if err := startBackgroundDaemon(commonFlags); err != nil {
			fmt.Printf("%scould not start background daemon: %v%s\n", cYell, err, cReset)
			fmt.Println("Falling back to foreground run (Esc or Ctrl+C to stop).")
			return cmdRun(commonFlags)
		}
		return cmdDashboard(commonFlags)
	case 1: // tray
		return cmdRun(append(commonFlags, "--tray"))
	case 2: // foreground
		fmt.Printf("\n%sRunning. Alerts appear below. Esc or Ctrl+C to stop.%s\n", cBold, cReset)
		return cmdRun(commonFlags)
	case 3: // autostart
		return installAutostart(paths)
	default: // exit or cancel
		fmt.Println("\n  Setup complete. Start any time with:")
		fmt.Printf("    %sseatguard dashboard%s   live view\n", cCyan, cReset)
		fmt.Printf("    %sseatguard run --tray%s  background (Windows)\n", cCyan, cReset)
		return nil
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

	tr := fmt.Sprintf(`"%s" run --db "%s" --key "%s" --journal "%s" --state "%s"`,
		self, paths.DB, paths.Key, paths.Journal, paths.State)
	cmd := exec.Command("schtasks", "/Create", "/TN", "seatguard", "/TR", tr, "/SC", "ONLOGON", "/RL", "HIGHEST", "/F")
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("%sschtasks failed:%s %s\n", cRed, cReset, strings.TrimSpace(string(out)))
		fmt.Println("Hint: /RL HIGHEST needs an elevated (Administrator) console.")
		fmt.Println("Either rerun setup elevated, or register without elevation:")
		fmt.Printf(`  schtasks /Create /TN seatguard /TR '%s' /SC ONLOGON /F`+"\n", tr)
		return err
	}
	fmt.Printf("%sAutostart installed:%s task \"seatguard\" runs at logon.\n", cGreen, cReset)
	fmt.Println("Start it now with:  schtasks /Run /TN seatguard")
	fmt.Println("Remove with:        schtasks /Delete /TN seatguard /F")
	return nil
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
