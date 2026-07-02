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
	fs.Parse(args)

	initColors()
	kr := newKeyReader()
	defer kr.close()
	fmt.Print(scrClear)

	// Splash + scan.
	fmt.Print(banner())
	fmt.Printf("\n  %s◇%s scanning for Claude installations…\n", cCyan, cReset)
	found := core.DiscoverInstalls()
	if len(found) == 0 {
		fmt.Printf("\n  %s✗ no Claude installation found.%s\n", cRed, cReset)
		fmt.Println("  Install Claude Code / Claude Desktop first, or enroll explicitly:")
		fmt.Println("    seatguard enroll --claude-path <path-to-claude>")
		return fmt.Errorf("nothing to enroll")
	}

	// Checklist (arrow keys + space), all pre-selected.
	items := make([]checkItem, len(found))
	for i, f := range found {
		sub := f.Source
		if f.Interpreter {
			sub += " · interpreter (script rule)"
		}
		items[i] = checkItem{label: shortPath(f.Path), sub: sub, checked: true}
	}
	sub := fmt.Sprintf("%d found · pick which binaries are your legitimate Claude", len(found))
	if _, err := os.Stat(paths.DB); err == nil {
		sub += " · replaces existing baseline"
	}
	mask, ok := runChecklist(kr, "Select Claude installations", sub, items)
	if !ok {
		fmt.Print(scrClear)
		fmt.Println("  aborted; nothing was written")
		return nil
	}

	opts := core.EnrollOptions{PollSecs: *poll, NoDiscover: true}
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
		return fmt.Errorf("no binaries selected; nothing to enroll")
	}

	fmt.Print(scrClear)
	fmt.Printf("\n  %s◇%s enrolling %d binaries…\n", cCyan, cReset, len(opts.ExtraBinaries))
	b, err := core.Enroll(*paths, platform.New(), opts)
	if err != nil {
		return err
	}
	fmt.Printf("\n  %s✓ enrolled %d identities%s  %s→ %s%s\n", cGreen, len(b.Identities), cReset, cMuted, paths.DB, cReset)
	for _, id := range b.Identities {
		fmt.Printf("    %s%s%s  %ssha256 %s…%s\n", cReset, shortPath(id.Path), cReset, cMuted, id.SHA256[:12], cReset)
	}
	fmt.Printf("  %swatching:%s %s\n", cMuted, cReset, strings.Join(shortPaths(b.CredPaths), ", "))
	fmt.Printf("\n  %spress any key to continue…%s", cMuted, cReset)
	kr.next()

	commonFlags := []string{"--db", paths.DB, "--key", paths.Key, "--journal", paths.Journal, "--state", paths.State}

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
	choice := runMenu(kr, "Start protection", "seatguard is enrolled — choose how to run it", menu)
	fmt.Print(scrClear, curShow)
	switch choice {
	case 0: // dashboard
		if err := startBackgroundDaemon(commonFlags); err != nil {
			fmt.Printf("%scould not start background daemon: %v%s\n", cYell, err, cReset)
			fmt.Println("Falling back to foreground run (Ctrl+C to stop).")
			return cmdRun(commonFlags)
		}
		return cmdDashboard(commonFlags)
	case 1: // tray
		return cmdRun(append(commonFlags, "--tray"))
	case 2: // foreground
		fmt.Printf("\n%sRunning. Alerts appear below. Ctrl+C to stop.%s\n", cBold, cReset)
		return cmdRun(commonFlags)
	case 3: // autostart
		return installAutostart(*paths)
	default: // exit or cancel
		fmt.Println("\n  Setup complete. Start any time with:")
		fmt.Printf("    %sseatguard dashboard%s   live view\n", cCyan, cReset)
		fmt.Printf("    %sseatguard run --tray%s  background (Windows)\n", cCyan, cReset)
		return nil
	}
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
