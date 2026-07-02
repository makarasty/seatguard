package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"seatguard/core"
	"seatguard/platform"
)

// ANSI palette; emptied when the console cannot render escapes.
var (
	cBold  = "\x1b[1m"
	cDim   = "\x1b[2m"
	cGreen = "\x1b[32m"
	cCyan  = "\x1b[36m"
	cRed   = "\x1b[31m"
	cYell  = "\x1b[33m"
	cReset = "\x1b[0m"
)

func initColors() {
	if !platform.EnableANSI() {
		cBold, cDim, cGreen, cCyan, cRed, cYell, cReset = "", "", "", "", "", "", ""
	}
}

// cmdSetup is the interactive console wizard: discover every Claude
// install, let the user confirm the selection, enroll, then offer to start
// protection or install autostart. Also runs when seatguard is launched
// with no arguments (e.g. double-clicked).
func cmdSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	paths := pathFlags(fs)
	poll := fs.Int("poll", 4, "poll interval, seconds (3-5 recommended)")
	fs.Parse(args)

	initColors()
	in := bufio.NewScanner(os.Stdin)

	fmt.Printf("%s%sseatguard setup%s — local Claude token-theft detector\n\n", cBold, cCyan, cReset)

	if _, err := os.Stat(paths.DB); err == nil {
		fmt.Printf("%sA baseline already exists at %s — completing setup will replace it.%s\n\n", cYell, paths.DB, cReset)
	}

	fmt.Println("Scanning for Claude installations...")
	found := core.DiscoverInstalls()
	if len(found) == 0 {
		fmt.Printf("%sNo Claude installation found.%s\n", cRed, cReset)
		fmt.Println("Install Claude Code / Claude Desktop first, or enroll a binary explicitly:")
		fmt.Println("  seatguard enroll --claude-path <path-to-claude.exe>")
		return fmt.Errorf("nothing to enroll")
	}

	selected := make([]bool, len(found))
	for i := range selected {
		selected[i] = true
	}

	for {
		fmt.Printf("\n%sFound %d candidate(s):%s\n", cBold, len(found), cReset)
		for i, f := range found {
			mark := fmt.Sprintf("%s[x]%s", cGreen, cReset)
			if !selected[i] {
				mark = "[ ]"
			}
			kind := ""
			if f.Interpreter {
				kind = cDim + " (interpreter: script rule applies)" + cReset
			}
			fmt.Printf("  %s %2d. %s  %s(%s)%s%s\n", mark, i+1, f.Path, cDim, f.Source, cReset, kind)
		}
		fmt.Printf("\nToggle: %snumber%s · all: %sa%s · none: %sn%s · continue: %sEnter%s · quit: %sq%s\n> ",
			cCyan, cReset, cCyan, cReset, cCyan, cReset, cGreen, cReset, cRed, cReset)

		if !in.Scan() {
			break // EOF: accept current selection
		}
		line := strings.TrimSpace(strings.ToLower(in.Text()))
		switch {
		case line == "":
			goto done
		case line == "q":
			fmt.Println("aborted; nothing was written")
			return nil
		case line == "a":
			for i := range selected {
				selected[i] = true
			}
		case line == "n":
			for i := range selected {
				selected[i] = false
			}
		default:
			for _, tok := range strings.Fields(line) {
				if k, err := strconv.Atoi(tok); err == nil && k >= 1 && k <= len(found) {
					selected[k-1] = !selected[k-1]
				}
			}
		}
	}
done:

	opts := core.EnrollOptions{PollSecs: *poll, NoDiscover: true}
	anySelected := false
	for i, f := range found {
		if !selected[i] {
			continue
		}
		anySelected = true
		opts.ExtraBinaries = append(opts.ExtraBinaries, f.Path)
		if f.InstallDir != "" {
			opts.InstallDirs = append(opts.InstallDirs, f.InstallDir)
		}
	}
	if !anySelected {
		return fmt.Errorf("no binaries selected; nothing to enroll")
	}

	fmt.Println("\nEnrolling...")
	b, err := core.Enroll(*paths, platform.New(), opts)
	if err != nil {
		return err
	}
	fmt.Printf("%sEnrolled %d identities.%s Baseline: %s\n", cGreen, len(b.Identities), cReset, paths.DB)
	for _, id := range b.Identities {
		fmt.Printf("  %s  %ssha256=%s...%s\n", id.Path, cDim, id.SHA256[:16], cReset)
	}
	fmt.Printf("\nWatching credential files:\n")
	for _, c := range b.CredPaths {
		fmt.Printf("  %s\n", c)
	}

	commonFlags := []string{"--db", paths.DB, "--key", paths.Key, "--journal", paths.Journal, "--state", paths.State}

	fmt.Printf("\n%sStart protection?%s\n", cBold, cReset)
	fmt.Printf("  [%sD%s]ashboard — live security view (recommended)\n", cGreen, cReset)
	trayLabel := "hidden in the system tray"
	if runtime.GOOS != "windows" {
		trayLabel = "background (tray: Windows only)"
	}
	fmt.Printf("  [%st%s]ray      — run %s\n", cCyan, cReset, trayLabel)
	fmt.Printf("  [%sr%s]un       — foreground log\n", cCyan, cReset)
	fmt.Printf("  [%si%s]nstall   — autostart at logon\n", cCyan, cReset)
	fmt.Printf("  [%sn%s]o        — exit, start later\n> ", cDim, cReset)
	choice := "d"
	if in.Scan() {
		choice = strings.TrimSpace(strings.ToLower(in.Text()))
	}
	switch choice {
	case "", "d", "dashboard", "y", "yes":
		// Start a background daemon, then attach the live dashboard.
		if err := startBackgroundDaemon(commonFlags); err != nil {
			fmt.Printf("%scould not start background daemon: %v%s\n", cYell, err, cReset)
			fmt.Println("Falling back to foreground run (Ctrl+C to stop).")
			return cmdRun(commonFlags)
		}
		return cmdDashboard(commonFlags)
	case "t", "tray":
		return cmdRun(append(commonFlags, "--tray"))
	case "r", "run":
		fmt.Printf("\n%sRunning. Alerts appear below. Ctrl+C to stop.%s\n", cBold, cReset)
		return cmdRun(commonFlags)
	case "i", "install":
		return installAutostart(*paths)
	default:
		fmt.Println("\nSetup complete. Start any time with:")
		fmt.Printf("  seatguard dashboard   (live view)\n  seatguard run --tray  (background, Windows)\n")
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
