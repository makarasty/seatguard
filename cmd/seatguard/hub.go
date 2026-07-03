package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"seatguard/core"
	"seatguard/platform"
)

// The control center is seatguard's single home screen. It is reachable two
// ways — after the first-run wizard, and by pressing Esc in the live monitor —
// so there is exactly one place to manage everything. It runs the UI as a
// two-state machine (menu <-> live monitor) over one key-reader goroutine, and
// it never hands the console to a foreground daemon: protection always runs as
// a detached background process, so opening or closing this window never starts
// or stops monitoring by accident.

// hubSignal is what an action asks the control center to do next.
type hubSignal int

const (
	hubStay    hubSignal = iota // redraw the menu (default)
	hubMonitor                  // switch to the live monitor
	hubQuit                     // close the control center
)

// hubHandler runs one menu action and returns what should happen next.
type hubHandler func(next func() keyEvent, paths core.Paths) hubSignal

// runControlCenter is the top-level interactive loop. startInMonitor opens
// straight into the live view (the `dashboard` command); otherwise it opens the
// menu (the setup wizard's landing screen).
func runControlCenter(paths core.Paths, startInMonitor bool) error {
	initColors()
	// The control center needs a real terminal: with redirected/EOF stdin every
	// key read returns Esc, which would instantly self-quit the UI (and spin the
	// reader goroutine). Non-interactive callers should use the plain commands.
	if !platform.StdinInteractive() {
		fmt.Fprintln(os.Stderr, "seatguard: the control center needs an interactive terminal.")
		fmt.Fprintln(os.Stderr, "for non-interactive or service use, see: seatguard status | run | verify | log")
		return nil
	}
	kr := newKeyReader()
	defer kr.close()

	// One reader goroutine feeds a shared channel; whichever view is active
	// consumes from it. next() is the blocking single-key read used by menus
	// and dialogs; the live monitor selects on the channel alongside its timer.
	keys := make(chan keyEvent, 16)
	go func() {
		for {
			keys <- kr.next()
		}
	}()
	next := func() keyEvent { return <-keys }

	fmt.Print(curHide, scrClear)
	defer fmt.Print(curShow, scrClear, "\n")

	monitor := startInMonitor
	for {
		if monitor {
			ensureDaemon(paths) // the monitor should show live data
			if liveDashboard(keys, paths) == dashQuit {
				return nil
			}
			monitor = false // Esc / 's' in the monitor → back to the menu
			continue
		}
		switch hubMenu(next, paths) {
		case hubMonitor:
			monitor = true
		default: // hubQuit
			return nil
		}
	}
}

// hubMenu draws the control center menu, recomputing posture each time it is
// (re)shown, and dispatches the chosen action. It returns only to open the
// monitor or to quit; inline actions loop back here.
func hubMenu(next func() keyEvent, paths core.Paths) hubSignal {
	for {
		p := core.ComputePosture(paths)
		items, handlers := buildHubMenu(p)
		choice := runMenu(next, "seatguard control center",
			"↑↓ move · ⏎ select · Esc quit", hubHeader(p), items)
		if choice == -1 {
			return hubQuit
		}
		if h := handlers[choice]; h != nil {
			if sig := h(next, paths); sig != hubStay {
				return sig
			}
		}
	}
}

// hubHeader renders the status card shown above the menu.
func hubHeader(p *core.Posture) string {
	var b strings.Builder
	pill := fmt.Sprintf(" %s %s ", levelGlyph(p.Level), p.Level.String())
	b.WriteString(fmt.Sprintf("\n  %s%s%s  %s%d/100%s %s\n",
		levelColor(p.Level), pill, cReset, cBold, p.Score, cReset, scoreBar(p.Score)))

	prot := cRed + "○ stopped" + cReset
	if p.Running {
		prot = cGreen + "● running" + cReset
	}
	auto := cDim + "off" + cReset
	if platform.AutostartInstalled("seatguard") {
		auto = cGreen + "on" + cReset
	}
	b.WriteString(fmt.Sprintf("  %sprotection%s %s    %sapps%s %s%d%s    %salerts%s %s%d%s    %sautostart%s %s\n",
		cMuted, cReset, prot,
		cMuted, cReset, cBold, p.Identities, cReset,
		cMuted, cReset, alertColor(p.Alerts), p.Alerts, cReset,
		cMuted, cReset, auto))
	return b.String()
}

// buildHubMenu returns the menu rows and a handler per row (nil for section
// headers), adapting to whether protection is currently running.
func buildHubMenu(p *core.Posture) ([]menuItem, []hubHandler) {
	var items []menuItem
	var hs []hubHandler
	add := func(it menuItem, h hubHandler) { items = append(items, it); hs = append(hs, h) }
	sec := func(label string) { add(menuItem{label: label, section: true}, nil) }
	openMonitor := func(next func() keyEvent, paths core.Paths) hubSignal { return hubMonitor }

	sec("Protection")
	if p.Running {
		add(menuItem{label: "Open live monitor", desc: "full-screen security view", hot: 'd'}, openMonitor)
		add(menuItem{label: "Stop protection", desc: "stop the background monitor", hot: 's'}, actStop)
	} else {
		add(menuItem{label: "Start protection", desc: "begin monitoring in the background", hot: 's'}, actStart)
		if runtime.GOOS == "windows" {
			add(menuItem{label: "Start with tray icon", desc: "monitor hidden, icon near the clock", hot: 't'}, actTray)
		}
		add(menuItem{label: "Open live monitor", desc: "view status (starts monitoring)", hot: 'd'}, openMonitor)
	}

	sec("Setup")
	add(menuItem{label: "Protected Claude apps", desc: "choose which installs to watch", hot: 'c',
		value: fmt.Sprintf("%d", p.Identities)}, actReconfigure)
	add(menuItem{label: "Check for Claude updates", desc: "refresh the baseline after an update", hot: 'u'}, actUpdate)
	autoVal := "Off"
	if platform.AutostartInstalled("seatguard") {
		autoVal = "On"
	}
	add(menuItem{label: "Start at logon", desc: "auto-run protection when you sign in", hot: 'a', value: autoVal}, actAutostart)

	sec("Security & logs")
	add(menuItem{label: "Verify integrity", desc: "re-check database, journal & self-hash", hot: 'v'}, actVerify)
	add(menuItem{label: "View activity log", desc: "recent events and detections", hot: 'l'}, actViewLog)
	add(menuItem{label: "Clear activity log", desc: "erase recorded events", hot: 'k', danger: true}, actClearLog)

	sec("") // horizontal rule before the destructive / exit rows
	add(menuItem{label: "Uninstall seatguard", desc: "remove autostart and all data files", danger: true}, actUninstall)
	add(menuItem{label: "Quit", desc: "close the control center", hot: 'q'},
		func(next func() keyEvent, paths core.Paths) hubSignal { return hubQuit })

	return items, hs
}

// ---- actions ----

func actStart(next func() keyEvent, paths core.Paths) hubSignal {
	fmt.Print(scrClear)
	fmt.Printf("\n  %s◇%s starting protection…\n", cCyan, cReset)
	if err := startBackgroundDaemon(paths.Args()); err != nil {
		fmt.Printf("\n  %s✗ could not start: %v%s\n", cRed, err, cReset)
		pressAnyKey(next)
		return hubStay
	}
	waitDaemon(paths, 6*time.Second)
	if daemonRunning(paths) {
		fmt.Printf("\n  %s✓ protection is running in the background.%s\n", cGreen, cReset)
		fmt.Printf("  %stip: enable “Start at logon” so it turns on automatically.%s\n", cMuted, cReset)
	} else {
		fmt.Printf("\n  %s! could not confirm protection started.%s\n", cYell, cReset)
		fmt.Printf("  %sit may be starting slowly, already running, or blocked by an integrity%s\n", cMuted, cReset)
		fmt.Printf("  %scheck or by needing elevation. Try “Verify integrity” or view the log.%s\n", cMuted, cReset)
	}
	pressAnyKey(next)
	return hubStay
}

func actTray(next func() keyEvent, paths core.Paths) hubSignal {
	fmt.Print(scrClear)
	fmt.Printf("\n  %s◇%s starting protection in the system tray…\n", cCyan, cReset)
	if err := startBackgroundDaemon(append(paths.Args(), "--tray")); err != nil {
		fmt.Printf("\n  %s✗ could not start: %v%s\n", cRed, err, cReset)
		pressAnyKey(next)
		return hubStay
	}
	waitDaemon(paths, 6*time.Second)
	if daemonRunning(paths) {
		fmt.Printf("\n  %s✓ running in the system tray%s — look for the shield icon near the clock.\n", cGreen, cReset)
		fmt.Printf("  %sright-click it for status, the dashboard, or to quit.%s\n", cMuted, cReset)
	} else {
		fmt.Printf("\n  %s! could not confirm the tray monitor started.%s\n", cYell, cReset)
		fmt.Printf("  %sit may already be running, or be blocked by an integrity check.%s\n", cMuted, cReset)
	}
	pressAnyKey(next)
	return hubStay
}

func actStop(next func() keyEvent, paths core.Paths) hubSignal {
	fmt.Print(scrClear)
	fmt.Printf("\n  %s◇%s stopping protection…\n", cCyan, cReset)
	switch stopped, err := stopDaemon(paths); {
	case err != nil:
		fmt.Printf("\n  %s! %v%s\n", cYell, err, cReset)
		fmt.Printf("  %sif it is running in the tray, quit it from the tray icon.%s\n", cMuted, cReset)
	case stopped:
		fmt.Printf("\n  %s✓ protection stopped.%s\n", cGreen, cReset)
	default:
		fmt.Printf("\n  %sprotection was not running.%s\n", cMuted, cReset)
	}
	pressAnyKey(next)
	return hubStay
}

func actReconfigure(next func() keyEvent, paths core.Paths) hubSignal {
	var pre map[string]bool
	if b := loadExisting(paths); b != nil {
		pre = enrolledSet(b)
	}
	b, err := selectAndEnroll(next, paths, 4, pre)
	if err != nil {
		fmt.Printf("\n  %s%v%s\n", cYell, err, cReset)
		pressAnyKey(next)
		return hubStay
	}
	if b == nil {
		return hubStay // cancelled; selectAndEnroll already reported
	}
	fmt.Printf("\n  %s✓ selection saved (%d apps protected).%s\n", cGreen, len(b.Identities), cReset)
	if daemonRunning(paths) {
		fmt.Printf("  %srestart protection (Stop, then Start) to load the new selection.%s\n", cMuted, cReset)
	}
	pressAnyKey(next)
	return hubStay
}

func actUpdate(next func() keyEvent, paths core.Paths) hubSignal {
	fmt.Print(scrClear)
	if err := updateBaseline(paths); err != nil {
		fmt.Printf("\n  %s✗ %v%s\n", cRed, err, cReset)
	}
	pressAnyKey(next)
	return hubStay
}

func actAutostart(next func() keyEvent, paths core.Paths) hubSignal {
	fmt.Print(scrClear)
	if platform.AutostartInstalled("seatguard") {
		if err := platform.RemoveAutostart("seatguard"); err != nil {
			fmt.Printf("\n  %s✗ could not disable autostart: %v%s\n", cRed, err, cReset)
		} else {
			fmt.Printf("\n  %s✓ autostart disabled%s — seatguard will not run at logon.\n", cGreen, cReset)
		}
	} else {
		_ = installAutostart(paths) // prints its own success/failure detail
	}
	pressAnyKey(next)
	return hubStay
}

func actVerify(next func() keyEvent, paths core.Paths) hubSignal {
	fmt.Print(scrClear, curShow)
	fmt.Printf("\n  %sVerifying integrity…%s\n\n", cBold, cReset)
	if _, err := core.VerifyAll(paths, os.Stdout); err != nil {
		fmt.Printf("\n  %s✗ integrity check FAILED — see the report above.%s\n", cRed, cReset)
	} else {
		fmt.Printf("\n  %s✓ all integrity checks passed.%s\n", cGreen, cReset)
	}
	pressAnyKey(next)
	fmt.Print(curHide)
	return hubStay
}

func actViewLog(next func() keyEvent, paths core.Paths) hubSignal {
	fmt.Print(scrClear, curShow)
	printRecentLog(paths, 25)
	pressAnyKey(next)
	fmt.Print(curHide)
	return hubStay
}

func actClearLog(next func() keyEvent, paths core.Paths) hubSignal {
	if !runConfirm(next, "Clear the activity log?", []string{
		"This erases all recorded events and detections and starts a",
		"fresh tamper-evident log. It cannot be undone.",
	}, "Clear log", true) {
		return hubStay
	}
	fmt.Print(scrClear)
	// A running daemon holds stale chain state in memory; stop it first so the
	// fresh log cannot develop a sequence gap, then let the user restart it.
	stopped := false
	if daemonRunning(paths) {
		switch ok, err := stopDaemon(paths); {
		case err != nil:
			fmt.Printf("\n  %s! could not stop the running monitor: %v%s\n", cYell, err, cReset)
			fmt.Printf("  %sstop it (from the tray) and clear the log while stopped.%s\n", cMuted, cReset)
			pressAnyKey(next)
			return hubStay
		case ok:
			stopped = true
		}
	}
	key, err := core.LoadKey(paths.Key)
	if err != nil {
		fmt.Printf("\n  %s✗ %v%s\n", cRed, err, cReset)
		pressAnyKey(next)
		return hubStay
	}
	if err := core.ClearJournal(paths, key); err != nil {
		fmt.Printf("\n  %s✗ clear failed: %v%s\n", cRed, err, cReset)
	} else {
		fmt.Printf("\n  %s✓ activity log cleared.%s\n", cGreen, cReset)
		if stopped {
			fmt.Printf("  %sprotection was stopped — start it again from the menu.%s\n", cMuted, cReset)
		}
	}
	pressAnyKey(next)
	return hubStay
}

func actUninstall(next func() keyEvent, paths core.Paths) hubSignal {
	if !runConfirm(next, "Uninstall seatguard?", []string{
		"This stops protection and permanently deletes:",
		"  · the enrolled baseline and its HMAC key",
		"  · the activity log and journal archive",
		"  · the autostart entry (if set)",
		"",
		"The seatguard program file is left in place so you can delete",
		"it afterwards. This cannot be undone.",
	}, "Uninstall", true) {
		return hubStay
	}
	fmt.Print(scrClear)
	fmt.Printf("\n  %s◇%s uninstalling…\n", cCyan, cReset)
	if daemonRunning(paths) {
		if _, err := stopDaemon(paths); err != nil {
			fmt.Printf("  %s! could not stop the running monitor (%v)%s\n", cYell, err, cReset)
			fmt.Printf("  %squit it from the tray icon, then uninstall again.%s\n", cMuted, cReset)
			pressAnyKey(next)
			return hubStay
		}
		fmt.Printf("  %s· protection stopped%s\n", cMuted, cReset)
	}
	res := core.Uninstall(paths)
	if res.AutostartRemoved {
		fmt.Printf("  %s· autostart removed%s\n", cMuted, cReset)
	}
	fmt.Printf("  %s· %d data file(s) deleted%s\n", cMuted, len(res.Removed), cReset)
	if len(res.Failed) > 0 {
		fmt.Printf("\n  %s! some files could not be deleted:%s\n", cYell, cReset)
		for p, e := range res.Failed {
			fmt.Printf("    %s%s — %s%s\n", cDim, shortPath(p), e, cReset)
		}
		fmt.Printf("  %sdelete them manually (elevation may be required).%s\n", cMuted, cReset)
	}
	self, _ := os.Executable()
	fmt.Printf("\n  %s✓ seatguard uninstalled.%s\n", cGreen, cReset)
	if self != "" {
		fmt.Printf("  %syou can now delete the program file:%s\n    %s%s%s\n", cMuted, cReset, cDim, self, cReset)
	}
	pressAnyKey(next)
	return hubQuit // nothing left to manage
}

// ---- daemon helpers ----

// daemonRunning reports whether a background monitor is live for these paths.
func daemonRunning(paths core.Paths) bool {
	st, err := core.ReadDaemonState(paths.State)
	return err == nil && st.Running()
}

// ensureDaemon starts a background monitor if none is running, so the live view
// shows real data rather than "stopped".
func ensureDaemon(paths core.Paths) {
	if daemonRunning(paths) {
		return
	}
	if err := startBackgroundDaemon(paths.Args()); err == nil {
		waitDaemon(paths, 4*time.Second)
	}
}

// waitDaemon blocks until a monitor reports running or the deadline passes.
func waitDaemon(paths core.Paths, d time.Duration) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if daemonRunning(paths) {
			return
		}
		time.Sleep(120 * time.Millisecond)
	}
}

// stopDaemon stops a running monitor and confirms it is actually gone. It first
// verifies the state file's PID is a real seatguard process (guarding against
// PID reuse — the very risk seatguard exists to catch), signals a graceful
// stop, and — if the process is still alive after a window longer than one poll
// cycle — escalates to a forced kill.
//
// It returns (true, nil) ONLY when the process is confirmed to have exited, so
// destructive callers (clear log, uninstall) can safely proceed. A timeout with
// the process still alive returns (false, err) so those callers abort instead of
// acting against a live daemon. (false, nil) means nothing was running.
func stopDaemon(paths core.Paths) (bool, error) {
	st, err := core.ReadDaemonState(paths.State)
	if err != nil || !st.Running() {
		return false, nil
	}
	if !pidIsSeatguard(st.PID) {
		return false, fmt.Errorf("the recorded monitor (pid %d) is not a verifiable seatguard process", st.PID)
	}
	if err := stopPID(st.PID); err != nil {
		return false, err
	}
	// The daemon services the stop signal only when its poll loop next re-enters
	// select, which can be up to PollSecs away if it is mid-poll — so the
	// graceful window must exceed one full poll cycle.
	poll := st.PollSecs
	if poll < 4 {
		poll = 4
	}
	if waitPidGone(st.PID, time.Duration(poll+4)*time.Second) {
		return true, nil
	}
	// Still alive after a graceful window → escalate to a forced kill and
	// confirm it really exits before reporting success.
	_ = stopPIDForce(st.PID)
	if waitPidGone(st.PID, 3*time.Second) {
		return true, nil
	}
	return false, fmt.Errorf("monitor (pid %d) did not exit after a stop request and forced kill", st.PID)
}

// waitPidGone polls until pid is no longer a running seatguard process, or the
// deadline passes. Returns true only when the process is confirmed gone.
func waitPidGone(pid int, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		if !pidIsSeatguard(pid) {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// pidIsSeatguard reports whether pid is a running instance of this executable.
// Reusing InstancesOf keeps the check PID-reuse-safe: a reused PID belonging to
// some unrelated process will not match our own binary path.
func pidIsSeatguard(pid int) bool {
	self, err := os.Executable()
	if err != nil {
		return false
	}
	self = platform.CanonPath(self)
	insts, err := platform.New().InstancesOf(self)
	if err != nil {
		return false
	}
	for _, in := range insts {
		if int(in.PID) == pid {
			return true
		}
	}
	return false
}
