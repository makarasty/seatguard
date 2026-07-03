package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"seatguard/core"
	"seatguard/platform"
)

// ---- color helpers keyed off the posture level ----

func levelColor(l core.Level) string {
	switch l {
	case core.LevelProtected:
		return cInvGreen
	case core.LevelWarning:
		return cInvYell
	case core.LevelAtRisk:
		return cInvRed
	default:
		return cInvGrey
	}
}

func levelGlyph(l core.Level) string {
	switch l {
	case core.LevelProtected:
		return "🛡"
	case core.LevelWarning:
		return "⚠"
	case core.LevelAtRisk:
		return "⛔"
	default:
		return "○"
	}
}

func sevGlyph(s core.Severity) string {
	switch s {
	case core.SevOK:
		return cGreen + "✓" + cReset
	case core.SevWarn:
		return cYell + "!" + cReset
	default:
		return cRed + "✗" + cReset
	}
}

// scoreBar renders a 0..100 score as a 20-cell bar.
func scoreBar(score int) string {
	const width = 20
	filled := score * width / 100
	col := cGreen
	switch {
	case score < 50:
		col = cRed
	case score < 80:
		col = cYell
	}
	return col + strings.Repeat("█", filled) + cDim + strings.Repeat("░", width-filled) + cReset
}

// renderPosture builds the full-screen dashboard frame in a modern TUI style.
func renderPosture(p *core.Posture, tick int) string {
	var b strings.Builder
	spin := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}[tick%10]

	// Header.
	b.WriteString(fmt.Sprintf("\n  %s%s🛡 seatguard%s  %s· live security monitor%s\n",
		cBold, cCyan, cReset, cMuted, cReset))

	// Status pill + score bar.
	pill := fmt.Sprintf(" %s %s ", levelGlyph(p.Level), p.Level.String())
	b.WriteString(fmt.Sprintf("\n  %s%s%s   %s%d/100%s %s\n",
		levelColor(p.Level), pill, cReset, cBold, p.Score, cReset, scoreBar(p.Score)))

	mon := cRed + "○ stopped" + cReset
	if p.Running {
		mon = cGreen + "● live " + spin + cReset
	}
	b.WriteString(fmt.Sprintf("  %smonitor%s %s   %sidentities%s %s%d%s   %spolls%s %d   %salerts%s %s%d%s\n\n",
		cMuted, cReset, mon, cMuted, cReset, cBold, p.Identities, cReset,
		cMuted, cReset, p.Polls, cMuted, cReset, alertColor(p.Alerts), p.Alerts, cReset))

	// Checks.
	b.WriteString(fmt.Sprintf("  %s╭─ security checks %s%s\n", cCyan, strings.Repeat("─", 44), cReset))
	for _, c := range p.Checks {
		b.WriteString(fmt.Sprintf("  %s│%s %s %-19s %s%s%s\n", cCyan, cReset, sevGlyph(c.Status), c.Name, cMuted, c.Detail, cReset))
	}
	b.WriteString(fmt.Sprintf("  %s╰%s%s\n", cCyan, strings.Repeat("─", 61), cReset))

	// Coverage gaps.
	if len(p.UnenrolledInstalls) > 0 {
		b.WriteString(fmt.Sprintf("\n  %s⚠ unenrolled Claude installs%s %s(press u to fix)%s\n", cYell, cReset, cMuted, cReset))
		for _, u := range p.UnenrolledInstalls {
			b.WriteString(fmt.Sprintf("    %s· %s%s\n", cDim, shortPath(u), cReset))
		}
	}
	if len(p.StaleBinaries) > 0 {
		b.WriteString(fmt.Sprintf("\n  %s⚠ changed since enroll — likely a Claude update%s %s(press u)%s\n", cYell, cReset, cMuted, cReset))
		for _, s := range p.StaleBinaries {
			b.WriteString(fmt.Sprintf("    %s· %s%s\n", cDim, shortPath(s), cReset))
		}
	}

	// Latest alert.
	if p.LastAlert != nil {
		a := p.LastAlert
		b.WriteString(fmt.Sprintf("\n  %s%s⛔ latest detection%s\n", cBold, cRed, cReset))
		b.WriteString(fmt.Sprintf("    %ssignal%s %s   %sbinary%s %s%s%s\n", cMuted, cReset, a.Signal, cMuted, cReset, cRed, a.ExePath, cReset))
		b.WriteString(fmt.Sprintf("    %spid%s %d %s(start %d)%s   %starget%s %s\n", cMuted, cReset, a.PID, cDim, a.StartTime, cReset, cMuted, cReset, a.Target))
	}

	b.WriteString(fmt.Sprintf("\n  %supdated %s%s   %sEsc%s menu   %s[v]%s verify  %s[u]%s update  %s[l]%s log  %s[q]%s quit\n",
		cMuted, p.GeneratedAt.Format("15:04:05"), cReset,
		cCyan, cReset, cCyan, cReset, cCyan, cReset, cCyan, cReset, cCyan, cReset))
	return b.String()
}

func alertColor(n int) string {
	if n > 0 {
		return cRed + cBold
	}
	return cGreen
}

// cmdDashboard opens the control center straight into the live monitor. The
// monitor and the menu are two views of one program (Esc toggles between them),
// so "settings" is always one key away and always the same screen.
func cmdDashboard(args []string) error {
	fs := flag.NewFlagSet("dashboard", flag.ExitOnError)
	paths := pathFlags(fs)
	fs.Parse(args)
	return runControlCenter(*paths, true)
}

// dashResult is how the live monitor exits: back to the menu, or quit.
type dashResult int

const (
	dashToMenu dashResult = iota
	dashQuit
)

// liveDashboard runs the full-screen, auto-refreshing monitor. It consumes keys
// from the shared channel (so it can refresh on a timer and react to keys at
// once) and returns when the user presses Esc/'s' (menu) or 'q' (quit). The
// read-only view has three in-place hotkeys: verify, update and log.
func liveDashboard(keys <-chan keyEvent, paths core.Paths) dashResult {
	next := func() keyEvent { return <-keys }
	fmt.Print(curHide, scrClear)

	ticker := time.NewTicker(1500 * time.Millisecond)
	defer ticker.Stop()
	tick := 0
	draw := func() {
		p := core.ComputePosture(paths)
		fmt.Print(cursorHome, renderPosture(p, tick))
		tick++
	}
	draw()

	// After an in-place action returns, redraw the live frame.
	redraw := func() { fmt.Print(curHide, scrClear); draw() }

	for {
		select {
		case <-ticker.C:
			draw()
		case ev := <-keys:
			switch dashHotkey(ev) {
			case 'q':
				return dashQuit
			case 's': // Esc or 's' → back to the control center menu
				return dashToMenu
			case 'v':
				fmt.Print(scrClear, curShow)
				fmt.Printf("\n  %sVerifying integrity…%s\n\n", cBold, cReset)
				core.VerifyAll(paths, os.Stdout)
				pressAnyKey(next)
				redraw()
			case 'u':
				fmt.Print(scrClear, curShow)
				if err := updateBaseline(paths); err != nil {
					fmt.Printf("\n  %supdate failed: %v%s\n", cRed, err, cReset)
				}
				pressAnyKey(next)
				redraw()
			case 'l':
				fmt.Print(scrClear, curShow)
				printRecentLog(paths, 20)
				pressAnyKey(next)
				redraw()
			}
		}
	}
}

// dashHotkey maps a key event to a monitor command letter; Esc is treated as
// 's' so it opens the menu rather than quitting.
func dashHotkey(ev keyEvent) byte {
	if ev.k == keyChar {
		return lower(ev.r)
	}
	if ev.k == keyEsc {
		return 's'
	}
	return 0
}

// updateBaseline re-discovers and re-enrolls all Claude installs, refreshing
// hashes after a Claude update. Note: a running daemon keeps its in-memory
// baseline until restarted — the dashboard says so.
func updateBaseline(paths core.Paths) error {
	fmt.Printf("%sRe-scanning and refreshing baseline...%s\n", cBold, cReset)
	b, err := core.Enroll(paths, platform.New(), core.EnrollOptions{PollSecs: 4})
	if err != nil {
		return err
	}
	fmt.Printf("%sBaseline updated: %d identities.%s\n", cGreen, len(b.Identities), cReset)
	fmt.Printf("%sRestart protection for a running daemon to load the new baseline.%s\n", cYell, cReset)
	return nil
}

func printRecentLog(paths core.Paths, n int) {
	key, err := core.LoadKey(paths.Key)
	if err != nil {
		fmt.Printf("%s%v%s\n", cRed, err, cReset)
		return
	}
	entries, _ := core.VerifyJournal(paths.Journal, key)
	fmt.Printf("%sRecent journal (%d of %d records):%s\n\n", cBold, minInt(n, len(entries)), len(entries), cReset)
	start := 0
	if len(entries) > n {
		start = len(entries) - n
	}
	for _, e := range entries[start:] {
		col := cDim
		if e.Type == "alert" {
			col = cRed
		}
		fmt.Printf("  %s%s #%d [%s]%s %s\n", col, e.TS, e.Seq, e.Type, cReset, truncate(string(e.Data), 80))
	}
}

// renderStatusOneShot is the upgraded `status` output (non-interactive).
func renderStatusOneShot(paths core.Paths) {
	initColors()
	p := core.ComputePosture(paths)
	fmt.Printf("\n  %s%s %s %s   score %d/100  %s\n\n",
		levelColor(p.Level), " "+p.Level.String()+" ", cReset, "", p.Score, scoreBar(p.Score))
	for _, c := range p.Checks {
		fmt.Printf("   %s %-20s %s%s%s\n", sevGlyph(c.Status), c.Name, cDim, c.Detail, cReset)
	}
	if p.LastAlert != nil {
		fmt.Printf("\n  %s⚠ latest detection:%s %s (%s)\n", cRed, cReset, filepath.Base(p.LastAlert.ExePath), p.LastAlert.Target)
	}
	fmt.Println()
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
