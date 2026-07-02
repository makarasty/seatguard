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

	b.WriteString(fmt.Sprintf("\n  %supdated %s%s   %s[q]%s quit  %s[v]%s verify  %s[u]%s update  %s[l]%s log\n",
		cMuted, p.GeneratedAt.Format("15:04:05"), cReset,
		cCyan, cReset, cCyan, cReset, cCyan, cReset, cCyan, cReset))
	return b.String()
}

func alertColor(n int) string {
	if n > 0 {
		return cRed + cBold
	}
	return cGreen
}

const (
	clearHome = "\x1b[H\x1b[2J"
	cursorTop = "\x1b[H\x1b[0J"
	hideCur   = "\x1b[?25l"
	showCur   = "\x1b[?25h"
)

// cmdDashboard renders a live, auto-refreshing security dashboard for the
// current baseline/daemon. Read-only except for the [u]pdate and [v]erify
// hotkeys. Attaches to whatever `run` daemon is writing the state file.
func cmdDashboard(args []string) error {
	fs := flag.NewFlagSet("dashboard", flag.ExitOnError)
	paths := pathFlags(fs)
	every := fs.Duration("refresh", 1500*time.Millisecond, "refresh interval")
	fs.Parse(args)

	initColors()
	kr := newKeyReader()
	defer kr.close()

	keys := make(chan keyEvent, 8)
	go func() {
		for {
			keys <- kr.next()
		}
	}()

	fmt.Print(hideCur, clearHome)
	defer fmt.Print(showCur, "\n")

	ticker := time.NewTicker(*every)
	defer ticker.Stop()
	tick := 0
	draw := func() {
		p := core.ComputePosture(*paths)
		fmt.Print(cursorTop, renderPosture(p, tick))
		tick++
	}
	draw()

	// hotkey extracts a lowercase command letter from a key event.
	hotkey := func(ev keyEvent) byte {
		if ev.k == keyChar {
			return lower(ev.r)
		}
		if ev.k == keyEsc {
			return 'q'
		}
		return 0
	}

	for {
		select {
		case <-ticker.C:
			draw()
		case ev := <-keys:
			switch hotkey(ev) {
			case 'q':
				return nil
			case 'v':
				fmt.Print(clearHome)
				fmt.Printf("%sRe-verifying integrity...%s\n\n", cBold, cReset)
				core.VerifyAll(*paths, os.Stdout)
				fmt.Printf("\n%spress any key to return%s", cDim, cReset)
				<-keys
				fmt.Print(clearHome)
				draw()
			case 'u':
				fmt.Print(clearHome)
				if err := updateBaseline(*paths); err != nil {
					fmt.Printf("%supdate failed: %v%s\n", cRed, err, cReset)
				}
				fmt.Printf("\n%spress any key to return%s", cDim, cReset)
				<-keys
				fmt.Print(clearHome)
				draw()
			case 'l':
				fmt.Print(clearHome, showCur)
				printRecentLog(*paths, 20)
				fmt.Printf("\n%spress any key to return%s", cDim, cReset)
				<-keys
				fmt.Print(hideCur, clearHome)
				draw()
			}
		}
	}
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
