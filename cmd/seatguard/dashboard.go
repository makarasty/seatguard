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
		return "\x1b[42;30m" // green bg
	case core.LevelWarning:
		return "\x1b[43;30m" // yellow bg
	case core.LevelAtRisk:
		return "\x1b[41;37m" // red bg
	default:
		return "\x1b[47;30m" // grey bg
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

// renderPosture builds the full-screen dashboard frame.
func renderPosture(p *core.Posture, tick int) string {
	var b strings.Builder
	spin := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}[tick%10]

	line := strings.Repeat("─", 62)
	b.WriteString(fmt.Sprintf("%s%s┌%s┐%s\n", cBold, cCyan, line, cReset))
	title := "seatguard — Claude subscription-token guard"
	b.WriteString(fmt.Sprintf("%s%s│%s %-60s %s%s│%s\n", cBold, cCyan, cReset, title, cBold, cCyan, cReset))
	b.WriteString(fmt.Sprintf("%s%s└%s┘%s\n", cBold, cCyan, line, cReset))

	// Headline banner.
	banner := fmt.Sprintf("  %s  ", p.Level.String())
	b.WriteString(fmt.Sprintf("\n  %s%s%s   security score %s%d/100%s  %s\n",
		levelColor(p.Level), banner, cReset, cBold, p.Score, cReset, scoreBar(p.Score)))

	mon := cRed + "stopped" + cReset
	if p.Running {
		mon = cGreen + "live " + spin + cReset
	}
	b.WriteString(fmt.Sprintf("  monitor: %s   identities: %s%d%s   polls: %d   alerts: %s%d%s\n\n",
		mon, cBold, p.Identities, cReset, p.Polls, alertColor(p.Alerts), p.Alerts, cReset))

	// Checks.
	b.WriteString(fmt.Sprintf("  %sSECURITY CHECKS%s\n", cBold, cReset))
	for _, c := range p.Checks {
		b.WriteString(fmt.Sprintf("   %s %-20s %s%s%s\n", sevGlyph(c.Status), c.Name, cDim, c.Detail, cReset))
	}

	// Coverage gaps detail.
	if len(p.UnenrolledInstalls) > 0 {
		b.WriteString(fmt.Sprintf("\n  %sUnenrolled Claude installs (press [u] to fix):%s\n", cYell, cReset))
		for _, u := range p.UnenrolledInstalls {
			b.WriteString(fmt.Sprintf("   %s· %s%s\n", cDim, u, cReset))
		}
	}
	if len(p.StaleBinaries) > 0 {
		b.WriteString(fmt.Sprintf("\n  %sChanged since enroll — likely a Claude update (press [u]):%s\n", cYell, cReset))
		for _, s := range p.StaleBinaries {
			b.WriteString(fmt.Sprintf("   %s· %s%s\n", cDim, s, cReset))
		}
	}

	// Latest alert.
	if p.LastAlert != nil {
		a := p.LastAlert
		b.WriteString(fmt.Sprintf("\n  %s%s⚠ LATEST DETECTION%s\n", cBold, cRed, cReset))
		b.WriteString(fmt.Sprintf("   signal : %s\n", a.Signal))
		b.WriteString(fmt.Sprintf("   binary : %s%s%s\n", cRed, a.ExePath, cReset))
		b.WriteString(fmt.Sprintf("   pid    : %d (start_time %d)\n", a.PID, a.StartTime))
		b.WriteString(fmt.Sprintf("   target : %s\n", a.Target))
	}

	b.WriteString(fmt.Sprintf("\n  %supdated %s · [q]uit  [v]erify  [u]pdate baseline  [l]og%s\n",
		cDim, p.GeneratedAt.Format("15:04:05"), cReset))
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
	restore, raw := platform.RawInput()
	defer restore()

	keys := make(chan byte, 8)
	if raw {
		go func() {
			buf := make([]byte, 1)
			for {
				if n, err := os.Stdin.Read(buf); err != nil || n == 0 {
					return
				}
				keys <- buf[0]
			}
		}()
	}

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

	for {
		select {
		case <-ticker.C:
			draw()
		case k := <-keys:
			switch k {
			case 'q', 'Q', 3 /*Ctrl-C*/ :
				return nil
			case 'v', 'V':
				fmt.Print(clearHome)
				fmt.Printf("%sRe-verifying integrity...%s\n\n", cBold, cReset)
				core.VerifyAll(*paths, os.Stdout)
				fmt.Printf("\n%spress any key to return%s", cDim, cReset)
				<-keys
				fmt.Print(clearHome)
				draw()
			case 'u', 'U':
				fmt.Print(clearHome)
				if err := updateBaseline(*paths); err != nil {
					fmt.Printf("%supdate failed: %v%s\n", cRed, err, cReset)
				}
				fmt.Printf("\n%spress any key to return%s", cDim, cReset)
				<-keys
				fmt.Print(clearHome)
				draw()
			case 'l', 'L':
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
