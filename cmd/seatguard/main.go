// seatguard — local detector for theft and abuse of the Claude
// subscription OAuth token. Phase 1: polling mode.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"seatguard/core"
	"seatguard/platform"
)

func main() {
	if len(os.Args) < 2 {
		// No arguments (e.g. double-clicked): interactive setup wizard.
		if err := cmdSetup(nil); err != nil {
			fmt.Fprintf(os.Stderr, "seatguard setup: %v\n", err)
			os.Exit(1)
		}
		return
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "setup":
		err = cmdSetup(args)
	case "enroll":
		err = cmdEnroll(args)
	case "run":
		err = cmdRun(args)
	case "dashboard", "dash", "ui":
		err = cmdDashboard(args)
	case "status":
		err = cmdStatus(args)
	case "verify":
		err = cmdVerify(args)
	case "log":
		err = cmdLog(args)
	case "autostart":
		err = cmdAutostart(args)
	case "clear-log":
		err = cmdClearLog(args)
	case "uninstall":
		err = cmdUninstall(args)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "seatguard %s: %v\n", cmd, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: seatguard <command> [flags]

Launched with no arguments, seatguard opens the interactive control center
(first run: a setup wizard that finds your Claude installs and enrolls them).

commands:
  setup      first-run wizard, then the control center (default with no args)
  dashboard  open the control center on the live security monitor
  enroll     create the protected baseline of legitimate Claude binaries
  run        start the polling detection daemon (foreground; --tray for tray)
  status     one-shot security posture and score
  verify     check baseline HMAC, journal hash chain and daemon self-hash
  log        print the event journal
  clear-log  erase the activity log (needs --yes)
  autostart  install|remove the logon autostart entry
  uninstall  stop protection and remove all data + autostart (needs --yes)

common flags: --db --key --journal --state (see 'seatguard <cmd> -h')
`)
}

// pathFlags registers the shared location flags on fs.
func pathFlags(fs *flag.FlagSet) *core.Paths {
	def := core.DefaultPaths()
	p := &core.Paths{}
	fs.StringVar(&p.DB, "db", def.DB, "baseline database file")
	fs.StringVar(&p.Key, "key", def.Key, "HMAC key file (kept separate from the DB)")
	fs.StringVar(&p.Journal, "journal", def.Journal, "append-only event journal")
	fs.StringVar(&p.State, "state", def.State, "daemon state file")
	return p
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func cmdEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	paths := pathFlags(fs)
	var bins, dirs, creds, hosts, ips multiFlag
	fs.Var(&bins, "claude-path", "explicit binary to enroll (repeatable)")
	fs.Var(&dirs, "claude-dir", "Claude install dir for the interpreter rule (repeatable)")
	fs.Var(&creds, "cred", "credential file to watch (repeatable; default: well-known Claude paths)")
	fs.Var(&hosts, "api-host", "API host to resolve and watch (repeatable; default: api.anthropic.com, claude.ai; '-' for none)")
	fs.Var(&ips, "api-ip", "static API IP to watch (repeatable; test use)")
	poll := fs.Int("poll", 4, "poll interval, seconds (3-5 recommended)")
	noDiscover := fs.Bool("no-discover", false, "skip auto-discovery of Claude installs")
	fs.Parse(args)

	apiHosts := core.DefaultAPIHosts()
	if len(hosts) > 0 {
		apiHosts = nil
		for _, h := range hosts {
			if h != "-" {
				apiHosts = append(apiHosts, h)
			}
		}
	}
	b, err := core.Enroll(*paths, platform.New(), core.EnrollOptions{
		ExtraBinaries: bins,
		InstallDirs:   dirs,
		CredPaths:     creds,
		APIHosts:      apiHosts,
		APIIPs:        ips,
		PollSecs:      *poll,
		NoDiscover:    *noDiscover,
	})
	if err != nil {
		return err
	}
	fmt.Printf("enrolled %d identities; baseline written to %s\n", len(b.Identities), paths.DB)
	for _, id := range b.Identities {
		fmt.Printf("  %s sha256=%s...\n", id.Path, id.SHA256[:16])
	}
	return nil
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	paths := pathFlags(fs)
	tray := fs.Bool("tray", false, "run hidden in the system tray (Windows)")
	requirePriv := fs.Bool("require-privileged", false, "refuse to start unless running elevated (Administrator/root)")
	fs.Parse(args)

	// Fail-safe startup: refuse to run on any integrity mismatch, loudly.
	b, err := core.VerifyAll(*paths, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ALERT [integrity] seatguard refuses to start: baseline/journal/self verification failed")
		os.Exit(2)
	}
	if !platform.IsPrivileged() {
		if *requirePriv {
			fmt.Fprintln(os.Stderr, "seatguard: --require-privileged set but not running elevated; refusing to start")
			os.Exit(5)
		}
		fmt.Fprintln(os.Stderr, "WARNING: running unprivileged — the baseline/key/journal are not owner-protected, so tamper-evidence is weakened. Run elevated (Administrator/root) with the default paths for full protection.")
	}

	// Single-instance: two daemons on one baseline would race the state file
	// and corrupt the journal's HMAC chain. Refuse the second.
	unlock, acquired, lerr := platform.Lock(paths.DB)
	if lerr != nil {
		fmt.Fprintf(os.Stderr, "warning: could not acquire instance lock (%v); continuing\n", lerr)
	} else if !acquired {
		fmt.Fprintln(os.Stderr, "seatguard is already running for this baseline; not starting a second instance")
		os.Exit(4)
	} else {
		defer unlock()
	}

	eng := &core.Engine{
		Backend:  platform.New(),
		Baseline: b,
		Stderr:   os.Stderr,
		Paths:    *paths,
	}
	key, err := core.LoadKey(paths.Key)
	if err != nil {
		return err
	}
	j, err := core.OpenJournal(paths.Journal, key)
	if err != nil {
		return err
	}
	eng.Journal = j

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *tray {
		return runInTray(ctx, stop, eng, *paths, b)
	}

	fmt.Fprintf(os.Stderr, "seatguard running: %d identities, %d cred paths, poll %ds — press Esc or Ctrl+C to stop\n",
		len(b.Identities), len(b.CredPaths), b.PollSecs)

	// Interactive foreground: watch the keyboard so Esc / q / Ctrl+C stop the
	// daemon even when the console was left in raw mode by a caller (e.g. the
	// setup wizard), where Ctrl+C is delivered as a byte instead of a signal.
	// Skipped for piped/redirected/service stdin, which relies on signals.
	if platform.StdinInteractive() {
		kr := platform.NewKeyInput()
		defer kr.Close()
		go func() {
			for {
				k, r := kr.Read()
				if k == platform.KeyEsc || (k == platform.KeyRune && (r == 'q' || r == 'Q')) {
					fmt.Fprintln(os.Stderr, "\nstopping…")
					stop()
					return
				}
			}
		}()
	}
	return eng.Run(ctx)
}

// traySummary renders the posture as plain multi-line text for the tray's
// status message box.
func traySummary(p *core.Posture) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s   —   security score %d/100\n\n", p.Level, p.Score)
	for _, c := range p.Checks {
		mark := "OK  "
		switch c.Status {
		case core.SevWarn:
			mark = "WARN"
		case core.SevFail:
			mark = "FAIL"
		}
		fmt.Fprintf(&b, "[%s] %s: %s\n", mark, c.Name, c.Detail)
	}
	return b.String()
}

// runInTray hides the console, runs the engine in the background, and shows
// a system-tray icon whose color reflects the live security posture. On
// non-Windows the tray call returns ErrTrayUnsupported and we fall back to
// the normal foreground loop.
func runInTray(ctx context.Context, stop context.CancelFunc, eng *core.Engine, paths core.Paths, b *core.Baseline) error {
	self, _ := os.Executable()
	dashArgs := paths.Args()

	engErr := make(chan error, 1)
	go func() { engErr <- eng.Run(ctx) }()

	refresh := func() platform.TrayInfo {
		p := core.ComputePosture(paths)
		lvl := platform.TrayGreen
		switch p.Level {
		case core.LevelWarning:
			lvl = platform.TrayYellow
		case core.LevelAtRisk, core.LevelUnprotected:
			lvl = platform.TrayRed
		}
		info := platform.TrayInfo{
			Level:      lvl,
			Tooltip:    fmt.Sprintf("seatguard: %s (score %d/100)", p.Level, p.Score),
			AlertCount: p.Alerts,
			Summary:    traySummary(p),
		}
		if p.LastAlert != nil {
			info.AlertText = fmt.Sprintf("%s accessed %s", p.LastAlert.ExePath, p.LastAlert.Target)
		}
		return info
	}

	platform.HideConsole()
	runtime.LockOSThread()
	err := platform.RunTray("seatguard", self, dashArgs, refresh, func() { stop() })
	if err == platform.ErrTrayUnsupported {
		// Fall back to foreground on non-Windows.
		fmt.Fprintf(os.Stderr, "seatguard running (tray unsupported here): %d identities\n", len(b.Identities))
		return <-engErr
	}
	stop()
	<-engErr
	return err
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	paths := pathFlags(fs)
	fs.Parse(args)

	renderStatusOneShot(*paths)
	return nil
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	paths := pathFlags(fs)
	fs.Parse(args)

	if _, err := core.VerifyAll(*paths, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "verification FAILED: integrity violation detected")
		os.Exit(3)
	}
	fmt.Println("verification passed")
	return nil
}

func cmdLog(args []string) error {
	fs := flag.NewFlagSet("log", flag.ExitOnError)
	paths := pathFlags(fs)
	asJSON := fs.Bool("json", false, "print entries as JSON lines")
	fs.Parse(args)

	key, err := core.LoadKey(paths.Key)
	if err != nil {
		return err
	}
	entries, verr := core.VerifyJournal(paths.Journal, key)
	for _, e := range entries {
		if *asJSON {
			raw, _ := json.Marshal(e)
			fmt.Println(string(raw))
		} else {
			fmt.Printf("%s #%d [%s] %s\n", e.TS, e.Seq, e.Type, string(e.Data))
		}
	}
	if verr != nil {
		fmt.Fprintf(os.Stderr, "journal verification FAILED: %v\n", verr)
		os.Exit(3)
	}
	return nil
}

// cmdClearLog erases the activity log from the CLI. Requires --yes so it can't
// wipe history by accident, and stops a running daemon first (a stale in-memory
// chain would otherwise open a sequence gap on its next append).
func cmdClearLog(args []string) error {
	fs := flag.NewFlagSet("clear-log", flag.ExitOnError)
	paths := pathFlags(fs)
	yes := fs.Bool("yes", false, "confirm erasing the activity log")
	fs.Parse(args)

	if !*yes {
		fmt.Println("This erases the activity log (a fresh tamper-evident chain is started).")
		fmt.Println("Re-run to confirm:  seatguard clear-log --yes")
		return nil
	}
	if daemonRunning(*paths) {
		if _, err := stopDaemon(*paths); err != nil {
			return fmt.Errorf("stop the running daemon first: %w", err)
		}
		fmt.Println("stopped the running monitor; restart it after clearing.")
	}
	key, err := core.LoadKey(paths.Key)
	if err != nil {
		return err
	}
	if err := core.ClearJournal(*paths, key); err != nil {
		return err
	}
	fmt.Println("activity log cleared.")
	return nil
}

// cmdUninstall stops protection and removes seatguard's data + autostart from
// the CLI. Requires --yes. The program binary itself is left in place.
func cmdUninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	paths := pathFlags(fs)
	yes := fs.Bool("yes", false, "confirm removal of all data and autostart")
	fs.Parse(args)

	if !*yes {
		fmt.Println("This stops protection and deletes the baseline, key, journal, state and")
		fmt.Println("autostart entry. Re-run to confirm:  seatguard uninstall --yes")
		return nil
	}
	if daemonRunning(*paths) {
		if _, err := stopDaemon(*paths); err != nil {
			// Do NOT delete data out from under a live daemon — it would just
			// recreate orphaned, unverifiable files. Abort and let the user stop
			// it (e.g. from the tray) first.
			return fmt.Errorf("could not stop the running monitor (%w); stop it, then re-run uninstall", err)
		}
	}
	res := core.Uninstall(*paths)
	fmt.Printf("removed %d data file(s); autostart removed: %v\n", len(res.Removed), res.AutostartRemoved)
	for p, e := range res.Failed {
		fmt.Fprintf(os.Stderr, "  could not delete %s: %s\n", p, e)
	}
	fmt.Println("done. You can now delete the seatguard program file.")
	return nil
}
