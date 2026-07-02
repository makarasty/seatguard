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

commands:
  setup    interactive wizard: find all Claude installs, enroll, start
           (also runs when seatguard is launched with no arguments)
  enroll   create the protected baseline of legitimate Claude binaries
  run      start the polling detection daemon (foreground; --tray to hide in tray)
  dashboard  live security dashboard (auto-refreshing TUI)
  status   one-shot security posture and score
  verify   check baseline HMAC, journal hash chain and daemon self-hash
  log      print the event journal

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
	fs.Parse(args)

	// Fail-safe startup: refuse to run on any integrity mismatch, loudly.
	b, err := core.VerifyAll(*paths, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ALERT [integrity] seatguard refuses to start: baseline/journal/self verification failed")
		os.Exit(2)
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

	fmt.Fprintf(os.Stderr, "seatguard running: %d identities, %d cred paths, poll %ds\n",
		len(b.Identities), len(b.CredPaths), b.PollSecs)
	return eng.Run(ctx)
}

// runInTray hides the console, runs the engine in the background, and shows
// a system-tray icon whose color reflects the live security posture. On
// non-Windows the tray call returns ErrTrayUnsupported and we fall back to
// the normal foreground loop.
func runInTray(ctx context.Context, stop context.CancelFunc, eng *core.Engine, paths core.Paths, b *core.Baseline) error {
	self, _ := os.Executable()
	dashArgs := []string{"--db", paths.DB, "--key", paths.Key, "--journal", paths.Journal, "--state", paths.State}

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
