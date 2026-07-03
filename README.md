# seatguard

A cross-platform background CLI daemon (Go) that detects theft and abuse of the Anthropic/Claude subscription OAuth token (`sk-ant-oat01-...`) on the local machine. The token sits on disk in plaintext (`~/.claude/.credentials.json`, `~/.claude.json`); any process under the same user can read it and silently burn the user's quota — indistinguishable from legit traffic on the provider side, so detection must be local. seatguard keeps a tamper-evident baseline of legitimate Claude binaries, polls who opens the credential files and who holds established TCP connections to Anthropic endpoints, resolves each such process to a stable identity (binary path + SHA-256 + (pid, start_time) handle — never bare PID, never process name), and alerts on anything foreign.

## Build

Requires Go 1.24+. Single static binary per target, CGO_ENABLED=0.

Commands (use exactly these, works from repo root):

**Windows:**
```
$env:CGO_ENABLED="0"; $env:GOOS="windows"; $env:GOARCH="amd64"; go build -o dist/seatguard.exe ./cmd/seatguard
```

**Linux:**
```
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dist/seatguard ./cmd/seatguard
```

**macOS:**
```
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o dist/seatguard ./cmd/seatguard
```

## Quick start

Run the interactive wizard — it scans every known Claude location (PATH, `~/.local/bin`, `%LOCALAPPDATA%\Claude-Profiles\**`, MSIX/Store packages via `Get-AppxPackage`, `%LOCALAPPDATA%\AnthropicClaude`, npm globals, and the `node` interpreter), lets you confirm the selection with a checkbox list, enrolls, and offers to start protection or install autostart:

```powershell
# Windows: build once, then just run it (no arguments = wizard)
$env:CGO_ENABLED="0"; go build -o seatguard.exe ./cmd/seatguard
.\seatguard.exe
```

```bash
# Linux / macOS
CGO_ENABLED=0 go build -o seatguard ./cmd/seatguard
./seatguard            # or: ./seatguard setup
```

The wizard is fully keyboard-driven (no typing paths, no Enter-per-line): an arrow-key **checklist** to pick which discovered Claude binaries are legitimate (`↑↓` move, `space` toggle, `a`/`n` all/none, `Enter` confirm), then an arrow-key **menu** to choose how to start — live dashboard, hidden in the **system tray** (Windows), foreground, or autostart. `Esc` or `q` exits any menu.

**It remembers.** If a valid baseline already exists, the wizard doesn't re-ask everything — it shows a short menu (Start / Re-scan & update / Edit selection / Quit) and flags any drift (new Claude installs on disk, or enrolled binaries whose hash changed after an update). Pass `--reconfigure` to force the full selection. `Esc` goes **back** a step in any menu (not straight out).

**Change settings without restarting.** In the live dashboard press `Esc` (or `s`) to open a settings menu — update/reconfigure the baseline, verify, view the log — then `Esc`/Back to return to the live view. `seatguard autostart` installs a per-user logon entry (runs in the tray; no admin needed); `seatguard autostart remove` uninstalls it.

This is the recommended path; the individual commands below exist for scripting.

### Live security dashboard

`seatguard dashboard` shows an auto-refreshing security view: an overall posture (`PROTECTED` / `NEEDS ATTENTION` / `AT RISK` / `UNPROTECTED`), a 0–100 security score, per-check results, coverage gaps (Claude installs on disk that aren't enrolled, or enrolled binaries whose hash changed after an update), and the latest detection. Hotkeys: `q` quit · `v` re-verify integrity · `u` update the baseline (re-scan installs) · `l` recent journal.

### System tray (Windows)

`seatguard run --tray` hides the console and shows a tray icon **drawn at runtime** (no resource files) as a rounded badge whose color and glyph track the live posture: green check = protected, amber `!` = needs attention, red `×` = at risk / alert. It raises a balloon notification when an unauthorized process is detected. Right-click the icon for: Open dashboard · Show status · Verify integrity · Quit. Double-click opens the dashboard.

## Commands

| Command | Description | Flags |
|---------|-------------|-------|
| `seatguard setup` | Interactive wizard: discover all Claude installs, enroll, start (also runs with no arguments) | `--poll`, plus common flags |
| `seatguard enroll` | Create the protected baseline non-interactively (discovers claude/node) | `--claude-path`, `--claude-dir`, `--cred`, `--api-host`, `--api-ip`, `--poll`, `--no-discover` |
| `seatguard run` | Foreground polling daemon; verifies DB integrity + its own binary hash at startup and refuses to run on mismatch (fail-safe); single-instance per baseline | `--tray` (Windows: hide in system tray), `--require-privileged` |
| `seatguard dashboard` | Live auto-refreshing security dashboard (TUI); `Esc`/`s` opens in-app settings | `--refresh` |
| `seatguard autostart` | `install` (default) / `remove` a per-user logon entry that runs in the tray (Windows; no admin) | common flags |
| `seatguard status` | One-shot security posture + score | — |
| `seatguard verify` | Check baseline HMAC, journal hash chain, daemon self-hash; nonzero exit on violation | — |
| `seatguard log` | Print event journal (verifies chain) | `--json` for machine-readable output |

Common flags on all commands: `--db`, `--key`, `--journal`, `--state`

## Architecture

- **`core/`** — baseline store (HMAC-SHA256-protected DB, key kept in a separate directory), append-only journal with per-record HMAC chain, polling detection engine, enroll/verify logic
- **`platform/`** — OS backends behind build tags, all pure-Go / CGO-free:
  - **Linux** — `/proc` scanning (fd links for file holders, `/proc/net/tcp{,6}` inode→PID for connections)
  - **Windows** — Restart Manager (file holders) + `GetExtendedTcpTable` (conn→PID) + PEB read (cmdline) + Authenticode signer capture + protected-DACL file hardening
  - **macOS** — `proc_info(2)` syscall + `sysctl KERN_PROCARGS2` (file holders, connections, cmdline, RSS) + `codesign` signer capture *(code-complete; see Validation status)*
- **`cmd/seatguard`** — CLI; **`cmd/harness`** — automated acceptance harness (`go run ./cmd/harness`); **`cmd/helper`** — test helper simulating legit/rogue processes

### Project layout

```
seatguard/
├── cmd/
│   ├── seatguard/   # CLI + TUI: setup wizard, run(+tray), dashboard, enroll, status, verify, log
│   │                #   tui.go = keyboard-driven menu/checklist toolkit
│   ├── harness/     # automated §6 acceptance checks
│   └── helper/      # test process simulating legit/rogue behaviour
├── core/            # OS-independent detection core
│   ├── engine.go    #   polling loop + legitimacy judgment
│   ├── store.go     #   HMAC-protected baseline DB
│   ├── journal.go   #   hash-chained append-only event log
│   ├── enroll.go    #   baseline creation
│   ├── discover.go  #   scan all Claude install locations
│   ├── status.go    #   security posture + score model
│   ├── verify.go    #   integrity self-check
│   ├── identity.go  #   binary identity (path + hash + signature)
│   ├── alert.go     #   alert record + emission
│   ├── netset.go    #   Anthropic endpoint IP set (runtime DNS)
│   └── config.go    #   per-OS default paths
└── platform/        # build-tagged OS backends (Linux / Windows / macOS)
```

## Detection model (Phase 1, polling)

- Snapshot every 3–5 s (default 4 s, `--poll`).
- Signal A: which process holds a credential file open. Signal B: which process has an established TCP connection to an Anthropic endpoint IP (domains resolved at runtime and refreshed every 5 min — Cloudflare rotates IPs; never hardcoded). Only connection metadata is used — no TLS interception, no MITM.
- Identity = binary path + content hash + captured code signature; (pid, start_time) used only as a stable runtime handle. The content hash is the *enforced* check; the signature (Authenticode CN on Windows, `codesign` Authority on macOS) is captured at enroll as supplementary attribution. Deduplication: exactly one alert per (signal, pid, start_time).
- Self-protection is tamper-EVIDENT, not tamper-proof: the DB, HMAC key, journal and state file are all `0600` (a protected DACL on Windows), outside the home dir, with the key kept in a separate directory from the DB; the journal is an append-only per-record HMAC chain that rotates (one archive kept) when it grows past a cap, with the new segment cryptographically linked to the archived tail; the daemon refuses to start on any integrity mismatch. The token itself is never stored — only metadata and hashes.
- **Single instance per baseline:** two `run` daemons on the same baseline would race the state file and corrupt the journal chain, so the second refuses to start (a named mutex on Windows, an `flock` on POSIX).
- The privileged-owner assumption is surfaced, not silently trusted: `run` prints a warning (or refuses, with `--require-privileged`) and the dashboard shows a `Privilege` check when seatguard runs unprivileged or the DB sits under your home directory. By default it does not hard-fail, so unprivileged/dev use still works.

## Known boundaries (by design, not detected)

- Code injection into a legitimate Claude process.
- Kernel/rootkit-level malware (can hide from any userland scanner).
- Theft that happened before seatguard was installed/enrolled.
- Polling gap: a process that opens the cred file and exits within one poll interval can be missed (event-driven backends — eBPF/ETW/ESF — are Phase 2).
- An attacker with the same privileges as the key/DB owner can re-forge both (hence tamper-evident, not tamper-proof).

## Acceptance harness

`go run ./cmd/harness` runs the full acceptance suite with zero manual steps: it cross-builds all three targets, enrolls a simulated Claude, then spins up rogue and legitimate helper processes and asserts nine binary criteria — cross-target static build, enroll, credential-read detection, egress detection, zero false positives on the enrolled twin, DB-integrity fail-safe, journal chain-break detection, idle RSS ≤ 15 MB over 60 s, and identity-not-name (a rogue renamed to `node` at a different path/hash still alerts). Exit code is 0 only if all nine pass. The suite runs against the host OS backend, and unit tests cover the identity/hash judgment, the HMAC-protected store, and the journal chain + rotation.

## CI & validation status

`.github/workflows/ci.yml` runs `go vet`, the unit tests, **and the full §6 acceptance harness on Linux, Windows and macOS** — so every backend is validated end-to-end at runtime on each push (not merely cross-compiled), then builds static binaries for all three targets.

- **Windows / Linux** — validated end-to-end and **gate CI** (locally on Windows; via CI on Linux). These are the deployable targets.
- **macOS** — the backend is code-complete and CGO-free; the macOS CI job runs the same harness but is **`continue-on-error` (informational, non-gating)** because its `proc_info(2)` accessors are not yet confirmed on Apple hardware. Treat macOS as **beta until that job is green**. Every darwin accessor is bounds-checked and fails safe (a layout mismatch causes a missed detection, never a false positive or crash).

## Deployment notes

- Run **elevated** (Administrator / root) with the default paths so the DB/key/journal are owned by a privileged account; add `--require-privileged` to make that mandatory.
- The distributed binary is unsigned — sign it (Authenticode / codesign / notarization) before wide distribution to avoid SmartScreen/Gatekeeper prompts.
- Install as a background service (Windows: `setup` → Autostart, or a Scheduled Task / service; Linux/macOS: a systemd/launchd unit — provided as a Phase-2 installer).

## Roadmap (Phase 2+)

- **Event-driven backends** (eBPF on Linux, ETW on Windows, EndpointSecurity on macOS) to replace polling and close the sub-interval gap.
- **Usage correlation** — tie observed egress to token-usage spikes.
- **macOS hardware validation** sign-off (the CI job is the gate).
- **Signature enforcement** — optionally require a valid signature match, not just capture it as metadata.
- **Privileged service install** — run as a system service under a dedicated account with the DB/key owned by that account (and enforce that ownership).
- **Code-signing / notarization** in the release pipeline.
