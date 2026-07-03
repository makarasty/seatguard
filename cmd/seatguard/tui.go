package main

import (
	"fmt"
	"strings"

	"seatguard/platform"
)

// This file implements a tiny dependency-free TUI toolkit: a key decoder
// (arrows, enter, space, escape, chars) over the platform raw-input mode,
// plus two interactive components — a single-select menu and a multi-select
// checklist — both driven entirely by keypresses (no Enter-per-line).
// Styling follows a modern Linux TUI aesthetic: rounded boxes, a left
// accent bar on the focused row, muted secondary text.

// ---- palette (disabled when the terminal can't do ANSI) ----

var (
	cReset = "\x1b[0m"
	cBold  = "\x1b[1m"
	cDim   = "\x1b[2m"

	cRed    = "\x1b[38;5;203m"
	cGreen  = "\x1b[38;5;114m"
	cYell   = "\x1b[38;5;221m"
	cCyan   = "\x1b[38;5;80m"
	cMuted  = "\x1b[38;5;245m"
	cAccent = "\x1b[38;5;170m" // focus accent (soft magenta)

	cInvGreen = "\x1b[48;5;114m\x1b[38;5;236m"
	cInvYell  = "\x1b[48;5;221m\x1b[38;5;236m"
	cInvRed   = "\x1b[48;5;203m\x1b[38;5;236m"
	cInvGrey  = "\x1b[48;5;245m\x1b[38;5;236m"
)

var colorsReady bool

func initColors() {
	if colorsReady {
		return
	}
	colorsReady = true
	if platform.EnableANSI() {
		return
	}
	// Not a VT terminal (piped/redirected): blank every escape, including the
	// screen/cursor controls, so output is plain text instead of raw escape
	// bytes.
	cReset, cBold, cDim = "", "", ""
	cRed, cGreen, cYell, cCyan, cMuted, cAccent = "", "", "", "", "", ""
	cInvGreen, cInvYell, cInvRed, cInvGrey = "", "", "", ""
	scrClear, scrHome, scrErase, curHide, curShow, cursorHome = "", "", "", "", "", ""
}

// ---- key decoding ----

type key int

const (
	keyNone key = iota
	keyUp
	keyDown
	keyLeft
	keyRight
	keyEnter
	keySpace
	keyEsc
	keyChar
)

type keyEvent struct {
	k key
	r byte // set when k == keyChar
}

// keyReader wraps the platform key source and maps its normalized keys to
// the local keyEvent type. The per-OS decoding (Windows ReadConsoleInput vs
// POSIX escape sequences) lives in the platform package.
type keyReader struct {
	in     platform.KeyInput
	closed bool
}

func newKeyReader() *keyReader {
	return &keyReader{in: platform.NewKeyInput()}
}

// close is idempotent: callers may close explicitly before handing the
// console to another reader and still rely on a deferred close.
func (kr *keyReader) close() {
	if !kr.closed {
		kr.in.Close()
		kr.closed = true
	}
}

// next blocks for one key event.
func (kr *keyReader) next() keyEvent {
	k, r := kr.in.Read()
	switch k {
	case platform.KeyUp:
		return keyEvent{k: keyUp}
	case platform.KeyDown:
		return keyEvent{k: keyDown}
	case platform.KeyLeft:
		return keyEvent{k: keyLeft}
	case platform.KeyRight:
		return keyEvent{k: keyRight}
	case platform.KeyEnter:
		return keyEvent{k: keyEnter}
	case platform.KeySpace:
		return keyEvent{k: keySpace}
	case platform.KeyEsc:
		return keyEvent{k: keyEsc}
	case platform.KeyRune:
		return keyEvent{k: keyChar, r: r}
	}
	return keyEvent{k: keyNone}
}

// ---- screen helpers ----

// Screen/cursor controls — vars (not consts) so initColors can blank them
// when stdout is not a VT terminal. cursorHome = home + erase-below, used to
// redraw a full-screen frame in place.
var (
	scrClear   = "\x1b[H\x1b[2J"
	scrHome    = "\x1b[H"
	scrErase   = "\x1b[0J"
	cursorHome = "\x1b[H\x1b[0J"
	curHide    = "\x1b[?25l"
	curShow    = "\x1b[?25h"
)

// ---- single-select menu ----

type menuItem struct {
	label    string
	desc     string
	hot      byte   // optional hotkey char (lowercase)
	value    string // optional right-aligned status text (e.g. "On")
	section  bool   // a non-selectable section header row
	danger   bool   // tint the label red (destructive action)
	disabled bool   // shown dimmed, not selectable
}

// selectable reports whether the row can receive focus / be chosen.
func (m menuItem) selectable() bool { return !m.section && !m.disabled }

// firstSelectable / nextSelectable / prevSelectable let arrow navigation skip
// over section headers and disabled rows so focus only ever lands on a real
// action.
func firstSelectable(items []menuItem) int {
	for i := range items {
		if items[i].selectable() {
			return i
		}
	}
	return -1
}

func stepSelectable(items []menuItem, from, dir int) int {
	if from < 0 {
		return firstSelectable(items)
	}
	n := len(items)
	for i := 1; i <= n; i++ {
		j := ((from+dir*i)%n + n) % n
		if items[j].selectable() {
			return j
		}
	}
	return from
}

// runMenu shows an arrow-navigable menu, reading keys from next(). header is an
// optional pre-rendered block (e.g. a status card) shown above the items.
// Returns the chosen index, or -1 if the user backed out (Esc). Enter or an
// item's hotkey selects immediately; section/disabled rows are skipped.
func runMenu(next func() keyEvent, title, subtitle, header string, items []menuItem) int {
	sel := firstSelectable(items)
	fmt.Print(curHide)
	defer fmt.Print(curShow)
	for {
		fmt.Print(scrHome, scrErase)
		fmt.Print(renderMenu(title, subtitle, header, items, sel))
		ev := next()
		switch ev.k {
		case keyUp, keyLeft:
			sel = stepSelectable(items, sel, -1)
		case keyDown, keyRight:
			sel = stepSelectable(items, sel, +1)
		case keyEnter, keySpace:
			if sel >= 0 && items[sel].selectable() {
				return sel
			}
		case keyEsc:
			return -1
		case keyChar:
			c := lower(ev.r)
			for i, it := range items {
				if it.selectable() && it.hot != 0 && it.hot == c {
					return i
				}
			}
		}
	}
}

// menuLabelCol is the column the right-aligned value text starts at.
const menuLabelCol = 34

func renderMenu(title, subtitle, header string, items []menuItem, sel int) string {
	var b strings.Builder
	b.WriteString("\n  " + cBold + cCyan + "◆ " + title + cReset + "\n")
	if subtitle != "" {
		b.WriteString("  " + cMuted + subtitle + cReset + "\n")
	}
	if header != "" {
		b.WriteString(header)
	}
	b.WriteString("\n")
	for i, it := range items {
		switch {
		case it.section:
			// Muted uppercase section header with a trailing rule.
			label := strings.ToUpper(it.label)
			rule := ""
			if pad := 58 - len(label); pad > 0 {
				rule = " " + cDim + strings.Repeat("─", pad-1) + cReset
			}
			b.WriteString("\n  " + cMuted + label + cReset + rule + "\n")
			continue
		case it.disabled:
			b.WriteString("    " + cDim + it.label + cReset)
			b.WriteString(valueTail(it, cDim))
			b.WriteString("\n")
			continue
		}
		focused := i == sel
		labelCol := cReset
		if it.danger {
			labelCol = cRed
		}
		if focused {
			b.WriteString("  " + cAccent + "▐ " + cReset + cBold + labelCol + it.label + cReset)
		} else {
			b.WriteString("    " + labelCol + it.label + cReset)
		}
		b.WriteString(valueTail(it, cMuted))
		if it.desc != "" {
			descCol := cMuted
			if !focused {
				descCol = cDim
			}
			b.WriteString("  " + descCol + it.desc + cReset)
		}
		b.WriteString("\n")
	}
	// No hard-coded bottom hint: the caller's subtitle carries the navigation
	// help (and the correct Esc action for this screen), so a fixed "Esc back"
	// here would contradict a top-level menu where Esc quits.
	return b.String()
}

// valueTail renders an item's right-aligned value, padded so values line up.
func valueTail(it menuItem, col string) string {
	if it.value == "" {
		return ""
	}
	pad := menuLabelCol - len(it.label)
	if pad < 2 {
		pad = 2
	}
	return strings.Repeat(" ", pad) + col + it.value + cReset
}

// ---- yes/no confirmation ----

// runConfirm shows a modal yes/no prompt. It defaults to "No" (safe) and
// returns true only if the user explicitly confirms. Esc / n / q = No.
// danger tints the confirm button red for destructive actions.
func runConfirm(next func() keyEvent, title string, body []string, confirmLabel string, danger bool) bool {
	yes := false // start on "No"
	fmt.Print(curHide)
	defer fmt.Print(curShow)
	for {
		fmt.Print(scrHome, scrErase)
		var b strings.Builder
		warn := cYell
		if danger {
			warn = cRed
		}
		b.WriteString("\n  " + cBold + warn + "▲ " + title + cReset + "\n\n")
		for _, line := range body {
			b.WriteString("  " + cMuted + line + cReset + "\n")
		}
		b.WriteString("\n  ")
		noBtn, yesBtn := "  No  ", "  "+confirmLabel+"  "
		yesCol := cInvGreen
		if danger {
			yesCol = cInvRed
		}
		if yes {
			b.WriteString(cDim + " " + noBtn + " " + cReset + "   " + yesCol + yesBtn + cReset)
		} else {
			b.WriteString(cInvGrey + " " + noBtn + " " + cReset + "   " + cDim + yesBtn + cReset)
		}
		b.WriteString("\n\n  " + cMuted + "←→ choose · ⏎ confirm · Esc cancel" + cReset + "\n")
		fmt.Print(b.String())
		ev := next()
		switch ev.k {
		case keyLeft, keyRight, keyUp, keyDown:
			yes = !yes
		case keyEnter, keySpace:
			return yes
		case keyEsc:
			return false
		case keyChar:
			switch lower(ev.r) {
			case 'y':
				return true
			case 'n', 'q':
				return false
			}
		}
	}
}

// pressAnyKey shows a hint and waits for one key — the return-from-result idiom.
func pressAnyKey(next func() keyEvent) {
	fmt.Printf("\n  %spress any key to go back%s", cDim, cReset)
	next()
}

// ---- multi-select checklist ----

type checkItem struct {
	label   string
	sub     string
	checked bool
}

// runChecklist shows an arrow-navigable checklist, reading keys from next().
// Space toggles the focused row, a/n select all/none, Enter confirms, q/Esc
// cancels. Returns the final checked mask and true, or (nil,false) on cancel.
func runChecklist(next func() keyEvent, title, subtitle string, items []checkItem) ([]bool, bool) {
	sel := 0
	fmt.Print(curHide)
	defer fmt.Print(curShow)
	for {
		fmt.Print(scrHome, scrErase)
		fmt.Print(renderChecklist(title, subtitle, items, sel))
		ev := next()
		switch ev.k {
		case keyUp:
			sel = (sel - 1 + len(items)) % len(items)
		case keyDown:
			sel = (sel + 1) % len(items)
		case keySpace:
			items[sel].checked = !items[sel].checked
		case keyEnter:
			out := make([]bool, len(items))
			for i := range items {
				out[i] = items[i].checked
			}
			return out, true
		case keyEsc:
			return nil, false
		case keyChar:
			switch lower(ev.r) {
			case 'a':
				for i := range items {
					items[i].checked = true
				}
			case 'n':
				for i := range items {
					items[i].checked = false
				}
			case 'q':
				return nil, false
			}
		}
	}
}

func renderChecklist(title, subtitle string, items []checkItem, sel int) string {
	var b strings.Builder
	b.WriteString("\n  " + cBold + cCyan + "◆ " + title + cReset + "\n")
	if subtitle != "" {
		b.WriteString("  " + cMuted + subtitle + cReset + "\n")
	}
	b.WriteString("\n")
	count := 0
	for _, it := range items {
		if it.checked {
			count++
		}
	}
	for i, it := range items {
		box := cDim + "☐" + cReset
		if it.checked {
			box = cGreen + "☑" + cReset
		}
		focus := "   "
		labelCol := cReset
		if i == sel {
			focus = cAccent + " ▐ " + cReset
			labelCol = cBold
		}
		b.WriteString(fmt.Sprintf("%s%s %s%s%s", focus, box, labelCol, it.label, cReset))
		if it.sub != "" {
			b.WriteString("  " + cMuted + it.sub + cReset)
		}
		b.WriteString("\n")
	}
	b.WriteString(fmt.Sprintf("\n  %s%d selected%s   %s↑↓ move · space toggle · a all · n none · ⏎ confirm · q cancel%s\n",
		cBold, count, cReset, cMuted, cReset))
	return b.String()
}

func lower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return b
}
