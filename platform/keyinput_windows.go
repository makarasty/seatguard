//go:build windows

package platform

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var procReadConsoleInput = kernel32.NewProc("ReadConsoleInputW")

// Virtual-key codes (winuser.h).
const (
	vkReturn = 0x0D
	vkEscape = 0x1B
	vkSpace  = 0x20
	vkLeft   = 0x25
	vkUp     = 0x26
	vkRight  = 0x27
	vkDown   = 0x28

	keyEventType = 0x0001
)

type keyEventRecord struct {
	bKeyDown          int32
	wRepeatCount      uint16
	wVirtualKeyCode   uint16
	wVirtualScanCode  uint16
	unicodeChar       uint16
	dwControlKeyState uint32
}

// inputRecord mirrors INPUT_RECORD: a WORD event type, 2 bytes union
// padding, then the (largest relevant) KEY_EVENT_RECORD.
type inputRecord struct {
	eventType uint16
	_         uint16
	key       keyEventRecord
}

type winKeyInput struct {
	h        windows.Handle
	prevMode uint32
	restored bool
	haveMode bool
}

// NewKeyInput reads decoded key events straight from the console input
// buffer via ReadConsoleInputW, which reports arrow keys as virtual-key
// codes — independent of the byte-stream / VT-input quirks that make arrows
// invisible to a plain stdin read on Windows.
func NewKeyInput() KeyInput {
	h := windows.Handle(windows.Stdin)
	w := &winKeyInput{h: h}
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err == nil {
		w.prevMode, w.haveMode = mode, true
		raw := mode &^ (windows.ENABLE_LINE_INPUT | windows.ENABLE_ECHO_INPUT | windows.ENABLE_PROCESSED_INPUT)
		windows.SetConsoleMode(h, raw)
	}
	return w
}

func (w *winKeyInput) Read() (Key, byte) {
	var rec inputRecord
	var read uint32
	for {
		r, _, _ := procReadConsoleInput.Call(
			uintptr(w.h),
			uintptr(unsafe.Pointer(&rec)),
			1,
			uintptr(unsafe.Pointer(&read)),
		)
		if r == 0 || read == 0 {
			return KeyEsc, 0
		}
		if rec.eventType != keyEventType || rec.key.bKeyDown == 0 {
			continue // key-up, mouse, resize, focus — ignore
		}
		switch rec.key.wVirtualKeyCode {
		case vkUp:
			return KeyUp, 0
		case vkDown:
			return KeyDown, 0
		case vkLeft:
			return KeyLeft, 0
		case vkRight:
			return KeyRight, 0
		case vkReturn:
			return KeyEnter, 0
		case vkEscape:
			return KeyEsc, 0
		case vkSpace:
			return KeySpace, ' '
		}
		if c := rec.key.unicodeChar; c != 0 {
			if c == 3 || c == 4 { // Ctrl-C / Ctrl-D
				return KeyEsc, 0
			}
			if c < 128 {
				return KeyRune, byte(c)
			}
		}
	}
}

func (w *winKeyInput) Close() {
	if w.haveMode && !w.restored {
		windows.SetConsoleMode(w.h, w.prevMode)
		w.restored = true
	}
}
