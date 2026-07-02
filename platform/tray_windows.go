//go:build windows

package platform

import (
	"errors"
	"os/exec"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ErrTrayUnsupported mirrors the non-Windows sentinel so callers can compare
// against it uniformly; the Windows tray implementation never returns it.
var ErrTrayUnsupported = errors.New("system tray unsupported")

// Tray levels (icon color), mapped to Windows stock icons.
const (
	TrayGreen  = 0 // information icon (blue/green "i")
	TrayYellow = 1 // warning icon (yellow triangle)
	TrayRed    = 2 // error icon (red circle)
	TrayGrey   = 3 // application icon
)

// TrayInfo is the snapshot the tray renders each refresh.
type TrayInfo struct {
	Level      int
	Tooltip    string
	AlertCount int
	AlertText  string
}

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procRegisterClassEx  = user32.NewProc("RegisterClassExW")
	procCreateWindowEx   = user32.NewProc("CreateWindowExW")
	procDefWindowProc    = user32.NewProc("DefWindowProcW")
	procGetMessage       = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessage  = user32.NewProc("DispatchMessageW")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procDestroyWindow    = user32.NewProc("DestroyWindow")
	procLoadIcon         = user32.NewProc("LoadIconW")
	procLoadImage        = user32.NewProc("LoadImageW")
	procCreatePopupMenu  = user32.NewProc("CreatePopupMenu")
	procAppendMenu       = user32.NewProc("AppendMenuW")
	procTrackPopupMenu   = user32.NewProc("TrackPopupMenu")
	procDestroyMenu      = user32.NewProc("DestroyMenu")
	procGetCursorPos     = user32.NewProc("GetCursorPos")
	procSetForegroundWin = user32.NewProc("SetForegroundWindow")
	procSetTimer         = user32.NewProc("SetTimer")
	procPostMessage      = user32.NewProc("PostMessageW")

	procShellNotifyIcon = shell32.NewProc("Shell_NotifyIconW")
	procCreateIcon      = user32.NewProc("CreateIcon")
	procDestroyIcon     = user32.NewProc("DestroyIcon")

	procGetConsoleWindow = kernel32.NewProc("GetConsoleWindow")
	procShowWindow       = user32.NewProc("ShowWindow")
	procGetModuleHandle  = kernel32.NewProc("GetModuleHandleW")
)

const (
	wmDestroy   = 0x0002
	wmCommand   = 0x0111
	wmTimer     = 0x0113
	wmApp       = 0x8000
	wmTrayCB    = wmApp + 1
	wmUserQuit  = wmApp + 2
	wmRButtonUp = 0x0205
	wmLButtonUp = 0x0202
	wmLDblClk   = 0x0203

	nimAdd    = 0
	nimModify = 1
	nimDelete = 2

	nifMessage = 0x01
	nifIcon    = 0x02
	nifTip     = 0x04
	nifInfo    = 0x10

	// Stock icon resource IDs (LoadIconW with hInstance = 0), used only as a
	// fallback if the custom CreateIcon path fails.
	idiError       = 32513
	idiWarning     = 32515
	idiInformation = 32516

	tpmReturnCmd  = 0x0100
	tpmRightAlign = 0x0008
	swHide        = 0
	mfString      = 0x0000
	mfSeparator   = 0x0800

	cmdOpen   = 1001
	cmdStatus = 1002
	cmdVerify = 1003
	cmdQuit   = 1009

	refreshTimerID = 1
)

type wndClassEx struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     windows.Handle
	hIcon         windows.Handle
	hCursor       windows.Handle
	hbrBackground windows.Handle
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       windows.Handle
}

type msg struct {
	hwnd    windows.Handle
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      point
}

type point struct{ x, y int32 }

type notifyIconData struct {
	cbSize           uint32
	hWnd             windows.Handle
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            windows.Handle
	szTip            [128]uint16
	dwState          uint32
	dwStateMask      uint32
	szInfo           [256]uint16
	uVersion         uint32
	szInfoTitle      [64]uint16
	dwInfoFlags      uint32
	guidItem         windows.GUID
	hBalloonIcon     windows.Handle
}

// tray holds the single per-process tray instance (wndproc is a C callback
// with no user pointer, so state lives here).
type tray struct {
	hwnd       windows.Handle
	nid        notifyIconData
	refresh    func() TrayInfo
	onQuit     func()
	selfExe    string
	dashArgs   []string
	lastAlerts int
	curIcon    windows.Handle
	curLevel   int

	mu     sync.Mutex // guards latest
	latest TrayInfo
}

var gTray *tray

// HideConsole hides the console window of this process (used when the
// daemon runs in tray mode so no terminal window lingers).
func HideConsole() {
	h, _, _ := procGetConsoleWindow.Call()
	if h != 0 {
		procShowWindow.Call(h, swHide)
	}
}

// levelRGB is the badge fill color per status level.
func levelRGB(level int) (r, g, b byte) {
	switch level {
	case TrayGreen:
		return 0x3f, 0xb9, 0x50 // green
	case TrayYellow:
		return 0xf1, 0xc4, 0x0f // amber
	case TrayRed:
		return 0xe0, 0x3b, 0x3b // red
	default:
		return 0x9a, 0x9a, 0x9a // grey
	}
}

const iconDim = 32

// statusIcon draws a rounded colored badge with a status glyph and returns
// an HICON. The whole icon is built pixel-by-pixel (no resource files, no
// cgo): a 32bpp XOR color plane plus a 1bpp AND transparency mask, fed to
// CreateIcon. Caller owns the handle and must DestroyIcon it.
func statusIcon(level int) windows.Handle {
	type px struct {
		opaque  bool
		r, g, b byte
	}
	var cv [iconDim][iconDim]px
	fr, fg, fb := levelRGB(level)

	// Rounded-square badge with a 1px lighter border.
	const radius = 7
	inCorner := func(x, y int) bool {
		// Distance from the nearest corner center; outside → transparent.
		cx, cy := x, y
		if x >= iconDim-radius {
			cx = iconDim - 1 - x
		} else if x >= radius {
			return false
		}
		if y >= iconDim-radius {
			cy = iconDim - 1 - y
		} else if y >= radius {
			return false
		}
		dx, dy := radius-1-cx, radius-1-cy
		return dx*dx+dy*dy > radius*radius
	}
	for y := 0; y < iconDim; y++ {
		for x := 0; x < iconDim; x++ {
			if inCorner(x, y) {
				continue // transparent corner
			}
			r, g, b := fr, fg, fb
			// Subtle border ring.
			if x < 2 || y < 2 || x >= iconDim-2 || y >= iconDim-2 {
				r, g, b = mix(r, 0xff), mix(g, 0xff), mix(b, 0xff)
			}
			cv[y][x] = px{true, r, g, b}
		}
	}

	// Dark glyph for contrast.
	dr, dg, db := byte(0x1a), byte(0x1a), byte(0x1a)
	plot := func(x, y int) {
		if x >= 0 && x < iconDim && y >= 0 && y < iconDim && cv[y][x].opaque {
			cv[y][x] = px{true, dr, dg, db}
		}
	}
	thick := func(f func(int, int)) func(int, int) {
		return func(x, y int) {
			for oy := 0; oy < 3; oy++ {
				for ox := 0; ox < 3; ox++ {
					f(x+ox-1, y+oy-1)
				}
			}
		}
	}
	tp := thick(plot)
	switch level {
	case TrayGreen: // check mark
		for i := 0; i < 5; i++ {
			tp(10+i, 16+i)
		}
		for i := 0; i < 9; i++ {
			tp(14+i, 20-i)
		}
	case TrayYellow: // exclamation
		for y := 9; y <= 19; y++ {
			tp(16, y)
		}
		tp(16, 23)
	case TrayRed: // cross
		for i := 0; i < 12; i++ {
			tp(10+i, 10+i)
			tp(10+i, 21-i)
		}
	default: // dot
		tp(16, 16)
	}

	// Emit XOR (32bpp BGRA, bottom-up) and AND (1bpp, bottom-up; 1=transparent).
	xor := make([]byte, iconDim*iconDim*4)
	and := make([]byte, iconDim*4) // 4 bytes/row * 32 rows
	for y := 0; y < iconDim; y++ {
		srcRow := iconDim - 1 - y // bottom-up
		for x := 0; x < iconDim; x++ {
			p := cv[srcRow][x]
			off := (y*iconDim + x) * 4
			if p.opaque {
				xor[off+0] = p.b
				xor[off+1] = p.g
				xor[off+2] = p.r
				xor[off+3] = 0xff
			} else {
				and[y*4+x/8] |= 1 << (7 - uint(x%8)) // transparent bit
			}
		}
	}
	h, _, _ := procCreateIcon.Call(0, iconDim, iconDim, 1, 32,
		uintptr(unsafe.Pointer(&and[0])), uintptr(unsafe.Pointer(&xor[0])))
	if h == 0 {
		// Fall back to a stock icon so the tray still appears.
		id := idiInformation
		if level == TrayRed {
			id = idiError
		} else if level == TrayYellow {
			id = idiWarning
		}
		h, _, _ = procLoadIcon.Call(0, uintptr(id))
	}
	return windows.Handle(h)
}

func mix(a, b byte) byte { return byte((int(a) + int(b)) / 2) }

// RunTray creates the tray icon and runs the Win32 message loop on the
// calling goroutine until the user chooses Quit. The caller must
// runtime.LockOSThread() before calling. refresh() is polled on a timer;
// onQuit() is invoked when the user exits (e.g. to stop the engine).
func RunTray(title, selfExe string, dashArgs []string, refresh func() TrayInfo, onQuit func()) error {
	t := &tray{refresh: refresh, onQuit: onQuit, selfExe: selfExe, dashArgs: dashArgs}
	gTray = t

	hInst, _, _ := procGetModuleHandle.Call(0)
	className, _ := windows.UTF16PtrFromString("seatguardTrayClass")

	wc := wndClassEx{
		cbSize:        uint32(unsafe.Sizeof(wndClassEx{})),
		lpfnWndProc:   syscall.NewCallback(wndProc),
		hInstance:     windows.Handle(hInst),
		lpszClassName: className,
	}
	if r, _, err := procRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		return err
	}

	winTitle, _ := windows.UTF16PtrFromString(title)
	hwnd, _, err := procCreateWindowEx.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(winTitle)),
		0, 0, 0, 0, 0,
		0, 0, hInst, 0,
	)
	if hwnd == 0 {
		return err
	}
	t.hwnd = windows.Handle(hwnd)

	// Initial icon.
	info := refresh()
	t.latest = info
	t.curIcon = statusIcon(info.Level)
	t.curLevel = info.Level
	t.nid = notifyIconData{
		cbSize:           uint32(unsafe.Sizeof(notifyIconData{})),
		hWnd:             t.hwnd,
		uID:              1,
		uFlags:           nifMessage | nifIcon | nifTip,
		uCallbackMessage: wmTrayCB,
		hIcon:            t.curIcon,
	}
	copyUTF16(t.nid.szTip[:], firstNonEmpty(info.Tooltip, title))
	t.lastAlerts = info.AlertCount
	procShellNotifyIcon.Call(nimAdd, uintptr(unsafe.Pointer(&t.nid)))

	// Compute the posture OFF the message-loop thread: ComputePosture reads
	// files and may spawn the OS package manager, which would otherwise
	// freeze the tray (GetMessage stops pumping) during the call. The timer
	// only reads the cached result.
	go func() {
		tick := time.NewTicker(3 * time.Second)
		defer tick.Stop()
		for range tick.C {
			info := refresh()
			t.mu.Lock()
			t.latest = info
			t.mu.Unlock()
		}
	}()

	// Repaint from the cached posture ~1s (cheap: no I/O on this thread).
	procSetTimer.Call(hwnd, refreshTimerID, 1000, 0)

	// Message loop.
	var m msg
	for {
		r, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 { // WM_QUIT or error
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}
	procShellNotifyIcon.Call(nimDelete, uintptr(unsafe.Pointer(&t.nid)))
	if t.curIcon != 0 {
		procDestroyIcon.Call(uintptr(t.curIcon))
	}
	return nil
}

func wndProc(hwnd windows.Handle, message uint32, wParam, lParam uintptr) uintptr {
	t := gTray
	switch message {
	case wmTrayCB:
		switch uint32(lParam) {
		case wmRButtonUp, wmLButtonUp:
			t.showMenu()
		case wmLDblClk:
			t.spawnDashboard()
		}
		return 0
	case wmTimer:
		t.onRefresh()
		return 0
	case wmCommand:
		t.onCommand(uint32(wParam & 0xffff))
		return 0
	case wmUserQuit:
		procPostQuitMessage.Call(0)
		return 0
	case wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProc.Call(uintptr(hwnd), uintptr(message), wParam, lParam)
	return r
}

func (t *tray) onRefresh() {
	t.mu.Lock()
	info := t.latest
	t.mu.Unlock()
	t.nid.uFlags = nifIcon | nifTip
	// Only rebuild the icon when the level actually changes (avoids churn).
	if info.Level != t.curLevel || t.curIcon == 0 {
		newIcon := statusIcon(info.Level)
		if t.curIcon != 0 {
			procDestroyIcon.Call(uintptr(t.curIcon))
		}
		t.curIcon = newIcon
		t.curLevel = info.Level
	}
	t.nid.hIcon = t.curIcon
	copyUTF16(t.nid.szTip[:], firstNonEmpty(info.Tooltip, "seatguard"))
	// New alert since last refresh → balloon.
	if info.AlertCount > t.lastAlerts && info.AlertText != "" {
		t.nid.uFlags |= nifInfo
		copyUTF16(t.nid.szInfo[:], info.AlertText)
		copyUTF16(t.nid.szInfoTitle[:], "seatguard: unauthorized access")
		t.nid.dwInfoFlags = 0x03 // NIIF_ERROR
	}
	t.lastAlerts = info.AlertCount
	procShellNotifyIcon.Call(nimModify, uintptr(unsafe.Pointer(&t.nid)))
}

func (t *tray) showMenu() {
	menu, _, _ := procCreatePopupMenu.Call()
	appendItem(menu, cmdOpen, "Open dashboard")
	appendItem(menu, cmdStatus, "Show status")
	appendItem(menu, cmdVerify, "Verify integrity")
	appendSep(menu)
	appendItem(menu, cmdQuit, "Quit seatguard")

	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForegroundWin.Call(uintptr(t.hwnd))
	cmd, _, _ := procTrackPopupMenu.Call(
		menu, tpmReturnCmd|tpmRightAlign,
		uintptr(pt.x), uintptr(pt.y), 0, uintptr(t.hwnd), 0)
	procDestroyMenu.Call(menu)
	if cmd != 0 {
		t.onCommand(uint32(cmd))
	}
}

func (t *tray) onCommand(id uint32) {
	switch id {
	case cmdOpen:
		t.spawnDashboard()
	case cmdStatus:
		t.spawnConsole([]string{"status"})
	case cmdVerify:
		t.spawnConsole([]string{"verify"})
	case cmdQuit:
		if t.onQuit != nil {
			t.onQuit()
		}
		procPostMessage.Call(uintptr(t.hwnd), wmUserQuit, 0, 0)
	}
}

func (t *tray) spawnDashboard() { t.spawnConsole(append([]string{"dashboard"}, t.dashArgs...)) }

// spawnConsole launches seatguard in a brand-new visible console window.
func (t *tray) spawnConsole(args []string) {
	const createNewConsole = 0x00000010
	cmd := exec.Command(t.selfExe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNewConsole}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	_ = cmd.Start()
}

func appendItem(menu uintptr, id uint32, text string) {
	p, _ := windows.UTF16PtrFromString(text)
	procAppendMenu.Call(menu, mfString, uintptr(id), uintptr(unsafe.Pointer(p)))
}

func appendSep(menu uintptr) {
	procAppendMenu.Call(menu, mfSeparator, 0, 0)
}

func copyUTF16(dst []uint16, s string) {
	u := windows.StringToUTF16(s)
	if len(u) > len(dst) {
		u = u[:len(dst)]
		u[len(u)-1] = 0
	}
	for i := range dst {
		if i < len(u) {
			dst[i] = u[i]
		} else {
			dst[i] = 0
		}
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
