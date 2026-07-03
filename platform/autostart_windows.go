//go:build windows

package platform

import "golang.org/x/sys/windows/registry"

// runKey is the per-user autostart location: values here run at logon with
// the user's token. Writable without elevation (unlike Task Scheduler with
// /RL HIGHEST, which needs an admin console to register).
const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`

// SetAutostart registers cmdline to run at logon under the given name.
func SetAutostart(name, cmdline string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(name, cmdline)
}

// RemoveAutostart deletes the logon entry.
func RemoveAutostart(name string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.DeleteValue(name)
}

// AutostartInstalled reports whether an autostart entry exists.
func AutostartInstalled(name string) bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue(name)
	return err == nil
}
