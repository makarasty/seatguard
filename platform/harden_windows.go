//go:build windows

package platform

import (
	"golang.org/x/sys/windows"
)

// HardenFile replaces the file's DACL with a protected (non-inherited) ACL
// granting full control to the file's owner, LocalSystem and the local
// Administrators group only. This is defense-in-depth on top of the HMAC:
// os.Chmod's 0600 is advisory on Windows, so we set a real ACL. Best
// effort — callers treat failure as non-fatal.
func HardenFile(path string) error {
	// Resolve current user SID (the intended owner in Phase 1, where the
	// daemon runs under the installing user).
	tok := windows.GetCurrentProcessToken()
	user, err := tok.GetTokenUser()
	if err != nil {
		return err
	}
	ownerSID := user.User.Sid

	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	adminsSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}

	ea := []windows.EXPLICIT_ACCESS{
		grantAll(ownerSID),
		grantAll(systemSID),
		grantAll(adminsSID),
	}
	acl, err := windows.ACLFromEntries(ea, nil)
	if err != nil {
		return err
	}
	// PROTECTED_DACL_SECURITY_INFORMATION strips inherited ACEs so a broad
	// parent-directory ACL cannot re-widen access.
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil,
	)
}

func grantAll(sid *windows.SID) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}
