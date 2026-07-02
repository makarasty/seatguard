//go:build windows

package platform

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SignerOf returns the Authenticode signer's common name and validity for
// path, e.g. "Anthropic PBC (trusted)" or "Anthropic PBC (untrusted chain)".
// Returns "unsigned" when the file has no embedded signature. Uses only
// documented WinVerifyTrust / crypt32 APIs — no cgo.
func SignerOf(path string) (string, error) {
	cn, err := signerCommonName(path)
	if err != nil {
		return "unsigned", nil
	}
	trusted := verifyTrust(path) == nil
	if trusted {
		return cn + " (trusted)", nil
	}
	return cn + " (untrusted chain)", nil
}

var (
	modWintrust        = windows.NewLazySystemDLL("wintrust.dll")
	procWinVerifyTrust = modWintrust.NewProc("WinVerifyTrust")

	modCrypt32              = windows.NewLazySystemDLL("crypt32.dll")
	procCryptQueryObject    = modCrypt32.NewProc("CryptQueryObject")
	procCryptMsgGetParam    = modCrypt32.NewProc("CryptMsgGetParam")
	procCertFindCertInStore = modCrypt32.NewProc("CertFindCertificateInStore")
	procCertGetNameStringW  = modCrypt32.NewProc("CertGetNameStringW")
	procCertCloseStore      = modCrypt32.NewProc("CertCloseStore")
	procCryptMsgClose       = modCrypt32.NewProc("CryptMsgClose")
	procCertFreeContext     = modCrypt32.NewProc("CertFreeCertificateContext")
)

// WinVerifyTrust action GUID WINTRUST_ACTION_GENERIC_VERIFY_V2.
var wintrustActionGenericVerifyV2 = windows.GUID{
	Data1: 0xaac56b,
	Data2: 0xcd44,
	Data3: 0x11d0,
	Data4: [8]byte{0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee},
}

type wintrustFileInfo struct {
	cbStruct       uint32
	pcwszFilePath  *uint16
	hFile          windows.Handle
	pgKnownSubject *windows.GUID
}

type wintrustData struct {
	cbStruct            uint32
	pPolicyCallbackData uintptr
	pSIPClientData      uintptr
	dwUIChoice          uint32
	fdwRevocationChecks uint32
	dwUnionChoice       uint32
	pFile               *wintrustFileInfo
	dwStateAction       uint32
	hWVTStateData       windows.Handle
	pwszURLReference    *uint16
	dwProvFlags         uint32
	dwUIContext         uint32
	pSignatureSettings  uintptr
}

func verifyTrust(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	fi := wintrustFileInfo{cbStruct: uint32(unsafe.Sizeof(wintrustFileInfo{})), pcwszFilePath: p}
	const (
		wtdUINone            = 2
		wtdRevokeNone        = 0
		wtdChoiceFile        = 1
		wtdStateActionVerify = 1
		wtdStateActionClose  = 2
		wtdSaferFlag         = 0x100
	)
	data := wintrustData{
		cbStruct:      uint32(unsafe.Sizeof(wintrustData{})),
		dwUIChoice:    wtdUINone,
		dwUnionChoice: wtdChoiceFile,
		pFile:         &fi,
		dwStateAction: wtdStateActionVerify,
		dwProvFlags:   wtdSaferFlag,
	}
	r, _, _ := procWinVerifyTrust.Call(0, uintptr(unsafe.Pointer(&wintrustActionGenericVerifyV2)), uintptr(unsafe.Pointer(&data)))
	// Always release the state data.
	data.dwStateAction = wtdStateActionClose
	procWinVerifyTrust.Call(0, uintptr(unsafe.Pointer(&wintrustActionGenericVerifyV2)), uintptr(unsafe.Pointer(&data)))
	if r != 0 {
		return fmt.Errorf("WinVerifyTrust: 0x%x", r)
	}
	return nil
}

// signerCommonName extracts the subject CN of the leaf signing cert.
func signerCommonName(path string) (string, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	const (
		certQueryObjectFile            = 1
		certQueryContentFlagPKCS7Embed = 1 << 10
		certQueryFormatFlagBinary      = 2
		cmsgSignerInfoParam            = 6
		cmsgSignerCertInfoParam        = 7
	)
	var encoding, contentType, formatType uint32
	var hStore, hMsg uintptr
	r, _, e := procCryptQueryObject.Call(
		certQueryObjectFile,
		uintptr(unsafe.Pointer(p)),
		certQueryContentFlagPKCS7Embed,
		certQueryFormatFlagBinary,
		0,
		uintptr(unsafe.Pointer(&encoding)),
		uintptr(unsafe.Pointer(&contentType)),
		uintptr(unsafe.Pointer(&formatType)),
		uintptr(unsafe.Pointer(&hStore)),
		uintptr(unsafe.Pointer(&hMsg)),
		0,
	)
	if r == 0 {
		return "", fmt.Errorf("CryptQueryObject: %v", e)
	}
	defer procCertCloseStore.Call(hStore, 0)
	defer procCryptMsgClose.Call(hMsg)

	// Fetch CMSG_SIGNER_CERT_INFO_PARAM to locate the signer cert, then
	// find that cert in the store.
	var size uint32
	procCryptMsgGetParam.Call(hMsg, cmsgSignerCertInfoParam, 0, 0, uintptr(unsafe.Pointer(&size)))
	if size == 0 {
		return "", fmt.Errorf("no signer cert info")
	}
	certInfoBuf := make([]byte, size)
	r, _, e = procCryptMsgGetParam.Call(hMsg, cmsgSignerCertInfoParam, 0, uintptr(unsafe.Pointer(&certInfoBuf[0])), uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return "", fmt.Errorf("CryptMsgGetParam: %v", e)
	}
	const certFindSubjectCert = 0x000B0000 | 11 // CERT_FIND_SUBJECT_CERT
	certCtx, _, _ := procCertFindCertInStore.Call(
		hStore, uintptr(encoding), 0, certFindSubjectCert, uintptr(unsafe.Pointer(&certInfoBuf[0])), 0)
	if certCtx == 0 {
		return "", fmt.Errorf("signer cert not found in store")
	}
	defer procCertFreeContext.Call(certCtx)

	const certNameSimpleDisplay = 4 // CERT_NAME_SIMPLE_DISPLAY_TYPE
	n, _, _ := procCertGetNameStringW.Call(certCtx, certNameSimpleDisplay, 0, 0, 0, 0)
	if n <= 1 {
		return "", fmt.Errorf("empty signer name")
	}
	buf := make([]uint16, n)
	procCertGetNameStringW.Call(certCtx, certNameSimpleDisplay, 0, 0, uintptr(unsafe.Pointer(&buf[0])), n)
	return syscall.UTF16ToString(buf), nil
}
