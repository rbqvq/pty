// Copyright (c) Tailscale Inc & contributors
// Copyright (c) 2026 CoiaPrant
// SPDX-License-Identifier: BSD-3-Clause
//
// Adapted from tailscale.com/util/winutil/s4u.

package token

import (
	"fmt"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	pkgKerberos = "Kerberos"
	pkgMSV1_0   = "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"

	kerbS4ULogonType = 12 // KERB_LOGON_SUBMIT_TYPE::KerbS4ULogon
	msV1S4ULogonType = 12 // MSV1_0_LOGON_SUBMIT_TYPE::MsV1_0S4ULogon

	_statusNotSupported = 0xC00000BB
)

// wakeMSV1 performs a deliberately failing LogonUser call to initialize
// msv1_0.dll's S4U code path.
//
// Windows lazily initializes MsV1_0S4ULogon; without a prior LogonUser
// invocation, LsaLogonUser can return STATUS_NOT_SUPPORTED even on builds
// that do support S4U. Lifted from Win32-OpenSSH: the fake credentials fail
// authentication, but touching the auth path is the point.
func wakeMSV1() {
	user, _ := windows.UTF16PtrFromString("__wintoken_wakeup_user__")
	domain, _ := windows.UTF16PtrFromString("__wintoken_wakeup_domain__")
	pass, _ := windows.UTF16PtrFromString("__wintoken_wakeup_pass__")

	var token windows.Token
	logonUserW(user, domain, pass,
		_logon32LogonNetworkCleartext,
		_logon32ProviderDefault,
		&token)
	if token != 0 {
		windows.CloseHandle(windows.Handle(token))
	}
}

type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type msv1S4ULogon struct {
	MessageType       uint32
	Flags             uint32
	UserPrincipalName unicodeString
	DomainName        unicodeString
}

type kerbS4ULogon struct {
	MessageType uint32
	Flags       uint32
	ClientUpn   unicodeString
	ClientRealm unicodeString
}

var (
	kerberosPkgOnce sync.Once
	kerberosPkgID   uint32
	kerberosPkgErr  error

	msv1PkgOnce sync.Once
	msv1PkgID   uint32
	msv1PkgErr  error

	compNameOnce sync.Once
	compName     string

	domainJoinedOnce sync.Once
	domainJoinedVal  bool

	thisComputer = []uint16{'.', 0}
)

// logonAs routes username through the appropriate S4U package: MSV1_0 for
// local accounts, Kerberos for domain accounts.
func (ls *lsaSession) logonAs(username string) (windows.Token, error) {
	name, domain, err := splitAccount(username)
	if err != nil {
		return 0, err
	}

	if domain != "" && !isDomainJoined() {
		return 0, fmt.Errorf(
			"token: cannot log on as domain user %q without being joined to a domain",
			domain+`\`+name)
	}

	if domain != "" {
		return ls.logonKerberos(domain + `\` + name)
	}

	return ls.logonMSV1(name)
}

func (ls *lsaSession) logonMSV1(username string) (windows.Token, error) {
	msv1PkgOnce.Do(func() {
		msv1PkgID, msv1PkgErr = ls.lookupPackage(pkgMSV1_0)
	})
	if msv1PkgErr != nil {
		return 0, msv1PkgErr
	}

	upn16, err := windows.UTF16FromString(username)
	if err != nil {
		return 0, err
	}

	token, status, subStatus, err := ls.callLsaLogonUser(msv1PkgID, buildMSV1S4ULogon(upn16))
	if err != nil {
		return 0, err
	}
	if status == 0 {
		return token, nil
	}

	if status == windows.NTStatus(_statusNotSupported) {
		// Retry once after the wakeup. This matches OpenSSH's order: let
		// LsaLogonUser fail with NOT_SUPPORTED first, then fake login to
		// populate msv1_0.dll state, then retry.
		wakeMSV1()

		token, status, subStatus, err = ls.callLsaLogonUser(msv1PkgID, buildMSV1S4ULogon(upn16))
		if err != nil {
			return 0, err
		}
		if status == 0 {
			return token, nil
		}
	}

	return 0, fmt.Errorf(
		"token: LsaLogonUser MSV1_0(%q): NTSTATUS=0x%x, SubStatus=0x%x",
		username, status, subStatus)
}

func (ls *lsaSession) logonKerberos(username string) (windows.Token, error) {
	kerberosPkgOnce.Do(func() {
		kerberosPkgID, kerberosPkgErr = ls.lookupPackage(pkgKerberos)
	})
	if kerberosPkgErr != nil {
		return 0, kerberosPkgErr
	}

	upn16, err := samToUPN16(username)
	if err != nil {
		return 0, fmt.Errorf("token: samToUPN(%q): %w", username, err)
	}

	token, status, subStatus, err := ls.callLsaLogonUser(kerberosPkgID, buildKerbS4ULogon(upn16))
	if err != nil {
		return 0, err
	}

	if status == 0 {
		return token, nil
	}

	return 0, fmt.Errorf(
		"token: LsaLogonUser Kerberos(%q): NTSTATUS=0x%x, SubStatus=0x%x",
		username, status, subStatus)
}

func buildMSV1S4ULogon(user16 []uint16) []byte {
	userLen := len(user16) - 1
	userBytes := userLen * 2

	domainLen := len(thisComputer) - 1
	domainBytes := domainLen * 2

	structSize := int(unsafe.Sizeof(msv1S4ULogon{}))
	buf := make([]byte, structSize+userBytes+domainBytes)

	logon := (*msv1S4ULogon)(unsafe.Pointer(&buf[0]))
	logon.MessageType = msV1S4ULogonType
	logon.Flags = 0

	userBuf := (*uint16)(unsafe.Pointer(&buf[structSize]))
	copy(unsafe.Slice(userBuf, userLen), user16[:userLen])
	logon.UserPrincipalName = unicodeString{
		Length:        uint16(userBytes),
		MaximumLength: uint16(userBytes),
		Buffer:        userBuf,
	}

	domainBuf := (*uint16)(unsafe.Pointer(&buf[structSize+userBytes]))
	copy(unsafe.Slice(domainBuf, domainLen), thisComputer[:domainLen])
	logon.DomainName = unicodeString{
		Length:        uint16(domainBytes),
		MaximumLength: uint16(domainBytes),
		Buffer:        domainBuf,
	}
	return buf
}

func buildKerbS4ULogon(upn16 []uint16) []byte {
	upnLen := len(upn16) - 1
	upnBytes := upnLen * 2
	structSize := int(unsafe.Sizeof(kerbS4ULogon{}))
	buf := make([]byte, structSize+upnBytes)

	logon := (*kerbS4ULogon)(unsafe.Pointer(&buf[0]))
	logon.MessageType = kerbS4ULogonType
	logon.Flags = 0

	upnBuf := (*uint16)(unsafe.Pointer(&buf[structSize]))
	copy(unsafe.Slice(upnBuf, upnLen), upn16[:upnLen])
	logon.ClientUpn = unicodeString{
		Length:        uint16(upnBytes),
		MaximumLength: uint16(upnBytes),
		Buffer:        upnBuf,
	}
	return buf
}

func samToUPN16(samName string) ([]uint16, error) {
	_, samAccount, hasSep := strings.Cut(samName, `\`)
	if !hasSep {
		return nil, fmt.Errorf("expected samName to contain a backslash: %q", samName)
	}

	upn16, err := translateName(samName, windows.NameSamCompatible, windows.NameUserPrincipal)
	if err == nil {
		return upn16, nil
	}

	canonical16, err := translateName(samName, windows.NameSamCompatible, windows.NameCanonical)
	if err != nil {
		return nil, err
	}
	canonical := windows.UTF16ToString(canonical16)

	domain, _, _ := strings.Cut(canonical, "/")
	return windows.UTF16FromString(samAccount + "@" + domain)
}

func translateName(from string, fromFmt, toFmt uint32) ([]uint16, error) {
	from16, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return nil, err
	}

	var size uint32
	if err := windows.TranslateName(from16, fromFmt, toFmt, nil, &size); err != nil {
		return nil, err
	}
	buf := make([]uint16, size)

	if err := windows.TranslateName(from16, fromFmt, toFmt, &buf[0], &size); err != nil {
		return nil, err
	}
	return buf, nil
}

// splitAccount parses username into (bareName, domain). An empty domain
// means local; a non-empty domain means the caller wants a domain logon.
// `.` and the local machine name are treated as local.
func splitAccount(username string) (name string, domain string, err error) {
	if username == "" {
		return "", "", fmt.Errorf("token: empty username")
	}

	if before, after, ok := strings.Cut(username, "\\"); ok {
		dom, usr := before, after
		if usr == "" {
			return "", "", fmt.Errorf("token: empty account name in %q", username)
		}
		if dom == "." || strings.EqualFold(dom, localComputerName()) {
			return usr, "", nil
		}
		return usr, dom, nil
	}

	if strings.ContainsRune(username, '@') {
		return "", "", fmt.Errorf(
			"token: UPN form %q not supported; use DOMAIN\\user", username)
	}

	return username, "", nil
}

func localComputerName() string {
	compNameOnce.Do(func() {
		var buf [windows.MAX_COMPUTERNAME_LENGTH + 1]uint16
		size := uint32(len(buf))

		err := windows.GetComputerName(&buf[0], &size)
		if err != nil {
			return
		}

		compName = windows.UTF16ToString(buf[:size])
	})
	return compName
}

func isDomainJoined() bool {
	domainJoinedOnce.Do(func() {
		var (
			nameBuf  *uint16
			nameType int32
		)
		if status := netGetJoinInformation(nil, &nameBuf, &nameType); status != 0 {
			return
		}
		defer netApiBufferFree(nameBuf)
		domainJoinedVal = nameType == 3 // NetSetupDomainName
	})
	return domainJoinedVal
}
