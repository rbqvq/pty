// Copyright (c) Tailscale Inc & contributors
// Copyright (c) 2026 CoiaPrant
// SPDX-License-Identifier: BSD-3-Clause
//
// Adapted from tailscale.com/util/winutil/s4u.

package token

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

type _LSAHANDLE windows.Handle
type _LSA_OPERATIONAL_MODE uint32
type _SECURITY_LOGON_TYPE int32

const logonTypeNetwork _SECURITY_LOGON_TYPE = 3

// maxLSAStringLength is the practical upper bound for LSA_STRING payloads
// passed to LsaRegisterLogonProcess / LsaLogonUser. The documented limit is
// 127 characters; longer names are truncated rather than rejected so an
// unusually long executable name doesn't break logon outright.
const maxLSAStringLength = 127

// lsaString mirrors LSA_STRING. buf keeps the backing bytes alive for the
// duration of the syscall; callers must KeepAlive the *lsaString.
type lsaString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *byte
	buf           []byte
}

func newLSAString(s string) (*lsaString, error) {
	if len(s) > maxLSAStringLength {
		s = s[:maxLSAStringLength]
	}
	for _, c := range []byte(s) {
		if c > 0x7f {
			return nil, fmt.Errorf("token: LSA string must be ASCII: %q", s)
		}
	}
	b := append([]byte(s), 0)
	return &lsaString{
		Length:        uint16(len(s)),
		MaximumLength: uint16(len(b)),
		Buffer:        &b[0],
		buf:           b,
	}, nil
}

type tokenSource struct {
	SourceName       [8]byte
	SourceIdentifier windows.LUID
}

type quotaLimits struct {
	PagedPoolLimit        uintptr
	NonPagedPoolLimit     uintptr
	MinimumWorkingSetSize uintptr
	MaximumWorkingSetSize uintptr
	PagefileLimit         uintptr
	TimeLimit             int64
}

type lsaSession struct {
	handle      _LSAHANDLE
	processName string
}

func newLSASessionForLogon(processName string) (*lsaSession, error) {
	ls, err := newLSAString(processName)
	if err != nil {
		return nil, err
	}
	defer runtime.KeepAlive(ls)

	var (
		h    _LSAHANDLE
		mode _LSA_OPERATIONAL_MODE
	)
	if status := lsaRegisterLogonProcess(ls, &h, &mode); status != 0 {
		return nil, fmt.Errorf(
			"token: LsaRegisterLogonProcess: NTSTATUS=0x%x (missing SeTcbPrivilege?)", status)
	}
	return &lsaSession{handle: h, processName: processName}, nil
}

func (ls *lsaSession) Close() {
	if ls.handle == 0 {
		return
	}

	lsaDeregisterLogonProcess(ls.handle)
	ls.handle = 0
}

func (ls *lsaSession) lookupPackage(name string) (uint32, error) {
	lstr, err := newLSAString(name)
	if err != nil {
		return 0, err
	}
	defer runtime.KeepAlive(lstr)

	var id uint32
	status := lsaLookupAuthenticationPackage(ls.handle, lstr, &id)
	if status != 0 {
		return 0, fmt.Errorf(
			"token: LsaLookupAuthenticationPackage(%q): NTSTATUS=0x%x", name, status)
	}
	return id, nil
}

// callLsaLogonUser performs LsaLogonUser and returns the resulting primary
// token on success. On LSA-level failure it returns status != 0 and
// err == nil; callers may inspect status to decide on a fallback. err is
// reserved for Go-side failures (allocation, DuplicateTokenEx).
func (ls *lsaSession) callLsaLogonUser(pkgID uint32, authInfo []byte) (windows.Token, windows.NTStatus, uint32, error) {
	originName, err := newLSAString(ls.processName)
	if err != nil {
		return 0, 0, 0, err
	}
	defer runtime.KeepAlive(originName)
	defer runtime.KeepAlive(authInfo)

	var srcCtx tokenSource
	copy(srcCtx.SourceName[:], "wintokn\x00")
	err = allocateLocallyUniqueId(&srcCtx.SourceIdentifier)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("token: AllocateLocallyUniqueId: %w", err)
	}

	var (
		profileBuf    uintptr
		profileBufLen uint32
		logonID       windows.LUID
		impersonation windows.Token
		quotas        quotaLimits
		subStatus     uint32
	)
	status := lsaLogonUser(
		ls.handle, originName, logonTypeNetwork, pkgID,
		unsafe.Pointer(&authInfo[0]), uint32(len(authInfo)),
		nil, &srcCtx,
		&profileBuf, &profileBufLen, &logonID, &impersonation,
		&quotas, &subStatus,
	)
	if profileBuf != 0 {
		lsaFreeReturnBuffer(profileBuf)
	}
	if status != 0 {
		return 0, status, subStatus, nil
	}

	var token windows.Token
	err = windows.DuplicateTokenEx(
		impersonation, 0, nil,
		windows.SecurityImpersonation, windows.TokenPrimary,
		&token,
	)
	if err != nil {
		windows.CloseHandle(windows.Handle(impersonation))
		return 0, 0, 0, fmt.Errorf("token: DuplicateTokenEx: %w", err)
	}

	windows.CloseHandle(windows.Handle(impersonation))
	return token, 0, 0, nil
}
