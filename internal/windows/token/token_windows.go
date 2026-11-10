// Package token acquires Windows primary tokens for a target user, with or
// without a password.
//
// The public surface is Login / Current / Username / LoginInteractive /
// ChangePassword. Internally:
//
//   - lsa_windows.go wraps LsaRegisterLogonProcess, LsaLookupAuthenticationPackage
//     and LsaLogonUser.
//   - s4u_windows.go builds the MSV1_0 and Kerberos S4U submit structures and
//     decides which authentication package to use.
//   - user_windows.go resolves account names to SIDs and compares them against
//     the calling process identity.
//
// Login takes one of three paths:
//
//   - If username resolves to the calling process's own SID, it returns a
//     duplicate of the process token (Current) without touching LSA.
//   - Otherwise the process must be running as LocalSystem. Any other account
//     cannot generate tokens for other users.
//   - As LocalSystem, Login uses MSV1_0 S4U for local accounts and Kerberos
//     S4U for domain accounts on a domain-joined machine.
//
// LoginInteractive authenticates with a plaintext password via LogonUserW and
// LOGON32_LOGON_NETWORK_CLEARTEXT, matching Win32-OpenSSH's
// windows_password_auth. The returned token is an impersonation token, so it
// is duplicated into a primary token before being returned.
//
// When the password is correct but expired, LoginInteractive returns an error
// that matches windows.ERROR_PASSWORD_MUST_CHANGE via errors.Is. The caller
// should prompt for a new password and call ChangePassword, then retry
// LoginInteractive with the new password.
//
// S4U requires SeTcbPrivilege, which is enabled on first import if the process
// holds it.

package token

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

const (
	nameSamCompatible             = 2 // EXTENDED_NAME_FORMAT::NameSamCompatible
	_logon32LogonNetworkCleartext = 8 // LOGON32_LOGON_NETWORK_CLEARTEXT
	_logon32ProviderDefault       = 0 // LOGON32_PROVIDER_DEFAULT
)

func init() {
	enablePrivilege("SeTcbPrivilege")
}

func enablePrivilege(name string) error {
	var token windows.Token
	err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY,
		&token,
	)
	if err != nil {
		return err
	}
	defer token.Close()

	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}

	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, name16, &luid)
	if err != nil {
		return err
	}

	privs := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{{
			Luid:       luid,
			Attributes: windows.SE_PRIVILEGE_ENABLED,
		}},
	}
	return windows.AdjustTokenPrivileges(token, false, &privs, 0, nil, nil)
}

func logonProcessName() string {
	exe, err := os.Executable()
	if err != nil {
		return "conpty"
	}

	name := filepath.Base(exe)
	return strings.TrimSuffix(name, filepath.Ext(name))
}

// Current returns a primary token that duplicates the calling process's
// identity. Use this for ":current:" semantics on Windows; do not route it
// through S4U, which would try to look the process identity up as a loggable
// account and fail under SYSTEM.
func Current() (windows.Token, error) {
	var token windows.Token
	err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY,
		&token,
	)
	if err != nil {
		return 0, fmt.Errorf("token: OpenProcessToken: %w", err)
	}
	defer token.Close()

	var dup windows.Token
	err = windows.DuplicateTokenEx(
		token, windows.MAXIMUM_ALLOWED, nil,
		windows.SecurityImpersonation, windows.TokenPrimary,
		&dup,
	)
	if err != nil {
		return 0, fmt.Errorf("token: DuplicateTokenEx: %w", err)
	}
	return dup, nil
}

// Username returns DOMAIN\user for the calling process, via
// GetUserNameExW(NameSamCompatible). Unlike user.Current(), it returns
// "NT AUTHORITY\SYSTEM" correctly under SYSTEM instead of the machine
// account name.
func Username() (string, error) {
	var size uint32
	err := getUserNameEx(nameSamCompatible, nil, &size)
	if !errors.Is(err, windows.ERROR_MORE_DATA) {
		if err == nil {
			return "", errors.New("token: GetUserNameExW sizing unexpectedly succeeded")
		}
		return "", fmt.Errorf("token: GetUserNameExW sizing: %w", err)
	}

	buf := make([]uint16, size)
	err = getUserNameEx(nameSamCompatible, &buf[0], &size)
	if err != nil {
		return "", fmt.Errorf("token: GetUserNameExW: %w", err)
	}
	return windows.UTF16ToString(buf[:size]), nil
}

func currentProcessSID() (*windows.SID, error) {
	var token windows.Token
	err := windows.OpenProcessToken(
		windows.CurrentProcess(), windows.TOKEN_QUERY, &token,
	)
	if err != nil {
		return nil, fmt.Errorf("token: OpenProcessToken: %w", err)
	}
	defer token.Close()

	user, err := token.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("token: GetTokenUser: %w", err)
	}
	return user.User.Sid.Copy()
}

// isCurrentUser reports whether username resolves to the identity of the
// calling process. It compares SIDs, not strings, so "PC", `MACHINE\PC` and
// `DOMAIN\PC` all match the same account.
func isCurrentUser(username string) (bool, error) {
	name, domain, err := splitAccount(username)
	if err != nil {
		return false, err
	}

	var requested *windows.SID
	switch domain {
	case "":
		requested, err = lookupAccountSID(name)
	default:
		requested, err = lookupAccountSIDInDomain(domain, name)
	}
	if err != nil {
		return false, err
	}

	current, err := currentProcessSID()
	if err != nil {
		return false, err
	}
	return requested.Equals(current), nil
}

// isLocalSystem reports whether the calling process runs as LocalSystem
// (S-1-5-18). Only LocalSystem can generate tokens for other users via S4U.
func isLocalSystem() (bool, error) {
	var token windows.Token
	err := windows.OpenProcessToken(
		windows.CurrentProcess(), windows.TOKEN_QUERY, &token,
	)
	if err != nil {
		return false, fmt.Errorf("token: OpenProcessToken: %w", err)
	}
	defer token.Close()

	user, err := token.GetTokenUser()
	if err != nil {
		return false, fmt.Errorf("token: GetTokenUser: %w", err)
	}

	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return false, fmt.Errorf("token: CreateWellKnownSid: %w", err)
	}
	return user.User.Sid.Equals(systemSID), nil
}

// Login returns a primary token for username without requiring a password.
// username may be "user", `MACHINE\user`, or `DOMAIN\user`.
//
// If username resolves to the calling process's own identity, Login returns
// a duplicate of the process token regardless of the process account.
//
// Otherwise the process must be running as LocalSystem; only LocalSystem can
// generate tokens for other users via S4U.
func Login(username string) (windows.Token, error) {
	current, err := isCurrentUser(username)
	if err != nil {
		return 0, err
	}
	if current {
		return Current()
	}

	system, err := isLocalSystem()
	if err != nil {
		return 0, err
	}
	if !system {
		return 0, fmt.Errorf(
			"token: cannot log on as %q: process is not running as LocalSystem",
			username)
	}

	lsa, err := newLSASessionForLogon(logonProcessName())
	if err != nil {
		return 0, err
	}

	defer lsa.Close()
	return lsa.logonAs(username)
}

// LoginInteractive returns a primary token for username after verifying
// password against the local SAM (for local accounts) or the domain (for
// DOMAIN\user accounts on a domain-joined machine).
//
// The login uses LOGON32_LOGON_NETWORK_CLEARTEXT, matching Win32-OpenSSH's
// windows_password_auth. That logon type returns an impersonation token, which
// is duplicated into a primary token before being returned so callers can pass
// it to CreateProcessAsUser or a ConPTY helper.
//
// If the password is correct but expired, LoginInteractive returns an error
// matching ErrPasswordMustChange. Call ChangePassword and retry with the new
// password.
//
// The caller must not pass the password of an account they should not have
// access to; LogonUser enforces the usual Windows policy (logon hours,
// logon-to restrictions, account lockout, LimitBlankPasswordUse) and may fail
// with ERROR_ACCOUNT_RESTRICTION, ERROR_LOGON_TYPE_NOT_GRANTED, or
// ERROR_ACCOUNT_LOCKED_OUT.
func LoginInteractive(username, password string) (windows.Token, error) {
	name, domain, err := splitAccount(username)
	if err != nil {
		return 0, err
	}

	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	passPtr, err := windows.UTF16PtrFromString(password)
	if err != nil {
		return 0, err
	}

	var domainPtr *uint16
	if domain != "" {
		domainPtr, err = windows.UTF16PtrFromString(domain)
		if err != nil {
			return 0, err
		}
	}

	var impToken windows.Token
	err = logonUserW(
		namePtr, domainPtr, passPtr,
		_logon32LogonNetworkCleartext,
		_logon32ProviderDefault,
		&impToken,
	)
	if err != nil {
		return 0, fmt.Errorf("token: LogonUser(%q): %w", username, err)
	}
	defer impToken.Close()

	// LOGON32_LOGON_NETWORK_CLEARTEXT returns an impersonation token.
	// Upgrade to a primary token so CreateProcessAsUser accepts it.
	var primary windows.Token
	err = windows.DuplicateTokenEx(
		impToken, windows.MAXIMUM_ALLOWED, nil,
		windows.SecurityImpersonation, windows.TokenPrimary,
		&primary,
	)
	if err != nil {
		return 0, fmt.Errorf("token: DuplicateTokenEx: %w", err)
	}

	return primary, nil
}

// ChangePassword changes the password for username, verifying oldPassword
// first. It is intended to be called after LoginInteractive returns an error
// matching windows.ERROR_PASSWORD_MUST_CHANGE.
//
// Local accounts are changed through NetUserChangePassword against
// \\127.0.0.1. The server argument cannot be NULL or ".": NULL resolves to
// the caller's logon domain (NT AUTHORITY under LocalSystem), which returns
// NERR_UserNotFound for local accounts, and "." returns ERROR_BAD_NETPATH (67).
//
// Domain accounts are changed through ChangeAccountPasswordW with the
// Kerberos provider; the calling process must be able to reach a domain
// controller over TCP/UDP 88 and 464.
//
// The caller is responsible for choosing newPassword that satisfies the
// password policy. Local policy failures wrap ERROR_PASSWORD_RESTRICTION or
// NERR_PasswordTooShort; domain policy failures return a SECURITY_STATUS.
func ChangePassword(username, oldPassword, newPassword string) error {
	user, domain, err := splitAccount(username)
	if err != nil {
		return err
	}
	if domain != "" {
		return changePasswordKerberos(domain, user, oldPassword, newPassword)
	}

	return changePassword(user, oldPassword, newPassword)
}
