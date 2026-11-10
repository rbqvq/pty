package token

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// SECBUFFER_CHANGE_PASS_RESPONSE is the buffer type expected by
	// ChangeAccountPasswordW for its output parameter.
	_secBufferChangePassResponse = 15
)

// domainPasswordInformation mirrors DOMAIN_PASSWORD_INFORMATION from
// ntsecapi.h. ChangeAccountPasswordW fills this on output to report the
// domain's password policy when the new password is rejected.
type domainPasswordInformation struct {
	MinPasswordLength     uint16
	PasswordHistoryLength uint16
	PasswordProperties    uint32
	MaxPasswordAge        int64
	MinPasswordAge        int64
}

// secBuffer mirrors SecBuffer from sspi.h.
type secBuffer struct {
	cbBuffer   uint32
	BufferType uint32
	pvBuffer   unsafe.Pointer
}

// secBufferDesc mirrors SecBufferDesc from sspi.h.
type secBufferDesc struct {
	ulVersion uint32
	cBuffers  uint32
	pBuffers  *secBuffer
}

// changePasswordKerberos changes the password for a domain account by calling
// ChangeAccountPasswordW with the "Kerberos" security provider. This is the
// supported path for domain accounts; NetUserChangePassword does not work
// against Active Directory.
//
// domain must be the NetBIOS or DNS domain name of the account (e.g. "CORP"),
// not the local machine name. user is the bare SAM account name.
//
// The calling process must be able to reach a domain controller over
// Kerberos (TCP/UDP 88 and 464).
func changePasswordKerberos(domain, user, oldPassword, newPassword string) error {
	packageName, err := windows.UTF16PtrFromString("Kerberos")
	if err != nil {
		return err
	}
	domainPtr, err := windows.UTF16PtrFromString(domain)
	if err != nil {
		return err
	}
	userPtr, err := windows.UTF16PtrFromString(user)
	if err != nil {
		return err
	}
	oldPtr, err := windows.UTF16PtrFromString(oldPassword)
	if err != nil {
		return err
	}
	newPtr, err := windows.UTF16PtrFromString(newPassword)
	if err != nil {
		return err
	}

	// DOMAIN_PASSWORD_INFORMATION is the documented payload; the extra
	// headroom covers any version-specific trailing data SSPI may append.
	var passwordInfo domainPasswordInformation
	outBuf := secBuffer{
		cbBuffer:   uint32(unsafe.Sizeof(passwordInfo)) + 64,
		BufferType: _secBufferChangePassResponse,
		pvBuffer:   unsafe.Pointer(&passwordInfo),
	}
	outDesc := secBufferDesc{
		ulVersion: 0,
		cBuffers:  1,
		pBuffers:  &outBuf,
	}

	status := changeAccountPasswordW(
		packageName, domainPtr, userPtr, oldPtr, newPtr,
		false, 0, &outDesc,
	)
	if status != 0 {
		if passwordInfo != (domainPasswordInformation{}) {
			return fmt.Errorf(
				"token: ChangeAccountPasswordW(%s\\%s): password rejected by domain policy (min length %d, history %d): %w",
				domain, user, passwordInfo.MinPasswordLength, passwordInfo.PasswordHistoryLength,
				windows.ERROR_PASSWORD_RESTRICTION)
		}

		return fmt.Errorf(
			"token: ChangeAccountPasswordW(%s\\%s): SECURITY_STATUS=0x%x",
			domain, user, status)
	}
	return nil
}

func changePassword(user, oldPassword, newPassword string) error {
	namePtr, err := windows.UTF16PtrFromString(user)
	if err != nil {
		return err
	}
	oldPtr, err := windows.UTF16PtrFromString(oldPassword)
	if err != nil {
		return err
	}
	newPtr, err := windows.UTF16PtrFromString(newPassword)
	if err != nil {
		return err
	}
	localPtr, err := windows.UTF16PtrFromString(`\\127.0.0.1`)
	if err != nil {
		return err
	}

	status := netUserChangePassword(localPtr, namePtr, oldPtr, newPtr)
	if status != 0 {
		return fmt.Errorf("token: NetUserChangePassword(%q): %w", user, syscall.Errno(status))
	}
	return nil
}
