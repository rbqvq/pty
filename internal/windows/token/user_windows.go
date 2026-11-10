package token

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// lookupAccountSID resolves a bare SAM name to a SID via LookupAccountNameW.
func lookupAccountSID(username string) (*windows.SID, error) {
	name16, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return nil, err
	}

	var (
		sidSize    uint32
		domainSize uint32
		sidType    uint32
	)
	_ = windows.LookupAccountName(nil, name16, nil, &sidSize, nil, &domainSize, &sidType)
	if sidSize == 0 {
		return nil, fmt.Errorf("LookupAccountName(%q): user not found", username)
	}

	sidBuf := make([]byte, sidSize)
	domainBuf := make([]uint16, domainSize)
	err = windows.LookupAccountName(
		nil, name16,
		(*windows.SID)(unsafe.Pointer(&sidBuf[0])), &sidSize,
		&domainBuf[0], &domainSize, &sidType,
	)
	if err != nil {
		return nil, fmt.Errorf("LookupAccountName(%q): %w", username, err)
	}
	return (*windows.SID)(unsafe.Pointer(&sidBuf[0])).Copy()
}

// lookupAccountSIDInDomain resolves name in the given domain via
// LookupAccountNameW. Used to disambiguate `DOMAIN\user` from a same-named
// local account.
func lookupAccountSIDInDomain(domain, name string) (*windows.SID, error) {
	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	domain16, err := windows.UTF16PtrFromString(domain)
	if err != nil {
		return nil, err
	}

	var (
		sidSize    uint32
		domainSize uint32
		sidType    uint32
	)
	_ = windows.LookupAccountName(domain16, name16, nil, &sidSize, nil, &domainSize, &sidType)
	if sidSize == 0 {
		return nil, fmt.Errorf("LookupAccountName(%q\\%q): user not found", domain, name)
	}

	sidBuf := make([]byte, sidSize)
	domainBuf := make([]uint16, domainSize)
	err = windows.LookupAccountName(
		domain16, name16,
		(*windows.SID)(unsafe.Pointer(&sidBuf[0])), &sidSize,
		&domainBuf[0], &domainSize, &sidType,
	)
	if err != nil {
		return nil, fmt.Errorf("LookupAccountName(%q\\%q): %w", domain, name, err)
	}
	return (*windows.SID)(unsafe.Pointer(&sidBuf[0])).Copy()
}
