// Package profile loads a Windows user's profile for a given primary token
// and exposes the profile directory and environment block.
//
// It is decoupled from how the token was obtained. The token may come from
// S4U, NtCreateToken, LogonUser, or a duplicate of the current process
// token; Load does not care.
//
// The caller owns the token. It must remain valid (not closed) for the
// lifetime of the Session, because LoadUserProfileW, CreateEnvironmentBlock
// and GetUserProfileDirectoryW all operate against it.

package profile

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	_piNoUI = 1

	errorProfileAlreadyLoaded syscall.Errno = 203
)

type profileInfo struct {
	Size        uint32
	Flags       uint32
	UserName    *uint16
	ProfilePath *uint16
	DefaultPath *uint16
	ServerName  *uint16
	PolicyPath  *uint16
	Profile     windows.Handle
}

// Session holds the loaded profile and environment for a user. It does not
// own the token; closing the Session does not close the token.
type Session struct {
	token    windows.Token
	env      []string
	envBlock *uint16
	profile  windows.Handle // 0 if not loaded by us (already loaded elsewhere)
	owned    bool           // true iff we called LoadUserProfileW successfully and should unload on Close
	dir      string
}

// Load loads the profile for token. username must match the token's user
// (e.g. "alice", "DOMAIN\alice", "MACHINE\alice").
//
// If the profile is already loaded (common for the interactive user whose
// session is active, or for SYSTEM whose systemprofile is loaded at boot),
// Load succeeds with an unowned profile handle: CreateEnvironmentBlock and
// GetUserProfileDirectoryW still work, but Close will skip UnloadUserProfile
// because we do not own the handle.
//
// If LoadUserProfileW fails with any error other than
// ERROR_PROFILE_ALREADY_LOADED, Load returns that error and does not attempt
// to load the environment block.
func Load(token windows.Token, username string) (*Session, error) {
	name16, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return nil, err
	}

	s := &Session{token: token}

	var pi profileInfo
	pi.Size = uint32(unsafe.Sizeof(pi))
	pi.Flags = _piNoUI
	pi.UserName = name16

	err = loadUserProfile(token, &pi)
	switch {
	case err == nil:
		s.profile = pi.Profile
		s.owned = true
	case errors.Is(err, errorProfileAlreadyLoaded):
		// Someone else (winlogon, services.exe, ...) owns the profile.
		// We may still use the token to build the env block and query the
		// profile directory, we just must not unload it.
		s.profile = pi.Profile
		s.owned = false
	default:
		return nil, fmt.Errorf("profile: LoadUserProfileW(%q): %w", username, err)
	}

	var envBlock *uint16
	if err := createEnvironmentBlock(&envBlock, token, false); err != nil {
		s.Close()
		return nil, fmt.Errorf("profile: CreateEnvironmentBlock: %w", err)
	}
	s.envBlock = envBlock
	s.env = parseEnvBlock(envBlock)

	dir, err := profileDir(token)
	if err != nil {
		s.Close()
		return nil, err
	}
	s.dir = dir
	return s, nil
}

// Environment returns the user's environment as KEY=VALUE strings. The
// slice is owned by the Session and must not be mutated by the caller.
func (s *Session) Environment() []string {
	if s == nil {
		return nil
	}
	return s.env
}

// Dir returns the user's profile directory (e.g. C:\Users\alice).
func (s *Session) Dir() string {
	if s == nil {
		return ""
	}
	return s.dir
}

// Close releases the environment block and, if we loaded it, the profile.
// It does not close the token. Subsequent calls are no-ops.
func (s *Session) Close() error {
	if s == nil {
		return nil
	}

	ret := make([]error, 0, 2)
	if s.envBlock != nil {
		err := destroyEnvironmentBlock(s.envBlock)
		if err != nil {
			ret = append(ret, err)
		}
		s.envBlock = nil
	}

	if s.owned && s.profile != 0 && s.token != 0 {
		err := unloadUserProfile(s.token, s.profile)
		if err != nil {
			ret = append(ret, err)
		}
	}
	s.profile = 0
	s.owned = false

	if len(ret) == 0 {
		return nil
	}
	return errors.Join(ret...)
}

func profileDir(token windows.Token) (string, error) {
	var size uint32
	// First call: sizing. Returns ERROR_INSUFFICIENT_BUFFER with size set
	// to the required number of TCHARs (including the NUL).
	getUserProfileDirectory(token, nil, &size)
	if size == 0 {
		return "", errors.New("profile: GetUserProfileDirectoryW sizing failed")
	}

	buf := make([]uint16, size)
	if err := getUserProfileDirectory(token, &buf[0], &size); err != nil {
		return "", fmt.Errorf("profile: GetUserProfileDirectoryW: %w", err)
	}
	return windows.UTF16ToString(buf[:size]), nil
}

// parseEnvBlock decodes the double-NUL-terminated UTF-16 environment block
// returned by CreateEnvironmentBlock into KEY=VALUE strings.
func parseEnvBlock(block *uint16) []string {
	if block == nil {
		return nil
	}
	var out []string
	p := unsafe.Pointer(block)
	for {
		s := windows.UTF16PtrToString((*uint16)(p))
		if s == "" {
			break
		}
		out = append(out, s)
		p = unsafe.Add(p, (len(s)+1)*2)
	}
	return out
}
