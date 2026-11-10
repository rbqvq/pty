package pty

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"sync/atomic"

	libpty "gitlab.com/CoiaPrant/pty/internal/windows/conpty"
	"gitlab.com/CoiaPrant/pty/internal/windows/profile"
	"gitlab.com/CoiaPrant/pty/internal/windows/token"
	"golang.org/x/sys/windows"
)

type pty struct {
	tty     *libpty.ConPty
	token   windows.Token
	profile *profile.Session
	closed  atomic.Bool
}

func (pty *pty) Read(p []byte) (int, error) {
	return pty.tty.Read(p)
}

func (pty *pty) Write(p []byte) (int, error) {
	return pty.tty.Write(p)
}

func (pty *pty) Setsize(cols, rows uint32) error {
	return pty.tty.Resize(int(cols), int(rows))
}

func (pty *pty) Close() error {
	if pty.closed.Swap(true) {
		return io.ErrClosedPipe
	}

	if pty.token != 0 {
		defer windows.CloseHandle(windows.Handle(pty.token))
	}

	if pty.profile != nil {
		defer pty.profile.Close()
	}

	return pty.tty.Close()
}

func (pty *pty) wait() {
	pty.tty.Wait(context.Background())
	pty.Close()
}

func New(options ...Option) (Pty, error) {
	if !libpty.IsConPtyAvailable() {
		return nil, libpty.ErrConPtyUnsupported
	}

	config := defaultConfig()
	for _, option := range options {
		option(config)
	}

	var binPath string
	for _, name := range config.shell {
		path, err := exec.LookPath(name)
		if err != nil || path == "" {
			continue
		}
		binPath = path
		break
	}
	if binPath == "" {
		return nil, errors.New("pty: shell not found in PATH")
	}

	switch {
	case config.interactiveLogin:
		return newInactiveLogin(binPath)

	case config.user != "":
		var username string
		var ptyToken windows.Token
		switch config.user {
		case CurrentUser:
			user, err := token.Username()
			if err != nil {
				return nil, err
			}

			token, err := token.Current()
			if err != nil {
				return nil, err
			}

			username = user
			ptyToken = token
		default:
			token, err := token.Login(config.user)
			if err != nil {
				return nil, err
			}

			username = config.user
			ptyToken = token
		}

		profile, err := profile.Load(ptyToken, username)
		if err != nil {
			windows.CloseHandle(windows.Handle(ptyToken))
			return nil, err
		}

		tty, err := libpty.Start(
			binPath,
			libpty.ConPtyToken(ptyToken),
			libpty.ConPtyEnv(profile.Environment()),
			libpty.ConPtyWorkDir(profile.Dir()),
		)
		if err != nil {
			profile.Close()
			windows.CloseHandle(windows.Handle(ptyToken))
			return nil, err
		}

		pty := &pty{tty: tty, token: ptyToken, profile: profile}
		go pty.wait()
		return pty, nil
	default:
		tty, err := libpty.Start(binPath)
		if err != nil {
			return nil, err
		}

		pty := &pty{tty: tty}
		go pty.wait()
		return pty, nil
	}
}
