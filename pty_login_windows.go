package pty

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	libpty "gitlab.com/CoiaPrant/pty/internal/windows/conpty"
	"gitlab.com/CoiaPrant/pty/internal/windows/profile"
	"gitlab.com/CoiaPrant/pty/internal/windows/token"
	"gitlab.com/go-extension/rand"
	"golang.org/x/sys/windows"
	"golang.org/x/term"
)

const (
	_NERR_PasswordTooShort = syscall.Errno(2245)
)

const (
	maxLoginAttempts  = 5
	maxPasswdAttempts = 3
	failDelay         = 3 * time.Second
)

var errDone = errors.New("pty: operation already done")

type ioPipe struct {
	*io.PipeReader
	*io.PipeWriter
}

func (p *ioPipe) Close() error {
	p.PipeReader.Close()
	p.PipeWriter.Close()
	return nil
}

func (p *ioPipe) CloseWithError(err error) error {
	p.PipeReader.CloseWithError(err)
	p.PipeWriter.CloseWithError(err)
	return err
}

type ptyInactiveLogin struct {
	mutex sync.Mutex

	binPath  string
	pipe     *ioPipe
	terminal *terminal
	pty      *pty
	done     chan struct{}
}

func (p *ptyInactiveLogin) Read(b []byte) (int, error) {
	select {
	case <-p.done:
		return p.pty.Read(b)
	default:
		n, err := p.pipe.Read(b)
		if err != errDone {
			return n, err
		}

		return p.pty.Read(b)
	}
}

func (p *ptyInactiveLogin) Write(b []byte) (int, error) {
	select {
	case <-p.done:
		return p.pty.Write(b)
	default:
		n, err := p.pipe.Write(b)
		if err != errDone {
			return n, err
		}

		nn, err := p.pty.Write(b[n:])
		return n + nn, err
	}
}

func (p *ptyInactiveLogin) Setsize(cols, rows uint32) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	select {
	case <-p.done:
		return p.pty.Setsize(cols, rows)
	default:
		return p.terminal.Setsize(cols, rows)
	}
}

func (p *ptyInactiveLogin) Close() error {
	select {
	case <-p.done:
		return p.pty.Close()
	default:
		return p.pipe.CloseWithError(io.EOF)
	}
}

type ioTerminal struct {
	*ioPipe
	discard atomic.Bool
}

func (t *ioTerminal) Write(b []byte) (int, error) {
	if t.discard.Load() {
		return 0, io.EOF
	}
	return t.ioPipe.Write(b)
}

func (t *ioTerminal) Err(err string) {
	t.discard.Store(true)
	io.WriteString(t.ioPipe, err)
}

type terminal struct {
	*term.Terminal
	pipe       *ioTerminal
	prompt     string
	cols, rows uint32
	notify     chan struct{}
}

func (term *terminal) Setsize(cols, rows uint32) error {
	term.cols = cols
	term.rows = rows
	return term.Terminal.SetSize(int(cols), int(rows))
}

func (term *terminal) CloseWithError(err error) error {
	return term.pipe.CloseWithError(err)
}

func (term *terminal) timeout() {
	defer term.CloseWithError(context.DeadlineExceeded)
	term.pipe.Err("login: timed out after 60 seconds\r\n")

	// NOTE: use buffered channel to avoid ReadLine blocking (no receiver)
	term.notify <- struct{}{}
}

func (term *terminal) askUser() (string, error) {
	timer := time.AfterFunc(time.Minute, term.timeout)

	term.Terminal.SetPrompt(term.prompt)
	ret, err := term.Terminal.ReadLine()
	if timer.Stop() {
		return ret, err
	}

	// avoid io.ErrClosedPipe truncating the error message
	<-term.notify
	return "", context.DeadlineExceeded
}

func (term *terminal) askPassword() (string, error) {
	timer := time.AfterFunc(time.Minute, term.timeout)

	ret, err := term.Terminal.ReadPassword("Password: ")
	if timer.Stop() {
		return ret, err
	}

	// avoid io.ErrClosedPipe truncating the error message
	<-term.notify
	return "", context.DeadlineExceeded
}

func pamFailDelay() {
	base := failDelay
	variance := float64(base) * 0.25
	offset := (rand.Standard.Float64()*2 - 1) * variance
	duration := base + time.Duration(offset)
	time.Sleep(duration)
}

func (p *ptyInactiveLogin) authLoop(terminal *terminal) {
attempt:
	for i := 1; i <= maxLoginAttempts; i++ {
		username, err := terminal.askUser()
		if err != nil {
			terminal.CloseWithError(err)
			return
		}

		password, err := terminal.askPassword()
		if err != nil {
			terminal.CloseWithError(err)
			return
		}

	loginSession:
		userToken, err := token.LoginInteractive(username, password)
		switch {
		case err == nil:
		case errors.Is(err, windows.ERROR_PASSWORD_MUST_CHANGE):
			io.WriteString(terminal.Terminal, "You are required to change your password immediately (administrator enforced).\n")

		changePassword:
			for j := 1; j <= maxPasswdAttempts; j++ {
				newPassword, err := terminal.ReadPassword("New password: ")
				if err != nil {
					terminal.CloseWithError(err)
					return
				}

				retypeNewPassword, err := terminal.ReadPassword("Retype new password: ")
				if err != nil {
					terminal.CloseWithError(err)
					return
				}

				if newPassword != retypeNewPassword {
					io.WriteString(terminal.Terminal, "Sorry, passwords do not match.\n")
					break
				}

				if newPassword == "" {
					io.WriteString(terminal.Terminal, "No password has been supplied.\n")
					continue
				}

				err = token.ChangePassword(username, password, newPassword)
				switch {
				case err == nil:
				case
					errors.Is(err, windows.ERROR_PASSWORD_RESTRICTION),
					errors.Is(err, _NERR_PasswordTooShort):
					io.WriteString(terminal.Terminal, "You must choose a stronger password.\n")
					continue
				default:
					println(err.Error())
					break changePassword
				}

				password = newPassword
				goto loginSession
			}

			io.WriteString(terminal.Terminal, "\nAuthentication token manipulation error\n")
			pamFailDelay()
			terminal.CloseWithError(nil)
			return

		default:
			pamFailDelay()
			if i >= maxLoginAttempts {
				break attempt
			}

			io.WriteString(terminal.Terminal, "Login incorrect\n")
			continue
		}

		userProfile, err := profile.Load(userToken, username)
		if err != nil {
			windows.CloseHandle(windows.Handle(userToken))
			terminal.CloseWithError(err)
			return
		}

		tty, err := libpty.Start(
			p.binPath,
			libpty.ConPtyToken(userToken),
			libpty.ConPtyEnv(userProfile.Environment()),
			libpty.ConPtyWorkDir(userProfile.Dir()),
		)
		if err != nil {
			userProfile.Close()
			windows.CloseHandle(windows.Handle(userToken))
			terminal.CloseWithError(err)
			return
		}

		p.pty = &pty{tty: tty, profile: userProfile, token: userToken}
		go p.pty.wait()

		p.mutex.Lock()
		defer p.mutex.Unlock()
		p.terminal = nil // for GC
		p.pty.Setsize(terminal.cols, terminal.rows)

		close(p.done)
		terminal.CloseWithError(errDone)
		return
	}

	io.WriteString(terminal.Terminal, "\nLogin incorrect\n")
	terminal.CloseWithError(nil)
}

func newInactiveLogin(binPath string) (Pty, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	authR, ptyW := io.Pipe()
	ptyR, authW := io.Pipe()
	pipePty := &ioPipe{PipeReader: ptyR, PipeWriter: ptyW}
	pipeTerm := &ioTerminal{ioPipe: &ioPipe{PipeReader: authR, PipeWriter: authW}}

	term := term.NewTerminal(pipeTerm, "")
	terminal := &terminal{
		Terminal: term,
		prompt:   hostname + " login: ",
		pipe:     pipeTerm,
		notify:   make(chan struct{}, 1),
	}
	p := &ptyInactiveLogin{
		binPath:  binPath,
		pipe:     pipePty,
		terminal: terminal,
		done:     make(chan struct{}),
	}
	go p.authLoop(terminal)
	return p, nil
}
