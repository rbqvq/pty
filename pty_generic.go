//go:build !windows

package pty

import (
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	libpty "github.com/creack/pty"
)

type pty struct {
	tty    *os.File
	cmd    *exec.Cmd
	state  atomic.Pointer[os.ProcessState]
	killed atomic.Bool
	done   chan struct{}
}

func (pty *pty) Read(p []byte) (int, error) {
	for {
		if state := pty.state.Load(); state != nil {
			return 0, &exec.ExitError{ProcessState: state}
		}

		n, err := pty.tty.Read(p)
		if err != nil {
			// login(1) calls vhangup() during startup to detach any
			// processes still attached to the tty, then reopens it via
			// opentty(). While the slave side is hung up, reads on the
			// pty master fail with EIO. The window is transient and
			// clears once login reopens the slave, so just retry.
			time.Sleep(100 * time.Millisecond)
			continue
		}

		return n, nil
	}
}

func (pty *pty) Write(p []byte) (int, error) {
	return pty.tty.Write(p)
}

func (pty *pty) Setsize(cols, rows uint32) error {
	return libpty.Setsize(pty.tty, &libpty.Winsize{
		Cols: uint16(cols),
		Rows: uint16(rows),
	})
}

func (pty *pty) killGroup() {
	pgid, err := syscall.Getpgid(pty.cmd.Process.Pid)
	if err != nil {
		return
	}

	syscall.Kill(-pgid, syscall.SIGHUP)
}

func (pty *pty) kill() {
	if pty.killed.Swap(true) {
		return
	}

	pty.killGroup()
	syscall.Kill(pty.cmd.Process.Pid, syscall.SIGHUP)

	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()

	select {
	case <-pty.done:
		return
	case <-timer.C:
		pty.cmd.Process.Kill()
	}
}

func (pty *pty) Close() error {
	err := pty.tty.Close()
	go pty.kill()
	return err
}

func (pty *pty) wait() {
	pty.cmd.Wait()
	pty.state.Store(pty.cmd.ProcessState)
	close(pty.done)
}

func New(options ...Option) (Pty, error) {
	config := defaultConfig()
	for _, option := range options {
		option(config)
	}

	var candidates []string
	var args []string
	switch {
	case config.interactiveLogin:
		candidates = []string{"login"}
	case config.user != "":
		var username string
		switch config.user {
		case CurrentUser:
			u, err := user.Current()
			if err != nil {
				return nil, err
			}
			username = u.Username
		default:
			username = config.user
		}

		candidates = []string{"login"}
		args = []string{"-f", username}
	default:
		candidates = config.shell
	}

	var binPath string
	for _, bin := range candidates {
		path, err := exec.LookPath(bin)
		if err != nil {
			continue
		}

		if path == "" {
			continue
		}

		binPath = path
		break
	}

	if binPath == "" {
		return nil, errors.New("pty: shell not found in PATH")
	}

	cmd := exec.Command(binPath, args...)

	// login(1) starts the user's shell with argv[0] prefixed by "-"
	// (e.g. "-bash"), which shells use to detect login-shell mode and
	// source /etc/profile, ~/.profile, etc.
	//
	// When we launch a shell directly (config.login == false), mimic that
	// convention so the session looks like a real login session to the
	// shell. We must NOT do this when invoking login(1) itself: login
	// does not expect a "-" prefix on its own argv[0], and it will add
	// the prefix to the shell it spawns.
	if filepath.Base(binPath) != "login" {
		cmd.Args[0] = "-" + filepath.Base(binPath)
	}

	env := os.Environ()
	cmd.Env = make([]string, 0, len(env)+1)
	cmd.Env = append(cmd.Env, env...)
	cmd.Env = append(cmd.Env, "TERM=xterm-256color")

	tty, err := libpty.Start(cmd)
	if err != nil {
		return nil, err
	}

	pty := &pty{
		tty:  tty,
		cmd:  cmd,
		done: make(chan struct{}),
	}
	go pty.wait()
	return pty, nil
}
