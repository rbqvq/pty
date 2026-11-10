//go:build !windows

package pty

func defaultConfig() *options {
	return &options{
		shell: []string{"zsh", "fish", "bash", "csh", "sh"},
	}
}
