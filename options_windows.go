//go:build windows

package pty

func defaultConfig() *options {
	return &options{
		shell: []string{"bash.exe", "powershell.exe", "cmd.exe"},
	}
}
