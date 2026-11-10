package pty

type options struct {
	shell            []string
	user             string
	interactiveLogin bool
}

type Option func(config *options)

func WithShell(shell ...string) Option {
	return func(config *options) {
		config.shell = shell
	}
}

func WithUser(user string) Option {
	return func(config *options) {
		config.user = user
	}
}

func WithInteractiveLogin() Option {
	return func(config *options) {
		config.interactiveLogin = true
	}
}
