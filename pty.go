package pty

const CurrentUser = ":current:"

type Pty interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Setsize(cols, rows uint32) error
	Close() error
}
