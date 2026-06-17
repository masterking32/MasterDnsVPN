//go:build android || dragonfly || freebsd || linux || netbsd || openbsd

package sockprotect

import "golang.org/x/sys/unix"

const socketCloseOnExecFlag = unix.SOCK_CLOEXEC
