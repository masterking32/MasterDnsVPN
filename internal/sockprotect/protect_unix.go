//go:build unix

package sockprotect

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const protectStatusReadTimeout = 5 * time.Second

// ProtectFD sends fd to an Android/NekoBox-style protect server.
// The server is expected to reply with 0x01 on success.
func ProtectFD(path string, fd uintptr) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}

	connFD, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|socketCloseOnExecFlag, 0)
	if err != nil {
		return fmt.Errorf("open protect socket: %w", err)
	}
	defer unix.Close(connFD)
	if socketCloseOnExecFlag == 0 {
		unix.CloseOnExec(connFD)
	}

	if err := unix.Connect(connFD, &unix.SockaddrUnix{Name: path}); err != nil {
		return fmt.Errorf("connect protect socket: %w", err)
	}

	if err := unix.Sendmsg(connFD, []byte{0x01}, unix.UnixRights(int(fd)), nil, 0); err != nil {
		return fmt.Errorf("send fd to protect socket: %w", err)
	}

	timeout := unix.NsecToTimeval(protectStatusReadTimeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(connFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		return fmt.Errorf("set protect status timeout: %w", err)
	}

	var status [1]byte
	n, err := unix.Read(connFD, status[:])
	if err != nil {
		return fmt.Errorf("read protect status: %w", err)
	}
	if n != 1 {
		return fmt.Errorf("read protect status: short read %d", n)
	}
	if status[0] != 0x01 {
		return fmt.Errorf("protect server returned failure")
	}

	return nil
}
