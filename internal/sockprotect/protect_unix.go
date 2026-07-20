//go:build unix

package sockprotect

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// protectTimeout bounds every blocking step of the protect handshake (connect,
// send, and status read) so a stalled or unresponsive protect server can never
// block upstream socket creation indefinitely.
const protectTimeout = 5 * time.Second

// ProtectFD sends fd to an Android-style protect server (matsuri/libneko framing).
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

	// Bound send and receive with timeouts so neither can block forever.
	tv := unix.NsecToTimeval(protectTimeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(connFD, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv); err != nil {
		return fmt.Errorf("set protect send timeout: %w", err)
	}
	if err := unix.SetsockoptTimeval(connFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return fmt.Errorf("set protect status timeout: %w", err)
	}

	if err := connectWithTimeout(connFD, &unix.SockaddrUnix{Name: path}, protectTimeout); err != nil {
		return fmt.Errorf("connect protect socket: %w", err)
	}

	if err := unix.Sendmsg(connFD, []byte{0x01}, unix.UnixRights(int(fd)), nil, 0); err != nil {
		return fmt.Errorf("send fd to protect socket: %w", err)
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

// connectWithTimeout performs a non-blocking connect bounded by timeout, so a
// protect server that accepts slowly (or never) cannot stall the caller.
func connectWithTimeout(connFD int, sa unix.Sockaddr, timeout time.Duration) error {
	if err := unix.SetNonblock(connFD, true); err != nil {
		return fmt.Errorf("set nonblocking: %w", err)
	}
	// Restore blocking mode so the subsequent send/read honor SO_SNDTIMEO/SO_RCVTIMEO.
	defer func() { _ = unix.SetNonblock(connFD, false) }()

	err := unix.Connect(connFD, sa)
	if err == nil {
		return nil
	}
	if err != unix.EINPROGRESS && err != unix.EINTR {
		return err
	}

	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return unix.ETIMEDOUT
		}
		fds := []unix.PollFd{{Fd: int32(connFD), Events: unix.POLLOUT}}
		n, perr := unix.Poll(fds, int(remaining.Milliseconds()))
		if perr != nil {
			if perr == unix.EINTR {
				continue
			}
			return perr
		}
		if n == 0 {
			return unix.ETIMEDOUT
		}
		// Connect finished; surface any pending socket error.
		soErr, gerr := unix.GetsockoptInt(connFD, unix.SOL_SOCKET, unix.SO_ERROR)
		if gerr != nil {
			return gerr
		}
		if soErr != 0 {
			return unix.Errno(soErr)
		}
		return nil
	}
}
