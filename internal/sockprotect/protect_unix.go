//go:build unix

// Package sockprotect hands socket file descriptors to an Android VpnService
// protect server over a Unix stream socket, so the host can call
// VpnService.protect(fd) before the socket is connected or bound.
package sockprotect

import (
	"fmt"
	"io"
	"net"
	"syscall"
	"time"
)

// protectTimeout bounds one whole protect handshake (connect, send, status
// read) so a stalled protect server cannot hang upstream socket creation.
const protectTimeout = 5 * time.Second

// ProtectFD sends fd to the protect server listening on path and waits for its
// verdict. The wire format matches the libneko/Matsuri protect server: one
// SCM_RIGHTS message carrying the fd plus a single payload byte, answered by one
// status byte where 0x01 means the fd was protected. path must be non-empty.
func ProtectFD(path string, fd uintptr) error {
	deadline := time.Now().Add(protectTimeout)
	dialer := net.Dialer{Deadline: deadline}
	conn, err := dialer.Dial("unix", path)
	if err != nil {
		return fmt.Errorf("connect protect socket: %w", err)
	}
	defer conn.Close()

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("unexpected protect socket type %T", conn)
	}
	if err := unixConn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("set protect deadline: %w", err)
	}
	if _, _, err := unixConn.WriteMsgUnix([]byte{0x01}, syscall.UnixRights(int(fd)), nil); err != nil {
		return fmt.Errorf("send fd to protect socket: %w", err)
	}

	var status [1]byte
	if _, err := io.ReadFull(unixConn, status[:]); err != nil {
		return fmt.Errorf("read protect status: %w", err)
	}
	if status[0] != 0x01 {
		return fmt.Errorf("protect server returned status 0x%02x", status[0])
	}
	return nil
}
