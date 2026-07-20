//go:build unix

package sockprotect

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type protectServerResult struct {
	fdCount int
	err     error
}

func startStubProtectServer(t *testing.T, status byte) (string, <-chan protectServerResult) {
	t.Helper()

	path := fmt.Sprintf("/tmp/masterdnsvpn-protect-%d.sock", time.Now().UnixNano())
	_ = os.Remove(path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("Listen unix failed: %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
		_ = os.Remove(path)
	})

	resultCh := make(chan protectServerResult, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			resultCh <- protectServerResult{err: err}
			return
		}
		defer conn.Close()

		unixConn, ok := conn.(*net.UnixConn)
		if !ok {
			resultCh <- protectServerResult{err: syscall.EINVAL}
			return
		}

		rawConn, err := unixConn.SyscallConn()
		if err != nil {
			resultCh <- protectServerResult{err: err}
			return
		}

		var (
			payload [1]byte
			oobn    int
			readErr error
		)
		oob := make([]byte, unix.CmsgSpace(4))
		if err := rawConn.Read(func(fd uintptr) bool {
			_, oobn, _, _, readErr = unix.Recvmsg(int(fd), payload[:], oob, 0)
			return true
		}); err != nil {
			resultCh <- protectServerResult{err: err}
			return
		}
		if readErr != nil {
			resultCh <- protectServerResult{err: readErr}
			return
		}

		messages, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			resultCh <- protectServerResult{err: err}
			return
		}

		fdCount := 0
		for _, msg := range messages {
			fds, err := unix.ParseUnixRights(&msg)
			if err != nil {
				resultCh <- protectServerResult{err: err}
				return
			}
			fdCount += len(fds)
			for _, receivedFD := range fds {
				_ = unix.Close(receivedFD)
			}
		}

		_, err = conn.Write([]byte{status})
		resultCh <- protectServerResult{fdCount: fdCount, err: err}
	}()

	return path, resultCh
}

func callProtectWithUDPSocket(t *testing.T, path string) error {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket udp failed: %v", err)
	}
	defer conn.Close()

	sysConn, ok := conn.(syscall.Conn)
	if !ok {
		t.Fatal("udp socket does not expose SyscallConn")
	}
	rawConn, err := sysConn.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn failed: %v", err)
	}

	var protectErr error
	if err := rawConn.Control(func(fd uintptr) {
		protectErr = ProtectFD(path, fd)
	}); err != nil {
		return err
	}
	return protectErr
}

func requireProtectServerResult(t *testing.T, resultCh <-chan protectServerResult) protectServerResult {
	t.Helper()

	select {
	case result := <-resultCh:
		if result.err != nil {
			t.Fatalf("protect server failed: %v", result.err)
		}
		return result
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for protect server")
		return protectServerResult{}
	}
}

func TestProtectFDSendsExactlyOneFD(t *testing.T) {
	path, resultCh := startStubProtectServer(t, 0x01)

	if err := callProtectWithUDPSocket(t, path); err != nil {
		t.Fatalf("ProtectFD returned error: %v", err)
	}

	result := requireProtectServerResult(t, resultCh)
	if result.fdCount != 1 {
		t.Fatalf("expected one fd, got %d", result.fdCount)
	}
}

func TestProtectFDReturnsErrorOnFailureStatus(t *testing.T) {
	path, resultCh := startStubProtectServer(t, 0x00)

	if err := callProtectWithUDPSocket(t, path); err == nil {
		t.Fatal("expected ProtectFD to fail on 0x00 status")
	}

	result := requireProtectServerResult(t, resultCh)
	if result.fdCount != 1 {
		t.Fatalf("expected one fd, got %d", result.fdCount)
	}
}
