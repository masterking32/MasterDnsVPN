//go:build unix

package sockprotect

import (
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// startStubProtectServer speaks the protect protocol on a temporary Unix
// socket. It answers every request with status and reports on the returned
// channel how many fds the request carried.
func startStubProtectServer(t *testing.T, status byte) (string, <-chan int) {
	t.Helper()

	// /tmp keeps the path under the sun_path limit; t.TempDir() can exceed it on macOS.
	path := fmt.Sprintf("/tmp/mdv-protect-%d-%d.sock", os.Getpid(), time.Now().UnixNano())
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("ListenUnix failed: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	fdCounts := make(chan int, 4)
	go func() {
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				fdCounts <- receiveFDs(conn)
				_, _ = conn.Write([]byte{status})
			}()
		}
	}()
	return path, fdCounts
}

// receiveFDs reads one protect request, closes the fds it carried and returns
// their count, or -1 on error.
func receiveFDs(conn *net.UnixConn) int {
	payload := make([]byte, 1)
	oob := make([]byte, syscall.CmsgSpace(4))
	_, oobn, _, _, err := conn.ReadMsgUnix(payload, oob)
	if err != nil {
		return -1
	}
	messages, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1
	}
	count := 0
	for i := range messages {
		fds, err := syscall.ParseUnixRights(&messages[i])
		if err != nil {
			return -1
		}
		for _, fd := range fds {
			_ = syscall.Close(fd)
		}
		count += len(fds)
	}
	return count
}

func protectTestSocket(t *testing.T, path string) error {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	defer conn.Close()

	rawConn, err := conn.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn failed: %v", err)
	}
	var protectErr error
	if err := rawConn.Control(func(fd uintptr) {
		protectErr = ProtectFD(path, fd)
	}); err != nil {
		t.Fatalf("Control failed: %v", err)
	}
	return protectErr
}

func requireFDCount(t *testing.T, fdCounts <-chan int, want int) {
	t.Helper()

	select {
	case got := <-fdCounts:
		if got != want {
			t.Fatalf("protect server received %d fds, want %d", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for protect server")
	}
}

func TestProtectFDSendsExactlyOneFD(t *testing.T) {
	path, fdCounts := startStubProtectServer(t, 0x01)

	if err := protectTestSocket(t, path); err != nil {
		t.Fatalf("ProtectFD returned error: %v", err)
	}
	requireFDCount(t, fdCounts, 1)
}

func TestProtectFDReportsFailureStatus(t *testing.T) {
	path, fdCounts := startStubProtectServer(t, 0x00)

	err := protectTestSocket(t, path)
	if err == nil {
		t.Fatal("expected ProtectFD to fail on 0x00 status")
	}
	if !strings.Contains(err.Error(), "0x00") {
		t.Fatalf("error should include the status byte, got: %v", err)
	}
	requireFDCount(t, fdCounts, 1)
}
