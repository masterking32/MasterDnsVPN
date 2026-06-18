//go:build unix

package client

import (
	"context"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"masterdnsvpn-go/internal/config"
)

type clientProtectServerResult struct {
	fdCount int
	err     error
}

func startClientStubProtectServer(t *testing.T, status byte) (string, <-chan clientProtectServerResult) {
	t.Helper()

	path := fmt.Sprintf("/tmp/masterdnsvpn-client-protect-%d.sock", time.Now().UnixNano())
	_ = os.Remove(path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("Listen unix failed: %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
		_ = os.Remove(path)
	})

	resultCh := make(chan clientProtectServerResult, 4)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleClientProtectConn(conn, status, resultCh)
		}
	}()

	return path, resultCh
}

func handleClientProtectConn(conn net.Conn, status byte, resultCh chan<- clientProtectServerResult) {
	defer conn.Close()

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		resultCh <- clientProtectServerResult{err: syscall.EINVAL}
		return
	}

	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		resultCh <- clientProtectServerResult{err: err}
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
		resultCh <- clientProtectServerResult{err: err}
		return
	}
	if readErr != nil {
		resultCh <- clientProtectServerResult{err: readErr}
		return
	}

	messages, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		resultCh <- clientProtectServerResult{err: err}
		return
	}

	fdCount := 0
	for _, msg := range messages {
		fds, err := unix.ParseUnixRights(&msg)
		if err != nil {
			resultCh <- clientProtectServerResult{err: err}
			return
		}
		fdCount += len(fds)
		for _, receivedFD := range fds {
			_ = unix.Close(receivedFD)
		}
	}

	_, err = conn.Write([]byte{status})
	resultCh <- clientProtectServerResult{fdCount: fdCount, err: err}
}

func requireClientProtectResult(t *testing.T, resultCh <-chan clientProtectServerResult) clientProtectServerResult {
	t.Helper()

	select {
	case result := <-resultCh:
		if result.err != nil {
			t.Fatalf("protect server failed: %v", result.err)
		}
		return result
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for protect server")
		return clientProtectServerResult{}
	}
}

func TestProtectedResolverQuerySendsFDToProtectServer(t *testing.T) {
	resolverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP resolver failed: %v", err)
	}
	defer resolverConn.Close()

	protectPath, protectResults := startClientStubProtectServer(t, 0x01)
	c := New(config.ClientConfig{
		FDControlUnixSocket:         protectPath,
		PacketDuplicationCount:      1,
		SetupPacketDuplicationCount: 1,
		RX_TX_Workers:               1,
	}, nil, nil)

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 512)
		n, addr, err := resolverConn.ReadFromUDP(buf)
		if err != nil || n < 2 {
			return
		}
		_, _ = resolverConn.WriteToUDP([]byte{buf[0], buf[1], 0x81, 0x00}, addr)
	}()

	udpConn, err := c.getUDPConn(context.Background(), resolverConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("getUDPConn returned error: %v", err)
	}
	defer udpConn.Close()

	response, err := c.exchangeUDPQueryWithConn(udpConn, []byte{0x12, 0x34, 0x01}, time.Second)
	if err != nil {
		t.Fatalf("exchangeUDPQueryWithConn returned error: %v", err)
	}
	if len(response) < 2 || response[0] != 0x12 || response[1] != 0x34 {
		t.Fatalf("unexpected resolver response: %v", response)
	}

	result := requireClientProtectResult(t, protectResults)
	if result.fdCount != 1 {
		t.Fatalf("expected one protected resolver fd, got %d", result.fdCount)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for resolver traffic")
	}
}

func TestListenUDPProtectedSendsFDToProtectServer(t *testing.T) {
	protectPath, protectResults := startClientStubProtectServer(t, 0x01)
	c := New(config.ClientConfig{FDControlUnixSocket: protectPath}, nil, nil)

	conn, err := c.listenUDPProtected(context.Background(), &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listenUDPProtected returned error: %v", err)
	}
	defer conn.Close()

	result := requireClientProtectResult(t, protectResults)
	if result.fdCount != 1 {
		t.Fatalf("expected one protected listener fd, got %d", result.fdCount)
	}
}

func TestListenUDPProtectedFailsOnProtectFailure(t *testing.T) {
	protectPath, _ := startClientStubProtectServer(t, 0x00)
	c := New(config.ClientConfig{FDControlUnixSocket: protectPath}, nil, nil)

	conn, err := c.listenUDPProtected(context.Background(), &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err == nil {
		_ = conn.Close()
		t.Fatal("expected listenUDPProtected to fail on protect failure")
	}
}
