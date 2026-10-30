//go:build unix

package client

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
)

// startStubProtectServer accepts protect requests on a temporary Unix socket,
// answers each with status and sends one value per request on the returned
// channel. The sockprotect tests cover fd passing; this stub only shows that
// socket creation reached the server.
func startStubProtectServer(t *testing.T, status byte) (string, <-chan struct{}) {
	t.Helper()

	// /tmp keeps the path under the sun_path limit; t.TempDir() can exceed it on macOS.
	path := fmt.Sprintf("/tmp/mdv-client-protect-%d-%d.sock", os.Getpid(), time.Now().UnixNano())
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("Listen unix failed: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	served := make(chan struct{}, 4)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if _, err := conn.Read(make([]byte, 1)); err != nil {
					return
				}
				_, _ = conn.Write([]byte{status})
				served <- struct{}{}
			}()
		}
	}()
	return path, served
}

func requireServed(t *testing.T, served <-chan struct{}) {
	t.Helper()

	select {
	case <-served:
	case <-time.After(2 * time.Second):
		t.Fatal("protect server was not contacted")
	}
}

func TestDialUDPResolverUsesProtectServer(t *testing.T) {
	path, served := startStubProtectServer(t, 0x01)
	c := New(config.ClientConfig{FDControlUnixSocket: path}, nil, nil)

	conn, err := c.dialUDPResolver(context.Background(), "127.0.0.1:53")
	if err != nil {
		t.Fatalf("dialUDPResolver returned error: %v", err)
	}
	defer conn.Close()
	requireServed(t, served)
}

func TestListenUDPProtectedUsesProtectServer(t *testing.T) {
	path, served := startStubProtectServer(t, 0x01)
	c := New(config.ClientConfig{FDControlUnixSocket: path}, nil, nil)

	conn, err := c.listenUDPProtected(context.Background(), "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listenUDPProtected returned error: %v", err)
	}
	defer conn.Close()
	requireServed(t, served)
}

func TestListenUDPProtectedFailsOnProtectFailure(t *testing.T) {
	path, _ := startStubProtectServer(t, 0x00)
	c := New(config.ClientConfig{FDControlUnixSocket: path}, nil, nil)

	conn, err := c.listenUDPProtected(context.Background(), "0.0.0.0:0")
	if err == nil {
		_ = conn.Close()
		t.Fatal("expected listenUDPProtected to fail on protect failure")
	}
}
