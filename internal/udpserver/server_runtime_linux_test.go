//go:build linux

package udpserver

import (
	"net"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
)

const dualStackTestTimeout = 2 * time.Second

func TestDefaultUDPListenerIsDualStack(t *testing.T) {
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6unspecified})
	if err != nil {
		t.Skipf("IPv6 wildcard unavailable: %v", err)
	}
	defer probe.Close()
	probeAddr := probe.LocalAddr().(*net.UDPAddr)
	probeClient, err := net.DialUDP("udp4", nil, &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: probeAddr.Port,
	})
	if err != nil {
		t.Skipf("IPv4 loopback unavailable: %v", err)
	}
	defer probeClient.Close()
	probeDeadline := time.Now().Add(dualStackTestTimeout)
	if err := probe.SetReadDeadline(probeDeadline); err != nil {
		t.Skipf("set mapped-IPv6 probe read deadline: %v", err)
	}
	if err := probeClient.SetWriteDeadline(probeDeadline); err != nil {
		t.Skipf("set mapped-IPv6 probe write deadline: %v", err)
	}
	if _, err := probeClient.Write([]byte("probe")); err != nil {
		t.Skipf("IPv4-mapped IPv6 unavailable: %v", err)
	}
	probeBuffer := make([]byte, 5)
	n, _, err := probe.ReadFromUDP(probeBuffer)
	if err != nil {
		t.Skipf("IPv4-mapped IPv6 unavailable: %v", err)
	}
	if string(probeBuffer[:n]) != "probe" {
		t.Fatalf("mapped-IPv6 probe received %q", probeBuffer[:n])
	}

	server := New(config.ServerConfig{
		UDPHost:          "",
		UDPPort:          0,
		UDPReaders:       1,
		SocketBufferSize: 64 * 1024,
	}, logger.New("Dual Stack UDP Test", "ERROR"), nil)
	conns, err := server.openUDPListeners()
	if err != nil {
		t.Fatalf("openUDPListeners failed: %v", err)
	}
	if len(conns) == 0 {
		t.Fatal("openUDPListeners returned no listeners")
	}
	listener := conns[0]
	t.Cleanup(func() { _ = listener.Close() })
	for i, conn := range conns {
		localAddr := conn.LocalAddr().(*net.UDPAddr)
		if localAddr.IP.To4() != nil {
			t.Fatalf("wildcard listener %d is IPv4-only: %s", i, localAddr)
		}
		if i != 0 {
			_ = conn.Close()
		}
	}
	localAddr := listener.LocalAddr().(*net.UDPAddr)

	tests := []struct {
		name    string
		network string
		ip      net.IP
	}{
		{name: "IPv4", network: "udp4", ip: net.IPv4(127, 0, 0, 1)},
		{name: "IPv6", network: "udp6", ip: net.IPv6loopback},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := &net.UDPAddr{IP: tt.ip, Port: localAddr.Port}
			client, err := net.DialUDP(tt.network, nil, target)
			if err != nil {
				t.Fatalf("dial %s: %v", target, err)
			}
			defer client.Close()

			deadline := time.Now().Add(dualStackTestTimeout)
			if err := listener.SetDeadline(deadline); err != nil {
				t.Fatalf("set listener deadline: %v", err)
			}
			if err := client.SetDeadline(deadline); err != nil {
				t.Fatalf("set client deadline: %v", err)
			}

			payload := []byte(tt.name)
			if _, err := client.Write(payload); err != nil {
				t.Fatalf("write to %s: %v", target, err)
			}
			buffer := make([]byte, 64)
			n, peer, err := listener.ReadFromUDP(buffer)
			if err != nil {
				t.Fatalf("read from %s: %v", target, err)
			}
			if string(buffer[:n]) != tt.name {
				t.Fatalf("listener received %q want=%q", buffer[:n], payload)
			}
			if _, err := listener.WriteToUDP(buffer[:n], peer); err != nil {
				t.Fatalf("reply to %s: %v", peer, err)
			}
			n, err = client.Read(buffer)
			if err != nil {
				t.Fatalf("read reply from %s: %v", target, err)
			}
			if string(buffer[:n]) != tt.name {
				t.Fatalf("client received %q want=%q", buffer[:n], payload)
			}
		})
	}
}

func TestExplicitIPv6WildcardUsesIPv6Socket(t *testing.T) {
	probe, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	_ = probe.Close()

	server := New(config.ServerConfig{
		UDPHost:          "::",
		UDPPort:          0,
		UDPReaders:       1,
		SocketBufferSize: 64 * 1024,
	}, logger.New("IPv6 Wildcard UDP Test", "ERROR"), nil)
	conns, err := server.openUDPListeners()
	if err != nil {
		t.Fatalf("openUDPListeners failed: %v", err)
	}
	if len(conns) == 0 {
		t.Fatal("openUDPListeners returned no listeners")
	}
	for _, conn := range conns {
		t.Cleanup(func() { _ = conn.Close() })
	}
	for i, conn := range conns {
		if localAddr := conn.LocalAddr().(*net.UDPAddr); localAddr.IP.To4() != nil {
			t.Fatalf("explicit IPv6 wildcard listener %d became IPv4-only: %s", i, localAddr)
		}
	}
}
