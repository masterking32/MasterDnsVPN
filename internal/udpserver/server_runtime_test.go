package udpserver

import (
	"testing"

	"masterdnsvpn-go/internal/config"
)

func TestOpenUDPListenersRejectsInvalidUDPHost(t *testing.T) {
	for _, host := range []string{"not-an-ip", "[::]"} {
		t.Run(host, func(t *testing.T) {
			server := &Server{cfg: config.ServerConfig{UDPHost: host}}
			if _, err := server.openUDPListeners(); err == nil {
				t.Fatalf("openUDPListeners(%q) unexpectedly succeeded", host)
			}
		})
	}
}
