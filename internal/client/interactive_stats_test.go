package client

import (
	"context"
	"os"
	"sync"
	"testing"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
)

func TestInteractiveStatsDefaultDoesNotClaimStdin(t *testing.T) {
	// A closed file keeps a regressed scanner from blocking on the test runner's stdin.
	stdin, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	stdin.Close()
	original := os.Stdin
	os.Stdin = stdin
	consoleListenerOnce = sync.Once{}
	statsHintOnce = sync.Once{}
	t.Cleanup(func() { os.Stdin = original; consoleListenerOnce = sync.Once{}; statsHintOnce = sync.Once{} })
	c := New(config.DefaultClientConfig(), logger.New("test", "error"), nil)
	c.startInteractiveConsoleListener(context.Background())
	c.printRuntimeStatsHint()
	listenerUnused, hintUnused := false, false
	consoleListenerOnce.Do(func() { listenerUnused = true })
	statsHintOnce.Do(func() { hintUnused = true })
	if !listenerUnused || !hintUnused {
		t.Fatalf("default configuration claimed console: listener=%v hint=%v", !listenerUnused, !hintUnused)
	}
}
