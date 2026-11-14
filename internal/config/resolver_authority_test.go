package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRankedResolversRespectUserAuthority(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolvers.txt")
	content := AutoRankedHeaderMarker + "\n8.8.8.8\n1.1.1.1\n192.0.2.2:5300\n" + AutoRankedFooterMarker + "\n# user's list\n1.1.1.1:5353\n192.0.2.0/30:5300\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	want := []ResolverAddress{{"192.0.2.2", 5300}, {"1.1.1.1", 5353}, {"192.0.2.1", 5300}}
	got, _, err := LoadClientResolvers(path)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("load=%v err=%v want=%v", got, err, want)
	}
	if err := UpdateResolversFileWithRanked(path, []ResolverAddress{{"8.8.8.8", 53}, {"1.1.1.1", 53}, {"192.0.2.2", 5300}}); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block := strings.Split(string(saved), AutoRankedFooterMarker)[0]
	if strings.Contains(block, "8.8.8.8") || strings.Contains(block, "1.1.1.1") {
		t.Fatalf("stale ranking retained: %s", block)
	}
	if !strings.Contains(string(saved), "# user's list\n1.1.1.1:5353\n192.0.2.0/30:5300") {
		t.Fatal("user lines changed")
	}
	// Removing all entries must not resurrect cached rankings.
	if err := os.WriteFile(path, []byte(AutoRankedHeaderMarker+"\n8.8.8.8\n"+AutoRankedFooterMarker+"\n# all removed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, _, err := LoadClientResolvers(path); err == nil {
		t.Fatalf("removed resolvers loaded: %v", got)
	}
}

func TestRankedResolversEmptyRankingClearsBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolvers.txt")
	content := AutoRankedHeaderMarker + "\n1.1.1.1\n" + AutoRankedFooterMarker + "\n1.1.1.1\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := UpdateResolversFileWithRanked(path, nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Split(string(data), AutoRankedFooterMarker)[0], "1.1.1.1") {
		t.Fatal("stale ranking survived empty result")
	}
	got, _, err := LoadClientResolvers(path)
	if err != nil || len(got) != 1 {
		t.Fatalf("user entry lost: %v %v", got, err)
	}
}
