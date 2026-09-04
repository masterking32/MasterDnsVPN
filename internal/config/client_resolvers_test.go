// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadClientResolversSupportsIPCIDRAndPort(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client_resolvers.txt")

	content := `
8.8.8.8
1.1.1.1:5353
192.168.10.0/30:5300
[2001:db8::1]:5400
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	resolvers, resolverMap, err := LoadClientResolvers(path)
	if err != nil {
		t.Fatalf("LoadClientResolvers returned error: %v", err)
	}

	if len(resolvers) != 5 {
		t.Fatalf("unexpected resolver count: got=%d want=%d", len(resolvers), 5)
	}
	if resolverMap["8.8.8.8"] != 53 {
		t.Fatalf("unexpected default port: got=%d want=%d", resolverMap["8.8.8.8"], 53)
	}
	if resolverMap["1.1.1.1"] != 5353 {
		t.Fatalf("unexpected custom port: got=%d want=%d", resolverMap["1.1.1.1"], 5353)
	}
	if resolverMap["192.168.10.1"] != 5300 || resolverMap["192.168.10.2"] != 5300 {
		t.Fatalf("unexpected cidr expansion map: %+v", resolverMap)
	}
	if resolverMap["2001:db8::1"] != 5400 {
		t.Fatalf("unexpected IPv6 port: got=%d want=%d", resolverMap["2001:db8::1"], 5400)
	}
}

func TestLoadClientResolversRejectsHugeCIDR(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client_resolvers.txt")

	if err := os.WriteFile(path, []byte("10.0.0.0/8\n"), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if _, _, err := LoadClientResolvers(path); err == nil {
		t.Fatal("LoadClientResolvers should still fail when no valid resolvers remain")
	}
}

func TestLoadClientResolversDropsDuplicateIPsEvenWithDifferentPorts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client_resolvers.txt")

	content := `
8.8.8.8:53
8.8.8.8:5353
8.8.8.8:53
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	resolvers, resolverMap, err := LoadClientResolvers(path)
	if err != nil {
		t.Fatalf("LoadClientResolvers returned error: %v", err)
	}

	if len(resolvers) != 1 {
		t.Fatalf("unexpected resolver count: got=%d want=%d", len(resolvers), 1)
	}
	if resolvers[0].IP != "8.8.8.8" || resolvers[0].Port != 53 {
		t.Fatalf("unexpected resolver entry: %+v", resolvers[0])
	}
	if resolverMap["8.8.8.8"] != 53 {
		t.Fatalf("unexpected resolver map port: got=%d want=%d", resolverMap["8.8.8.8"], 53)
	}
}

func TestLoadClientResolversSkipsInvalidEntriesAndKeepsValidOnes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client_resolvers.txt")

	content := `
bad ip
8.8.8.8
10.0.0.0/8
1.1.1.1:5353
8.8.8.8:9999
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	resolvers, resolverMap, err := LoadClientResolvers(path)
	if err != nil {
		t.Fatalf("LoadClientResolvers returned error: %v", err)
	}

	if len(resolvers) != 2 {
		t.Fatalf("unexpected resolver count: got=%d want=%d", len(resolvers), 2)
	}
	if resolverMap["8.8.8.8"] != 53 {
		t.Fatalf("unexpected port for 8.8.8.8: got=%d want=%d", resolverMap["8.8.8.8"], 53)
	}
	if resolverMap["1.1.1.1"] != 5353 {
		t.Fatalf("unexpected port for 1.1.1.1: got=%d want=%d", resolverMap["1.1.1.1"], 5353)
	}
}

func TestLoadClientResolversPreservesFileLineOrder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client_resolvers.txt")

	content := `
# Best resolver first
9.9.9.9
1.1.1.1:5353
8.8.8.8
192.168.1.100
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	resolvers, _, err := LoadClientResolvers(path)
	if err != nil {
		t.Fatalf("LoadClientResolvers failed: %v", err)
	}

	if len(resolvers) != 4 {
		t.Fatalf("unexpected count: %d", len(resolvers))
	}
	expectedOrder := []string{"9.9.9.9", "1.1.1.1", "8.8.8.8", "192.168.1.100"}
	for i, exp := range expectedOrder {
		if resolvers[i].IP != exp {
			t.Errorf("position %d: got %s, want %s", i, resolvers[i].IP, exp)
		}
	}
}

func TestUpdateResolversFileWithRankedPreservesCommentsAndSubnets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client_resolvers.txt")

	initialContent := `# Custom user comments
# Cloudflare
1.1.1.1

# Home LAN Subnet
192.168.10.0/30:5300
`
	if err := os.WriteFile(path, []byte(initialContent), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	ranked := []ResolverAddress{
		{IP: "192.168.10.2", Port: 5300},
		{IP: "1.1.1.1", Port: 53},
		{IP: "8.8.8.8", Port: 53},
	}

	if err := UpdateResolversFileWithRanked(path, ranked); err != nil {
		t.Fatalf("UpdateResolversFileWithRanked failed: %v", err)
	}

	// 1. Check file content contains markers and user lines
	updatedBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	updatedStr := string(updatedBytes)

	if !strings.Contains(updatedStr, AutoRankedHeaderMarker) {
		t.Error("missing AutoRankedHeaderMarker")
	}
	if !strings.Contains(updatedStr, AutoRankedFooterMarker) {
		t.Error("missing AutoRankedFooterMarker")
	}
	if !strings.Contains(updatedStr, "# Custom user comments") {
		t.Error("user comment was lost")
	}
	if !strings.Contains(updatedStr, "192.168.10.0/30:5300") {
		t.Error("user subnet was lost")
	}

	// 2. Test that loading the file puts ranked resolvers first and deduplicates
	loaded, _, err := LoadClientResolvers(path)
	if err != nil {
		t.Fatalf("LoadClientResolvers failed on updated file: %v", err)
	}

	if len(loaded) < 3 {
		t.Fatalf("expected at least 3 resolvers, got %d", len(loaded))
	}
	if loaded[0].IP != "192.168.10.2" || loaded[0].Port != 5300 {
		t.Errorf("expected 1st resolver to be 192.168.10.2:5300, got %+v", loaded[0])
	}
	if loaded[1].IP != "1.1.1.1" || loaded[1].Port != 53 {
		t.Errorf("expected 2nd resolver to be 1.1.1.1:53, got %+v", loaded[1])
	}
	if loaded[2].IP != "8.8.8.8" || loaded[2].Port != 53 {
		t.Errorf("expected 3rd resolver to be 8.8.8.8:53, got %+v", loaded[2])
	}

	// 3. Test updating again replaces the existing block rather than duplicating it
	newRanked := []ResolverAddress{
		{IP: "8.8.8.8", Port: 53},
		{IP: "9.9.9.9", Port: 53},
	}
	if err := UpdateResolversFileWithRanked(path, newRanked); err != nil {
		t.Fatalf("second UpdateResolversFileWithRanked failed: %v", err)
	}

	reUpdatedBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	reUpdatedStr := string(reUpdatedBytes)

	// Ensure header marker appears exactly once
	if strings.Count(reUpdatedStr, AutoRankedHeaderMarker) != 1 {
		t.Errorf("expected exactly 1 header marker, got %d", strings.Count(reUpdatedStr, AutoRankedHeaderMarker))
	}
	if strings.Count(reUpdatedStr, AutoRankedFooterMarker) != 1 {
		t.Errorf("expected exactly 1 footer marker, got %d", strings.Count(reUpdatedStr, AutoRankedFooterMarker))
	}
}

func TestFormatResolverAddressForFile(t *testing.T) {
	tests := []struct {
		addr ResolverAddress
		want string
	}{
		{ResolverAddress{IP: "8.8.8.8", Port: 53}, "8.8.8.8"},
		{ResolverAddress{IP: "8.8.8.8", Port: 0}, "8.8.8.8"},
		{ResolverAddress{IP: "1.1.1.1", Port: 5353}, "1.1.1.1:5353"},
		{ResolverAddress{IP: "2001:4860:4860::8888", Port: 53}, "[2001:4860:4860::8888]:53"},
		{ResolverAddress{IP: "2001:4860:4860::8888", Port: 5300}, "[2001:4860:4860::8888]:5300"},
	}

	for _, tc := range tests {
		got := FormatResolverAddressForFile(tc.addr)
		if got != tc.want {
			t.Errorf("FormatResolverAddressForFile(%+v) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}

