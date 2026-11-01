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
	"runtime"
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
	if loaded[2].IP != "192.168.10.1" || loaded[2].Port != 5300 {
		t.Errorf("expected remaining configured subnet host 192.168.10.1:5300, got %+v", loaded[2])
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

func TestResolversFileReadErrorPreservation(t *testing.T) {
	dir := t.TempDir()
	ranked := []ResolverAddress{{IP: "1.1.1.1", Port: 53}}

	// 1. Non-existent file initializes a clean file
	nonExistentPath := filepath.Join(dir, "new_resolvers.txt")
	if err := UpdateResolversFileWithRanked(nonExistentPath, ranked); err != nil {
		t.Fatalf("expected non-existent file to succeed, got %v", err)
	}
	if _, err := os.Stat(nonExistentPath); err != nil {
		t.Fatalf("expected new file to exist: %v", err)
	}

	// 2. Unreadable directory path returns error immediately without creating temporary or corrupt files
	dirPath := filepath.Join(dir, "directory_target")
	if err := os.Mkdir(dirPath, 0o755); err != nil {
		t.Fatalf("Mkdir failed: %v", err)
	}
	if err := UpdateResolversFileWithRanked(dirPath, ranked); err == nil {
		t.Fatal("expected UpdateResolversFileWithRanked to fail on directory target")
	}

	// 3. Permission denied on platforms supporting 000 chmod preserves content without overwriting
	if runtime.GOOS != "windows" {
		filePath := filepath.Join(dir, "protected_resolvers.txt")
		initialContent := "# Preserved Comments\n8.8.8.8\n"
		if err := os.WriteFile(filePath, []byte(initialContent), 0o644); err != nil {
			t.Fatalf("WriteFile failed: %v", err)
		}
		_ = os.Chmod(filePath, 0o000)
		defer os.Chmod(filePath, 0o644)

		if _, testReadErr := os.ReadFile(filePath); testReadErr == nil {
			t.Skip("skipping permission denial test: process has privileged permissions that permit reading 000 files")
		}

		err := UpdateResolversFileWithRanked(filePath, ranked)
		if err == nil {
			t.Fatal("expected UpdateResolversFileWithRanked to fail on unreadable file")
		}

		_ = os.Chmod(filePath, 0o644)
		data, err := os.ReadFile(filePath)
		if err != nil {
			t.Fatalf("ReadFile failed: %v", err)
		}
		if string(data) != initialContent {
			t.Fatalf("file content was not preserved: got=%s want=%s", string(data), initialContent)
		}
	}
}

func TestWriteRankedResolversFile_UnterminatedBlockReturnsError(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "unterminated.txt")

	// Missing footer marker
	content := AutoRankedHeaderMarker + "\n# Some ranked resolver\n8.8.8.8\n# User custom resolver\n1.2.3.4\n"
	if err := os.WriteFile(filePath, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	ranked := []ResolverAddress{{IP: "9.9.9.9", Port: 53}}
	err := UpdateResolversFileWithRanked(filePath, ranked)
	if err == nil {
		t.Fatal("expected error on unterminated managed block, got nil")
	}
	if !strings.Contains(err.Error(), "unterminated managed block") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// Verify original file is unchanged
	afterData, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(afterData) != content {
		t.Fatalf("file content was modified despite error: got=%s want=%s", string(afterData), content)
	}
}

// TestEmpirical_ResolversUnterminatedBlockFailsafe empirically tests detection of
// unterminated auto-ranked blocks across diverse adversarial corrupted/truncated inputs:
// 1. Header followed immediately by EOF.
// 2. Header with user comments and CIDRs, but truncated before footer.
// 3. Header with partial/malformed footer prefix.
// 4. Repeated/nested headers without footers.
// 5. Truncated mid-line within auto block.
// Verifies:
// - UpdateResolversFileWithRanked returns an explicit unterminated block error.
// - The configuration file on disk is strictly preserved byte-for-byte (atomic write safety).
// - No user configuration or custom resolvers/CIDRs are lost.
func TestEmpirical_ResolversUnterminatedBlockFailsafe(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{
			name:    "HeaderOnlyEOF",
			content: AutoRankedHeaderMarker + "\n",
		},
		{
			name:    "HeaderWithRankedAndNoFooter",
			content: AutoRankedHeaderMarker + "\n1.1.1.1\n8.8.8.8\n",
		},
		{
			name: "HeaderWithUserCommentsAndCIDRNoFooter",
			content: AutoRankedHeaderMarker + "\n" +
				"# Production DNS fallback\n" +
				"10.0.0.0/24:5353\n" +
				"# Important custom route\n" +
				"192.168.1.1\n",
		},
		{
			name: "PartialFooterMarkerMissingEnd",
			content: AutoRankedHeaderMarker + "\n" +
				"8.8.8.8\n" +
				"# --- END AUTO-RANKED\n",
		},
		{
			name: "PartialFooterMarkerTypo",
			content: AutoRankedHeaderMarker + "\n" +
				"8.8.8.8\n" +
				"# --- END AUTO-RANKED RESOLVER\n",
		},
		{
			name: "MultipleHeadersNoFooter",
			content: AutoRankedHeaderMarker + "\n" +
				"1.1.1.1\n" +
				AutoRankedHeaderMarker + "\n" +
				"8.8.8.8\n",
		},
		{
			name: "TruncatedMidLineInAutoBlock",
			content: AutoRankedHeaderMarker + "\n" +
				"1.1.1.1\n" +
				"8.8.",
		},
	}

	ranked := []ResolverAddress{
		{IP: "9.9.9.9", Port: 53},
		{IP: "149.112.112.112", Port: 53},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "resolvers.txt")

			if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
				t.Fatalf("WriteFile failed: %v", err)
			}

			err := UpdateResolversFileWithRanked(path, ranked)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
			if !strings.Contains(err.Error(), "unterminated managed block") {
				t.Fatalf("expected unterminated block error for %s, got: %v", tc.name, err)
			}

			// Verify file content is 100% preserved
			postBytes, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("ReadFile failed: %v", err)
			}
			if string(postBytes) != tc.content {
				t.Fatalf("file content was corrupted or overwritten on error!\nGot: %q\nWant: %q",
					string(postBytes), tc.content)
			}
		})
	}

	// Control case: properly terminated file must succeed and preserve user lines
	t.Run("ProperlyTerminatedControl", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "valid.txt")
		content := "# Header comment\n" +
			AutoRankedHeaderMarker + "\n" +
			"1.1.1.1\n" +
			AutoRankedFooterMarker + "\n" +
			"# User custom CIDR\n" +
			"10.0.0.0/24\n"

		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("WriteFile failed: %v", err)
		}

		err := UpdateResolversFileWithRanked(path, ranked)
		if err != nil {
			t.Fatalf("UpdateResolversFileWithRanked failed on properly terminated file: %v", err)
		}

		postBytes, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile failed: %v", err)
		}
		postStr := string(postBytes)

		if strings.Contains(postStr, "9.9.9.9") {
			t.Fatal("unconfigured ranked resolver must not be added")
		}
		if !strings.Contains(postStr, "# User custom CIDR") || !strings.Contains(postStr, "10.0.0.0/24") {
			t.Fatal("user custom configuration was lost!")
		}
	})
}
