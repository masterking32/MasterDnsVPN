package main

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func testSettings(t *testing.T) settings {
	t.Helper()
	root := t.TempDir()
	s := settings{
		appDir:     filepath.Join(root, "app"),
		dataDir:    filepath.Join(root, "data"),
		configFile: "server_config.toml",
		keyFile:    "encrypt_key.txt",
		domain:     "vpn.example.com",
		template:   filepath.Join(root, "sample.toml"),
	}
	writeTestFile(t, filepath.Join(s.appDir, "masterdnsvpn"), "fake server")
	writeTestFile(t, s.template, "DOMAIN = [\"sample.example.com\"]\nDATA_ENCRYPTION_METHOD = 1\nUDP_PORT = 53\n")
	return s
}

func writeTestFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func argumentValue(args []string, flag string) string {
	var value string
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag {
			value = args[i+1]
		}
	}
	return value
}

// Stand in for the server's idempotent -genkey operation without launching an
// architecture-specific executable. The real server owns encryption policy.
func fakeGenerate(c command) error {
	keyLength := 32
	if argumentValue(c.args, "-data-encryption-method") == "3" {
		keyLength = 16
	}
	keyPath := argumentValue(c.args, "-encryption-key-file")
	key, err := os.ReadFile(keyPath)
	if err == nil && len(strings.TrimSpace(string(key))) == keyLength {
		return nil
	}
	return os.WriteFile(keyPath, []byte(strings.Repeat("a", keyLength)), 0600)
}

func TestPrepareFirstBootCreatesValidConfigAndPersistsState(t *testing.T) {
	s := testSettings(t)
	s.domain = `vpn$1&"quoted"\path.example.com`
	launch, err := prepare(s, nil, fakeGenerate)
	if err != nil {
		t.Fatal(err)
	}
	config := readTestFile(t, filepath.Join(s.dataDir, s.configFile))
	var decoded struct {
		Domain  []string `toml:"DOMAIN"`
		UDPPort int      `toml:"UDP_PORT"`
	}
	if _, err := toml.Decode(config, &decoded); err != nil {
		t.Fatalf("generated config is invalid TOML: %v", err)
	}
	if !reflect.DeepEqual(decoded.Domain, []string{s.domain}) || decoded.UDPPort != 53 {
		t.Fatalf("unexpected generated config: %#v", decoded)
	}
	if got := readTestFile(t, filepath.Join(s.appDir, s.configFile)); got != config {
		t.Fatal("persisted config differs from active config")
	}
	key := readTestFile(t, filepath.Join(s.dataDir, s.keyFile))
	if len(key) != 32 || key != readTestFile(t, filepath.Join(s.appDir, s.keyFile)) {
		t.Fatal("generated key was not persisted intact")
	}
	if launch.path != filepath.Join(s.appDir, "masterdnsvpn") || launch.dir != s.appDir {
		t.Fatalf("unexpected server executable or working directory: %#v", launch)
	}
}

func TestPrepareRestartRestoresPersistedConfigAndKeyWithoutDomain(t *testing.T) {
	s := testSettings(t)
	s.domain = ""
	s.template = filepath.Join(t.TempDir(), "unavailable-template")
	config := "DOMAIN = [\"persisted.example.com\"]\nUDP_PORT = 15353\n"
	key := strings.Repeat("b", 32)
	writeTestFile(t, filepath.Join(s.dataDir, s.configFile), config)
	writeTestFile(t, filepath.Join(s.dataDir, s.keyFile), key)
	writeTestFile(t, filepath.Join(s.appDir, s.configFile), "stale config")
	writeTestFile(t, filepath.Join(s.appDir, s.keyFile), "stale key")
	if _, err := prepare(s, nil, fakeGenerate); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{s.appDir, s.dataDir} {
		if readTestFile(t, filepath.Join(dir, s.configFile)) != config || readTestFile(t, filepath.Join(dir, s.keyFile)) != key {
			t.Fatalf("persistent state was changed or not restored in %s", dir)
		}
	}
}

func TestPrepareRepairsAndPersistsMalformedKey(t *testing.T) {
	s := testSettings(t)
	writeTestFile(t, filepath.Join(s.dataDir, s.keyFile), "bad key")
	if _, err := prepare(s, nil, fakeGenerate); err != nil {
		t.Fatal(err)
	}
	key := readTestFile(t, filepath.Join(s.dataDir, s.keyFile))
	if len(key) != 32 || key != readTestFile(t, filepath.Join(s.appDir, s.keyFile)) {
		t.Fatal("repaired key was not persisted")
	}
}

func TestPrepareCustomPathsAndFlagsReachGenerationAndRuntime(t *testing.T) {
	s := testSettings(t)
	s.appDir = filepath.Join(t.TempDir(), "custom app", "nested")
	s.dataDir = filepath.Join(t.TempDir(), "custom data", "nested")
	s.configFile = "custom config.toml"
	s.keyFile = "custom key.txt"
	s.keyFileExplicit = true
	writeTestFile(t, filepath.Join(s.appDir, "masterdnsvpn"), "fake server")
	args := []string{"-udp-port", "15353", "-data-encryption-method", "3"}
	var generated command
	launch, err := prepare(s, args, func(c command) error {
		generated = c
		return fakeGenerate(c)
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []command{generated, launch} {
		for flag, want := range map[string]string{
			"-config":                 filepath.Join(s.appDir, s.configFile),
			"-encryption-key-file":    filepath.Join(s.appDir, s.keyFile),
			"-udp-port":               "15353",
			"-data-encryption-method": "3",
		} {
			if got := argumentValue(c.args, flag); got != want {
				t.Errorf("%s: got %q, want %q", flag, got, want)
			}
		}
	}
	if generated.args[len(generated.args)-1] != "-genkey" {
		t.Fatal("generation command does not request key generation")
	}
	for _, arg := range launch.args {
		if arg == "-genkey" {
			t.Fatal("generation-only flag leaked into runtime command")
		}
	}
	if len(readTestFile(t, filepath.Join(s.dataDir, s.keyFile))) != 16 {
		t.Fatal("custom encryption-mode key was not persisted")
	}
	if _, err := os.Stat(filepath.Join(s.dataDir, s.configFile)); err != nil {
		t.Fatalf("custom config was not persisted: %v", err)
	}
}

func TestPrepareKeyPathPrecedencePreservesExistingKeys(t *testing.T) {
	for _, source := range []string{"config", "environment", "command line"} {
		t.Run(source, func(t *testing.T) {
			s := testSettings(t)
			s.domain = ""
			s.configFile = filepath.Join("settings", "server.toml")
			writeTestFile(t, filepath.Join(s.dataDir, s.configFile), "DOMAIN = [\"saved.example.com\"]\nENCRYPTION_KEY_FILE = \"keys/config.key\"\n")
			relativeKey := filepath.Join("settings", "keys", "config.key")
			var args []string
			if source != "config" {
				s.keyFile = filepath.Join("environment", "custom.key")
				s.keyFileExplicit = true
				relativeKey = s.keyFile
			}
			if source == "command line" {
				args = []string{"--encryption-key-file=keys/command.key"}
				relativeKey = filepath.Join("settings", "keys", "command.key")
			}
			key := strings.Repeat("c", 32)
			writeTestFile(t, filepath.Join(s.dataDir, relativeKey), key)
			launch, err := prepare(s, args, fakeGenerate)
			if err != nil {
				t.Fatal(err)
			}
			activeKey := filepath.Join(s.appDir, relativeKey)
			if got := argumentValue(launch.args, "-encryption-key-file"); got != activeKey {
				t.Fatalf("runtime key path: got %q, want %q", got, activeKey)
			}
			if readTestFile(t, activeKey) != key || readTestFile(t, filepath.Join(s.dataDir, relativeKey)) != key {
				t.Fatal("existing custom encryption key was changed")
			}
		})
	}
}

func TestPrepareConfigFlagSelectsFilesForRestoreAndPersistence(t *testing.T) {
	s := testSettings(t)
	s.domain = ""
	configName := filepath.Join("selected", "server.toml")
	config := "DOMAIN = [\"selected.example.com\"]\nENCRYPTION_KEY_FILE = \"selected.key\"\n"
	writeTestFile(t, filepath.Join(s.dataDir, configName), config)
	args := []string{"-config", "superseded.toml", "--config=selected/server.toml", "-udp-port", "15353"}
	var generated command
	launch, err := prepare(s, args, func(c command) error {
		generated = c
		return fakeGenerate(c)
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []command{generated, launch} {
		if got := argumentValue(c.args, "-config"); got != filepath.Join(s.appDir, configName) {
			t.Fatalf("incorrect effective config path: %q", got)
		}
		if got := argumentValue(c.args, "-encryption-key-file"); got != filepath.Join(s.appDir, "selected", "selected.key") {
			t.Fatalf("incorrect key path for selected config: %q", got)
		}
	}
	if readTestFile(t, filepath.Join(s.dataDir, configName)) != config {
		t.Fatal("selected persisted config was modified")
	}
	if len(readTestFile(t, filepath.Join(s.dataDir, "selected", "selected.key"))) != 32 {
		t.Fatal("selected config's key was not persisted")
	}
	if _, err := os.Stat(filepath.Join(s.appDir, s.configFile)); !os.IsNotExist(err) {
		t.Fatalf("default config unexpectedly created: %v", err)
	}
}

func TestPrepareConfigInsideDataDirectoryPersistsInPlace(t *testing.T) {
	s := testSettings(t)
	s.domain = ""
	configPath := filepath.Join(s.dataDir, "mounted", "server.toml")
	keyPath := filepath.Join(s.dataDir, "mounted", "server.key")
	writeTestFile(t, configPath, "DOMAIN = [\"mounted.example.com\"]\nENCRYPTION_KEY_FILE = \"server.key\"\n")
	key := strings.Repeat("d", 32)
	writeTestFile(t, keyPath, key)
	launch, err := prepare(s, []string{"-config", configPath}, fakeGenerate)
	if err != nil {
		t.Fatal(err)
	}
	if argumentValue(launch.args, "-config") != configPath || argumentValue(launch.args, "-encryption-key-file") != keyPath {
		t.Fatalf("mounted paths were not retained: %#v", launch.args)
	}
	if readTestFile(t, keyPath) != key {
		t.Fatal("mounted encryption key was modified")
	}
}

func TestEnvironmentSettingsDistinguishesExplicitKeyFile(t *testing.T) {
	t.Setenv("KEY_FILE", "")
	if s := environmentSettings(); s.keyFileExplicit || s.keyFile != "encrypt_key.txt" {
		t.Fatalf("empty KEY_FILE should use implicit fallback: %#v", s)
	}
	t.Setenv("KEY_FILE", "encrypt_key.txt")
	if s := environmentSettings(); !s.keyFileExplicit {
		t.Fatal("an explicitly provided default key name must still take precedence")
	}
}

func TestPrepareGenerationFlagPrecedesArgumentTerminator(t *testing.T) {
	s := testSettings(t)
	launch, err := prepare(s, []string{"-udp-port", "15353", "-genkey=false", "--"}, func(c command) error {
		generating := false
		for _, arg := range c.args {
			if arg == "-genkey" {
				generating = true
			}
			if arg == "-genkey=false" {
				generating = false
			}
			if arg == "--" {
				break
			}
		}
		if !generating {
			t.Fatal("key generation would start the long-running server")
		}
		return fakeGenerate(c)
	})
	if err != nil {
		t.Fatal(err)
	}
	if launch.args[len(launch.args)-1] != "--" {
		t.Fatal("runtime argument terminator was changed")
	}
}

func TestPrepareJSONFileAliasesSelectConfigAndKey(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		file string
	}{
		{"primary wins", []string{"-json", "json/primary.json", "-j", "json/alias.json"}, "primary"},
		{"alias", []string{"--j=json/alias.json"}, "alias"},
		{"empty primary uses alias", []string{"-j", "json/alias.json", "--json="}, "alias"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := testSettings(t)
			s.domain = ""
			for _, file := range []string{"primary", "alias"} {
				config := `{"DOMAIN":["saved.example.com"],"ENCRYPTION_KEY_FILE":"keys/` + file + `.key"}`
				writeTestFile(t, filepath.Join(s.dataDir, "json", file+".json"), config)
			}
			launch, err := prepare(s, append([]string{"-config", "unused.toml"}, tt.args...), fakeGenerate)
			if err != nil {
				t.Fatal(err)
			}
			wantConfig := filepath.Join(s.appDir, "json", tt.file+".json")
			wantKey := filepath.Join(s.appDir, "json", "keys", tt.file+".key")
			if argumentValue(launch.args, "-config") != wantConfig || argumentValue(launch.args, "-encryption-key-file") != wantKey {
				t.Fatalf("JSON source and key were not selected together: %#v", launch.args)
			}
			if len(readTestFile(t, filepath.Join(s.dataDir, "json", "keys", tt.file+".key"))) != 32 {
				t.Fatal("JSON config's encryption key was not persisted")
			}
		})
	}
}

func TestPrepareBase64ConfigOverridesPersistedJSONAndSurvivesRestart(t *testing.T) {
	document := `{"DOMAIN":["incoming.example.com"],"ENCRYPTION_KEY_FILE":"keys/encoded.key"}`
	encoded := base64.StdEncoding.EncodeToString([]byte(document))
	for _, args := range [][]string{
		{"-json_base64", encoded, "-json-base64", "ignored-invalid-alias"},
		{"--json-base64=" + encoded},
	} {
		t.Run(args[0], func(t *testing.T) {
			s := testSettings(t)
			s.domain = ""
			writeTestFile(t, filepath.Join(s.dataDir, "server_config.json"), `{"DOMAIN":["stale.example.com"],"ENCRYPTION_KEY_FILE":"stale.key"}`)
			launch, err := prepare(s, args, fakeGenerate)
			if err != nil {
				t.Fatal(err)
			}
			if argumentValue(launch.args, "-config") != filepath.Join(s.appDir, "server_config.json") {
				t.Fatalf("base64 config was not canonicalized: %#v", launch.args)
			}
			if readTestFile(t, filepath.Join(s.dataDir, "server_config.json")) != document {
				t.Fatal("incoming base64 config did not replace persisted JSON")
			}
			keyPath := filepath.Join(s.dataDir, "keys", "encoded.key")
			key := readTestFile(t, keyPath)
			if len(key) != 32 {
				t.Fatal("base64 config key was not persisted")
			}
			// Simulate a replacement container with only the data volume left.
			s.appDir = filepath.Join(t.TempDir(), "replacement-app")
			s.template = filepath.Join(t.TempDir(), "unavailable-template")
			writeTestFile(t, filepath.Join(s.appDir, "masterdnsvpn"), "fake server")
			restarted, err := prepare(s, nil, fakeGenerate)
			if err != nil {
				t.Fatal(err)
			}
			if argumentValue(restarted.args, "-config") != filepath.Join(s.appDir, "server_config.json") || readTestFile(t, keyPath) != key {
				t.Fatal("restart failed to restore JSON config and original key")
			}
		})
	}
}

func TestPrepareConflictingJSONSourcesFailBeforeStateWrites(t *testing.T) {
	s := testSettings(t)
	_, err := prepare(s, []string{"-j", "config.json", "-json-base64", "e30="}, func(command) error {
		t.Fatal("server invoked despite conflicting configuration sources")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "only one of -json and -json_base64") {
		t.Fatalf("conflicting sources were accepted: %v", err)
	}
	if _, err := os.Stat(s.dataDir); !os.IsNotExist(err) {
		t.Fatalf("data directory modified before source validation: %v", err)
	}
}

func TestPrepareJSONKeyLookupMatchesServerCaseSensitivity(t *testing.T) {
	s := testSettings(t)
	s.domain = ""
	writeTestFile(t, filepath.Join(s.dataDir, "server_config.json"), `{"DOMAIN":["saved.example.com"],"encryption_key_file":"ignored.key"}`)
	launch, err := prepare(s, nil, fakeGenerate)
	if err != nil {
		t.Fatal(err)
	}
	if got := argumentValue(launch.args, "-encryption-key-file"); got != filepath.Join(s.appDir, "encrypt_key.txt") {
		t.Fatalf("launcher honored a JSON key the server ignores: %q", got)
	}
}

func TestPrepareReportsStartupFailures(t *testing.T) {
	tests := []struct {
		name   string
		change func(*testing.T, *settings)
		want   string
	}{
		{"missing domain", func(t *testing.T, s *settings) { s.domain = "" }, "DOMAIN env is required"},
		{"missing binary", func(t *testing.T, s *settings) {
			if err := os.Remove(filepath.Join(s.appDir, "masterdnsvpn")); err != nil {
				t.Fatal(err)
			}
		}, "server binary is missing"},
		{"missing template", func(t *testing.T, s *settings) {
			s.template = filepath.Join(t.TempDir(), "missing.toml")
		}, "read bundled configuration"},
		{"invalid template", func(t *testing.T, s *settings) {
			writeTestFile(t, s.template, "UDP_PORT = 53\n")
		}, "bundled configuration has no DOMAIN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := testSettings(t)
			tt.change(t, &s)
			called := false
			_, err := prepare(s, nil, func(command) error { called = true; return nil })
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got error %v, want %q", err, tt.want)
			}
			if called {
				t.Fatal("server was invoked despite invalid startup inputs")
			}
		})
	}

	t.Run("key generation", func(t *testing.T) {
		s := testSettings(t)
		failure := errors.New("server rejected config")
		_, err := prepare(s, nil, func(command) error { return failure })
		if !errors.Is(err, failure) {
			t.Fatalf("generation failure was lost: %v", err)
		}
	})

	t.Run("persistence", func(t *testing.T) {
		s := testSettings(t)
		_, err := prepare(s, nil, func(c command) error {
			if err := fakeGenerate(c); err != nil {
				return err
			}
			// Introduce a destination failure after restore, independent of OS
			// permissions (which behave differently on Windows and as root).
			return os.Mkdir(filepath.Join(s.dataDir, s.keyFile), 0755)
		})
		if err == nil || !strings.Contains(err.Error(), "persist "+s.keyFile) {
			t.Fatalf("persistence failure was ignored: %v", err)
		}
	})
}
