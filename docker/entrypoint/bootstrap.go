package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

type settings struct {
	appDir, dataDir, configFile, keyFile, domain, template string
	keyFileExplicit                                        bool
}

type command struct {
	path, dir string
	args      []string
}

func environmentSettings() settings {
	value := func(name, fallback string) string {
		if s := os.Getenv(name); s != "" {
			return s
		}
		return fallback
	}
	return settings{
		appDir:          value("APP_DIR", "/opt/masterdnsvpn"),
		dataDir:         value("DATA_DIR", "/data"),
		configFile:      value("CONFIG_FILE", "server_config.toml"),
		keyFile:         value("KEY_FILE", "encrypt_key.txt"),
		keyFileExplicit: os.Getenv("KEY_FILE") != "",
		domain:          strings.TrimSpace(os.Getenv("DOMAIN")),
		template:        "/usr/share/masterdnsvpn/server_config.toml.simple",
	}
}

// prepare restores persistent state and uses the server itself to validate or
// generate the encryption key, keeping all encryption modes consistent.
func prepare(s settings, args []string, generate func(command) error) (command, error) {
	overrides, args, err := pathOverrides(args)
	if err != nil {
		return command{}, err
	}
	jsonFile := overrides.jsonFile
	if jsonFile == "" {
		jsonFile = overrides.jsonShort
	}
	encoded := overrides.jsonBase64
	if encoded == "" {
		encoded = overrides.jsonBase64Alias
	}
	if jsonFile != "" && encoded != "" {
		return command{}, fmt.Errorf("only one of -json and -json_base64 can be used")
	}
	var incomingJSON []byte
	if encoded != "" {
		incomingJSON, err = base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
		if err != nil {
			return command{}, fmt.Errorf("decode JSON base64 configuration: %w", err)
		}
		var document map[string]json.RawMessage
		if err := json.Unmarshal(incomingJSON, &document); err != nil {
			return command{}, fmt.Errorf("decode JSON configuration: %w", err)
		}
	}
	if s.appDir, err = filepath.Abs(s.appDir); err != nil {
		return command{}, err
	}
	if s.dataDir, err = filepath.Abs(s.dataDir); err != nil {
		return command{}, err
	}
	for _, dir := range []string{s.appDir, s.dataDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return command{}, err
		}
	}
	bin := filepath.Join(s.appDir, "masterdnsvpn")
	if info, err := os.Stat(bin); err != nil || !info.Mode().IsRegular() {
		return command{}, fmt.Errorf("server binary is missing or not a regular file: %s", bin)
	}
	configName := s.configFile
	if overrides.config != "" {
		configName = overrides.config
	}
	if jsonFile != "" {
		configName = jsonFile
	}
	if encoded != "" {
		// Base64 configs resolve relative keys against the working directory.
		// Store the decoded file there, independent of any -config override.
		configName = jsonFallbackPath(filepath.Base(s.configFile))
	}
	configPath := resolvePath(s.appDir, configName)
	persistedConfig := persistentPath(s, configPath)
	if encoded != "" {
		// Explicit incoming configuration must win over older persisted JSON.
		if err := os.WriteFile(configPath, incomingJSON, 0600); err != nil {
			return command{}, err
		}
	} else {
		// Match the server's TOML-to-JSON fallback, including persisted files
		// which are not yet present in this container's application directory.
		for _, candidate := range []string{configPath, jsonFallbackPath(configPath)} {
			persisted := persistentPath(s, candidate)
			if err := copyFile(persisted, candidate, 0644); err != nil && !os.IsNotExist(err) {
				return command{}, fmt.Errorf("restore configuration: %w", err)
			}
			if _, err := os.Stat(candidate); err == nil {
				configPath, persistedConfig = candidate, persisted
				break
			} else if !os.IsNotExist(err) {
				return command{}, err
			}
		}
	}
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if s.domain == "" {
			return command{}, fmt.Errorf("DOMAIN env is required when %s does not exist", persistedConfig)
		}
		sample, err := os.ReadFile(s.template)
		if err != nil {
			return command{}, fmt.Errorf("read bundled configuration: %w", err)
		}
		pattern := regexp.MustCompile(`(?m)^DOMAIN[\t ]*=.*$`)
		if !pattern.Match(sample) {
			return command{}, fmt.Errorf("bundled configuration has no DOMAIN setting")
		}
		// JSON string escaping is valid for these TOML basic strings. A function
		// replacement keeps dollar signs in a domain from becoming substitutions.
		domains, err := json.Marshal([]string{s.domain})
		if err != nil {
			return command{}, err
		}
		sample = pattern.ReplaceAllFunc(sample, func([]byte) []byte {
			return append([]byte("DOMAIN = "), domains...)
		})
		if strings.EqualFold(filepath.Ext(configPath), ".json") {
			var document map[string]any
			if _, err := toml.Decode(string(sample), &document); err != nil {
				return command{}, fmt.Errorf("read bundled configuration: %w", err)
			}
			sample, err = json.Marshal(document)
			if err != nil {
				return command{}, err
			}
		}
		if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
			return command{}, err
		}
		if err := os.WriteFile(configPath, sample, 0644); err != nil {
			return command{}, err
		}
	} else if err != nil {
		return command{}, err
	}
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return command{}, err
	}
	var keyConfig struct {
		File string `toml:"ENCRYPTION_KEY_FILE" json:"ENCRYPTION_KEY_FILE"`
	}
	if strings.EqualFold(filepath.Ext(configPath), ".json") {
		var document map[string]json.RawMessage
		err = json.Unmarshal(configData, &document)
		if err == nil {
			if value, ok := document["ENCRYPTION_KEY_FILE"]; ok {
				err = json.Unmarshal(value, &keyConfig.File)
			}
		}
	} else {
		_, err = toml.Decode(string(configData), &keyConfig)
	}
	if err != nil {
		return command{}, fmt.Errorf("read encryption key path from configuration: %w", err)
	}
	keyName := keyConfig.File
	if keyName == "" {
		keyName = "encrypt_key.txt"
	}
	keyPath := resolvePath(filepath.Dir(configPath), keyName)
	if s.keyFileExplicit {
		keyPath = resolvePath(s.appDir, s.keyFile)
	}
	if overrides.key != "" {
		keyPath = resolvePath(filepath.Dir(configPath), overrides.key)
	}
	persistedKey := persistentPath(s, keyPath)
	if err := copyFile(persistedKey, keyPath, 0600); err != nil && !os.IsNotExist(err) {
		return command{}, fmt.Errorf("restore encryption key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0755); err != nil {
		return command{}, err
	}

	launch := command{
		path: bin,
		dir:  s.appDir,
		args: append([]string{"-nowait", "-config", configPath, "-encryption-key-file", keyPath}, args...),
	}
	keygen := launch
	keygen.args = append([]string(nil), launch.args...)
	insertAt := len(keygen.args)
	for i, arg := range keygen.args {
		if arg == "--" {
			insertAt = i
			break
		}
	}
	keygen.args = append(keygen.args[:insertAt], append([]string{"-genkey"}, keygen.args[insertAt:]...)...)
	if err := generate(keygen); err != nil {
		return command{}, fmt.Errorf("initialize server encryption key: %w", err)
	}
	for _, file := range []struct {
		active, persistent string
		mode               os.FileMode
	}{{configPath, persistedConfig, 0644}, {keyPath, persistedKey, 0600}} {
		if err := copyFile(file.active, file.persistent, file.mode); err != nil {
			return command{}, fmt.Errorf("persist %s: %w", filepath.Base(file.active), err)
		}
	}
	return launch, nil
}

func resolvePath(dir, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Join(dir, path)
}

func persistentPath(s settings, active string) string {
	for _, dir := range []string{s.dataDir, s.appDir} {
		rel, err := filepath.Rel(dir, active)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return filepath.Join(s.dataDir, rel)
		}
	}
	return filepath.Join(s.dataDir, filepath.Base(active))
}

func jsonFallbackPath(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".toml":
		return strings.TrimSuffix(path, filepath.Ext(path)) + ".json"
	case ".json":
		return path
	default:
		return path + ".json"
	}
}

type configOverrides struct {
	config, key, jsonFile, jsonShort, jsonBase64, jsonBase64Alias string
}

// Canonicalize path flags once so generation, persistence and the running
// server all use the same files. The remaining server options retain order.
func pathOverrides(args []string) (overrides configOverrides, remaining []string, err error) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			remaining = append(remaining, args[i:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") {
			remaining = append(remaining, arg)
			continue
		}
		name, value, hasValue := strings.Cut(arg, "=")
		name = strings.TrimPrefix(strings.TrimPrefix(name, "-"), "-")
		switch name {
		case "config", "encryption-key-file", "json", "j", "json_base64", "json-base64":
			if !hasValue {
				i++
				if i == len(args) {
					return overrides, nil, fmt.Errorf("-%s requires a value", name)
				}
				value = args[i]
			}
			if value == "" && (name == "config" || name == "encryption-key-file") {
				return overrides, nil, fmt.Errorf("-%s requires a nonempty path", name)
			}
			switch name {
			case "config":
				overrides.config = value
			case "encryption-key-file":
				overrides.key = value
			case "json":
				overrides.jsonFile = value
			case "j":
				overrides.jsonShort = value
			case "json_base64":
				overrides.jsonBase64 = value
			case "json-base64":
				overrides.jsonBase64Alias = value
			}
		default:
			remaining = append(remaining, arg)
		}
	}
	return overrides, remaining, nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	if source, err := os.Stat(src); err == nil {
		if target, err := os.Stat(dst); err == nil && os.SameFile(source, target) {
			return nil
		}
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	return os.WriteFile(dst, data, mode)
}
