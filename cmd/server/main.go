// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"
	UDPServer "masterdnsvpn-go/internal/udpserver"
	"masterdnsvpn-go/internal/version"
)

func main() {
	configPath := flag.String("config", "server_config.toml", "Path to server configuration file")
	logPath := flag.String("log", "", "Path to log file (optional)")
	versionFlag := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("MasterDnsVPN Server Version: %s\n", version.GetVersion())
		return
	}

	resolvedConfigPath := resolveRuntimePath(*configPath)

	cfg, err := config.LoadServerConfig(resolvedConfigPath)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Server startup failed: %v\n", err)
		os.Exit(1)
	}

	var log *logger.Logger
	if *logPath != "" {
		log = logger.NewWithFile("MasterDnsVPN Server", cfg.LogLevel, *logPath)
	} else {
		log = logger.New("MasterDnsVPN Server", cfg.LogLevel)
	}
	log.Infof("\U0001F680 <magenta>MasterDnsVPN Server starting ...</magenta>")

	keyInfo, err := security.EnsureServerEncryptionKey(cfg)
	if err != nil {
		log.Errorf("\u274C <red>Encryption Key Setup Failed</red> <magenta>|</magenta> <cyan>%v</cyan>", err)
		fmt.Print("Press Enter to exit...")
		_, _ = fmt.Scanln()
		os.Exit(1)
	}

	codec, err := security.NewCodecFromConfig(cfg, keyInfo.Key)
	if err != nil {
		log.Errorf("\u274C <red>Encryption Codec Setup Failed</red> <magenta>|</magenta> <cyan>%v</cyan>", err)
		fmt.Print("Press Enter to exit...")
		_, _ = fmt.Scanln()
		os.Exit(1)
	}

	srv := UDPServer.New(cfg, log, codec)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Infof("\U0001F680 <green>Server Configuration Loaded</green>")
	if len(cfg.Domain) > 0 {
		log.Infof(
			"\U0001F310 <green>Allowed Domains: <cyan>%s</cyan>, Min Label:<cyan>%d</cyan></green>",
			strings.Join(cfg.Domain, ", "),
			cfg.MinVPNLabelLength,
		)
	} else {
		log.Errorf("\u26A0\uFE0F <yellow>No Allowed Domains Configured!</yellow>")
		fmt.Print("Press Enter to exit...")
		_, _ = fmt.Scanln()
		os.Exit(1)
	}

	log.Infof(
		"\U0001F510 <green>Encryption Method: <cyan>%s</cyan> <gray>(id=%d)</gray></green>",
		keyInfo.MethodName,
		keyInfo.MethodID,
	)
	if cfg.UseExternalSOCKS5 {
		authMode := "OFF"
		if cfg.SOCKS5Auth {
			authMode = "ON"
		}
		log.Infof(
			"\U0001F9E6 <green>External SOCKS5 Upstream: <cyan>%s:%d</cyan> <magenta>|</magenta> Auth: <cyan>%s</cyan></green>",
			cfg.ForwardIP,
			cfg.ForwardPort,
			authMode,
		)
	}

	if keyInfo.Generated {
		log.Warnf(
			"\U0001F5DD\uFE0F <yellow>Encryption Key Generated, Path: <cyan>%s</cyan></yellow>",
			keyInfo.Path,
		)
	} else {
		log.Infof(
			"\U0001F5C2 <green>Encryption Key Loaded, Path: <cyan>%s</cyan></green>",
			keyInfo.Path,
		)
	}

	log.Infof("\U0001F511 <green>Active Encryption Key: <yellow>%s</yellow></green>", keyInfo.Key)
	log.Debugf("\u25B6\uFE0F <green>Starting UDP Server...</green>")

	if err := srv.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Errorf("\U0001F4A5 <red>Server Stopped Unexpectedly, <cyan>%v</cyan></red>", err)
		os.Exit(1)
	}

	log.Infof("\U0001F6D1 <yellow>Server Stopped</yellow>")
}

func resolveRuntimePath(path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}

	if _, err := os.Stat(path); err == nil {
		return path
	}

	exePath, err := os.Executable()
	if err != nil {
		return path
	}

	exeDir := filepath.Dir(exePath)
	candidate := filepath.Join(exeDir, path)
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}

	return path
}
