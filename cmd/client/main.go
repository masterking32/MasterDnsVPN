// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"masterdnsvpn-go/internal/client"
	"masterdnsvpn-go/internal/version"
)

func main() {
	configPath := flag.String("config", "client_config.toml", "Path to client configuration file")
	logPath := flag.String("log", "", "Path to log file (optional)")
	versionFlag := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("MasterDnsVPN Client Version: %s\n", version.GetVersion())
		return
	}

	resolvedConfigPath := resolveRuntimePath(*configPath)

	app, err := client.Bootstrap(resolvedConfigPath, *logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Client startup failed: %v\n", err)
		os.Exit(1)
	}

	app.PrintBanner()

	log := app.Log()
	if log != nil {
		log.Infof("\U0001F680 <green>MasterDnsVPN Client Started</green>")
		log.Infof("\U0001F4C4 <green>Configuration loaded from: <cyan>%s</cyan></green>", resolvedConfigPath)
		log.Infof("\U0001F5C2  <green>Connection Catalog: <cyan>%d</cyan> domain-resolver pairs</green>", len(app.Connections()))
	}

	// Wait for termination signal
	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := app.Run(sigCtx); err != nil {
		if log != nil {
			log.Errorf("Runtime error: %v", err)
		}
	}

	if log != nil {
		log.Infof("\U0001F6D1 <red>Shutting down...</red>")
	}
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
