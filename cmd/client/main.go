// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"masterdnsvpn-go/internal/client"
	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/runtimepath"
	"masterdnsvpn-go/internal/version"
)

func waitForExitInput() {
	_, _ = fmt.Fprint(os.Stderr, "Press Enter to exit...")
	reader := bufio.NewReader(os.Stdin)
	_, _ = reader.ReadString('\n')
}

func printClientUsage(fs *flag.FlagSet) {
	bin := filepath.Base(os.Args[0])
	if bin == "" || bin == "." || strings.Contains(bin, "go-build") || strings.HasPrefix(bin, "main") {
		bin = "masterdnsvpn-client"
	}

	fmt.Fprintf(fs.Output(), "MasterDnsVPN Client - A high-performance DNS-based VPN Tunnel\n\n")
	fmt.Fprintf(fs.Output(), "Usage:\n")
	fmt.Fprintf(fs.Output(), "  %s [flags]\n\n", bin)
	fmt.Fprintf(fs.Output(), "Examples:\n")
	fmt.Fprintf(fs.Output(), "  %s -config client_config.toml\n", bin)
	fmt.Fprintf(fs.Output(), "  %s -config ./client_config.toml -resolvers ./client_resolvers.txt\n", bin)
	fmt.Fprintf(fs.Output(), "  %s -log ./client.log -version\n", bin)
	fmt.Fprintf(fs.Output(), "  %s -config ./client_config.toml -d domain1.com,domain2.com -k my-secret-key\n\n", bin)
	fmt.Fprintf(fs.Output(), "Flags:\n")
	fs.PrintDefaults()
}

func main() {
	flag.CommandLine.SetOutput(os.Stdout)
	flag.Usage = func() {
		printClientUsage(flag.CommandLine)
	}

	var configPath string
	flag.StringVar(&configPath, "config", "client_config.toml", "Path to client configuration file")
	flag.StringVar(&configPath, "c", "client_config.toml", "Alias for -config")

	var logPath string
	flag.StringVar(&logPath, "log", "", "Path to log file (optional)")
	flag.StringVar(&logPath, "l", "", "Alias for -log")

	var resolversPath string
	flag.StringVar(&resolversPath, "resolvers", "", "Path to resolver file override (optional)")
	flag.StringVar(&resolversPath, "r", "", "Alias for -resolvers")

	var showVersion bool
	flag.BoolVar(&showVersion, "version", false, "Print version and exit")
	flag.BoolVar(&showVersion, "v", false, "Alias for -version")

	var showHelp bool
	flag.BoolVar(&showHelp, "help", false, "Show help and exit")
	flag.BoolVar(&showHelp, "h", false, "Alias for -help")

	domainsShort := flag.String("d", "", "Alias for -domains (comma separated)")
	keyShort := flag.String("k", "", "Alias for -encryption-key")
	
	configFlags, err := config.NewClientConfigFlagBinder(flag.CommandLine)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Client flag setup failed: %v\n", err)
		os.Exit(2)
	}
	flag.Parse()

	if showHelp {
		flag.Usage()
		return
	}

	if flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "Unexpected positional arguments: %v\n\n", flag.Args())
		flag.Usage()
		os.Exit(2)
	}

	if showVersion {
		fmt.Printf("MasterDnsVPN Client Version: %s\n", version.GetVersion())
		return
	}

	resolvedConfigPath := runtimepath.Resolve(configPath)
	overrides := configFlags.Overrides()
	if resolversPath != "" {
		resolvedResolversPath := runtimepath.Resolve(resolversPath)
		overrides.ResolversFilePath = &resolvedResolversPath
	}
	
	if *domainsShort != "" {
		overrides.Values["Domains"] = strings.Split(*domainsShort, ",")
	}
	if *keyShort != "" {
		overrides.Values["EncryptionKey"] = *keyShort
	}

	app, err := client.Bootstrap(resolvedConfigPath, logPath, overrides)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Client startup failed: %v\n", err)
		waitForExitInput()
		os.Exit(1)
	}

	app.PrintBanner()

	log := app.Log()
	if log != nil {
		log.Infof("\U0001F680 <green>MasterDnsVPN Client Started</green>")
		log.Infof("\U0001F4C4 <green>Configuration loaded from: <cyan>%s</cyan></green>", resolvedConfigPath)
		log.Infof("\U0001F5C2  <green>Connection Catalog: <cyan>%d</cyan> domain-resolver pairs</green>", app.Balancer().TotalCount())
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
