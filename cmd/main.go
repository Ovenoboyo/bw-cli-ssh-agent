package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/Ovenoboyo/bw-cli-ssh-agent/pkg/agent"
	"github.com/Ovenoboyo/bw-cli-ssh-agent/pkg/logging"
	"github.com/Ovenoboyo/bw-cli-ssh-agent/pkg/server"
)

func main() {
	defaultSock := filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "bw-ssh-agent.sock")

	sockPath := flag.String("socket", defaultSock, "Path to the Unix domain socket")
	keyringDesc := flag.String("keyring-desc", agent.DefaultKeyringDesc, "Kernel keyring description holding BW_SESSION")
	logFile := flag.String("log-file", "", "Optional path to write logs (defaults to stderr)")
	storeAPIKey := flag.Bool("store-apikey", false, "Prompt for Bitwarden API key credentials, store them in kernel keyring, and exit")
	clearAPIKey := flag.Bool("clear-apikey", false, "Remove stored Bitwarden API key credentials from kernel keyring and exit")
	flag.Parse()

	logger, cleanup, err := logging.Setup(*logFile)
	if err != nil {
		slog.Error("logger initialization failed", "err", err)
		os.Exit(1)
	}
	defer cleanup()

	if *clearAPIKey {
		removed, err := agent.ClearAPIKey()
		if err != nil {
			logger.Error("failed to clear API key", "err", err)
			os.Exit(1)
		}
		if removed == 0 {
			logger.Info("no Bitwarden API key credentials found in user kernel keyring (@u)")
		} else {
			logger.Info("cleared Bitwarden API key credentials from user kernel keyring (@u)", "removed_keys", removed)
		}
		return
	}

	if *storeAPIKey {
		if err := agent.StoreAPIKey(); err != nil {
			logger.Error("failed to store API key", "err", err)
			os.Exit(1)
		}
		logger.Info("stored Bitwarden API key credentials in user kernel keyring (@u)")
		return
	}

	bwAgent := agent.New(*keyringDesc, logger)
	cfg := server.Config{
		SocketPath: *sockPath,
		Logger:     logger,
	}

	if err := server.Run(context.Background(), cfg, bwAgent); err != nil {
		logger.Error("server exited with error", "err", err)
		os.Exit(1)
	}
}
