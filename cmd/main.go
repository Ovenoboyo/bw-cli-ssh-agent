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
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	defaultSock := filepath.Join(runtimeDir, "bw-ssh-agent.sock")
	defaultPid := filepath.Join(runtimeDir, "bw-ssh-agent.pid")

	sockPath := flag.String("socket", defaultSock, "Path to the Unix domain socket")
	pidFile := flag.String("pid-file", defaultPid, "Path to the daemon PID file")
	keyringDesc := flag.String("keyring-desc", agent.DefaultKeyringDesc, "Kernel keyring description holding BW_SESSION")
	logFile := flag.String("log-file", "", "Optional path to write logs (defaults to stderr)")
	storeAPIKey := flag.Bool("store-apikey", false, "Prompt for Bitwarden API key credentials, store them in kernel keyring, and exit")
	clearAPIKey := flag.Bool("clear-apikey", false, "Remove stored Bitwarden API key credentials from kernel keyring and exit")
	refreshCache := flag.Bool("refresh-cache", false, "Signal the running bw-ssh-agent daemon to refresh its public key cache")
	flag.Parse()

	logger, cleanup, err := logging.Setup(*logFile)
	if err != nil {
		slog.Error("logger initialization failed", "err", err)
		os.Exit(1)
	}
	defer cleanup()

	if *refreshCache {
		if err := server.TriggerRefresh(*pidFile); err != nil {
			logger.Error("failed to trigger cache refresh", "err", err)
			os.Exit(1)
		}
		logger.Info("sent cache refresh signal to running bw-ssh-agent")
		return
	}

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
		PidFile:    *pidFile,
		Logger:     logger,
	}

	if err := server.Run(context.Background(), cfg, bwAgent); err != nil {
		logger.Error("server exited with error", "err", err)
		os.Exit(1)
	}
}
