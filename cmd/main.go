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
	flag.Parse()

	logger, cleanup, err := logging.Setup(*logFile)
	if err != nil {
		slog.Error("logger initialization failed", "err", err)
		os.Exit(1)
	}
	defer cleanup()

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
