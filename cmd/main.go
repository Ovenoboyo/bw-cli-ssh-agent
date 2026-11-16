package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/Ovenoboyo/bw-cli-ssh-agent/pkg/agent"
	"github.com/Ovenoboyo/bw-cli-ssh-agent/pkg/doctor"
	"github.com/Ovenoboyo/bw-cli-ssh-agent/pkg/logging"
	"github.com/Ovenoboyo/bw-cli-ssh-agent/pkg/server"
)

func main() {
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	var defaultSock, defaultPid string
	if runtimeDir != "" {
		defaultSock = filepath.Join(runtimeDir, "bw-ssh-agent.sock")
		defaultPid = filepath.Join(runtimeDir, "bw-ssh-agent.pid")
	}

	sockPath := flag.String("socket", defaultSock, "Path to the Unix domain socket")
	pidFile := flag.String("pid-file", defaultPid, "Path to the daemon PID file")
	keyringDesc := flag.String("keyring-desc", agent.DefaultKeyringDesc, "Kernel keyring description holding BW_SESSION")
	logFile := flag.String("log-file", "", "Optional path to write logs (defaults to stderr)")
	loginAPIKey := flag.Bool("login-apikey", false, "Prompt for Bitwarden API key credentials, authenticate bw CLI once, and exit")
	refreshCache := flag.Bool("refresh-cache", false, "Signal the running bw-ssh-agent daemon to refresh its public key cache")
	doctorFlag := flag.Bool("doctor", false, "Check system dependencies, keyring, prompt tooling, and daemon status")
	flag.Parse()

	if *doctorFlag || flag.Arg(0) == "doctor" {
		opts := doctor.Options{
			SocketPath:  *sockPath,
			PidFile:     *pidFile,
			KeyringDesc: *keyringDesc,
		}
		if err := doctor.Run(os.Stdout, opts); err != nil {
			os.Exit(1)
		}
		return
	}

	logger, cleanup, err := logging.Setup(*logFile)
	if err != nil {
		slog.Error("logger initialization failed", "err", err)
		os.Exit(1)
	}
	defer cleanup()

	if *loginAPIKey {
		if err := agent.LoginWithAPIKey(); err != nil {
			logger.Error("API key login failed", "err", err)
			os.Exit(1)
		}
		logger.Info("authenticated Bitwarden CLI via API key")
		return
	}

	if *sockPath == "" || !filepath.IsAbs(*sockPath) {
		logger.Error("invalid socket path: XDG_RUNTIME_DIR is unset and --socket was not provided as an absolute path")
		os.Exit(1)
	}
	if *pidFile == "" || !filepath.IsAbs(*pidFile) {
		logger.Error("invalid pid-file path: XDG_RUNTIME_DIR is unset and --pid-file was not provided as an absolute path")
		os.Exit(1)
	}

	if *refreshCache {
		if err := server.TriggerRefresh(*pidFile); err != nil {
			logger.Error("failed to trigger cache refresh", "err", err)
			os.Exit(1)
		}
		logger.Info("sent cache refresh signal to running bw-ssh-agent")
		return
	}

	bwAgent := agent.New(*keyringDesc, logger)
	cfg := server.Config{
		SocketPath: *sockPath,
		PidFile:    *pidFile,
		Logger:     logger,
	}

	if err := server.Run(context.Background(), cfg, bwAgent); err != nil {
		logger.Error("server exited with error", "err", fmt.Errorf("%w", err))
		os.Exit(1)
	}
}
