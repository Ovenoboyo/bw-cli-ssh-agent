package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/Ovenoboyo/bw-cli-ssh-agent/pkg/agent"
	"github.com/Ovenoboyo/bw-cli-ssh-agent/pkg/config"
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
	defaultCfg, _ := config.DefaultPath()

	sockPath := flag.String("socket", defaultSock, "Path to the Unix domain socket")
	pidFile := flag.String("pid-file", defaultPid, "Path to the daemon PID file")
	cfgPath := flag.String("config", defaultCfg, "Path to the JSON configuration file")
	secretKey := flag.String("secret-key", agent.DefaultSecretKey, "Secret identifier holding BW_SESSION")
	logFile := flag.String("log-file", "", "Optional path to write logs (defaults to stderr)")

	// One-shot actions & configuration mutators
	loginAPIKey := flag.Bool("login-apikey", false, "Prompt for Bitwarden API key credentials, authenticate bw CLI once, and exit")
	storeMasterPw := flag.Bool("store-master-password", false, "Enable store_master_password in config, store master password in keyring, and exit")
	clearMasterPw := flag.Bool("clear-master-password", false, "Disable store_master_password in config, remove stored master password, and exit")
	enablePolkitUnlock := flag.Bool("polkit-on-unlock", false, "Set require_polkit_on_unlock=true in config and exit")
	disablePolkitUnlock := flag.Bool("no-polkit-on-unlock", false, "Set require_polkit_on_unlock=false in config and exit")
	enableForwarding := flag.Bool("allow-forwarding", false, "Set allow_agent_forwarding=true in config and exit")
	disableForwarding := flag.Bool("no-allow-forwarding", false, "Set allow_agent_forwarding=false in config and exit")
	polkitCacheTTL := flag.Int("polkit-cache-ttl", -1, "Set polkit_cache_ttl_seconds in config (0 to disable caching) and exit")
	showConfig := flag.Bool("show-config", false, "Print the active configuration file path and JSON settings, then exit")
	refreshCache := flag.Bool("refresh-cache", false, "Signal the running bw-ssh-agent daemon to refresh its public key cache")
	doctorFlag := flag.Bool("doctor", false, "Check system dependencies, secret storage, prompt tooling, and daemon status")
	flag.Parse()

	appCfg, err := config.Load(*cfgPath)
	if err != nil {
		slog.Error("failed to load config", "path", *cfgPath, "err", err)
		os.Exit(1)
	}
	if *cfgPath != "" {
		if _, statErr := os.Stat(*cfgPath); os.IsNotExist(statErr) {
			_ = config.Save(*cfgPath, appCfg)
		}
	}

	if *doctorFlag || flag.Arg(0) == "doctor" {
		opts := doctor.Options{
			SocketPath:            *sockPath,
			PidFile:               *pidFile,
			ConfigPath:            *cfgPath,
			SecretKey:             *secretKey,
			StoreMasterPassword:   appCfg.StoreMasterPassword,
			RequirePolkitOnUnlock: appCfg.RequirePolkitOnUnlock,
			AllowAgentForwarding:  appCfg.AllowAgentForwarding,
			PolkitCacheTTLSeconds: appCfg.PolkitCacheTTLSeconds,
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

	if *enablePolkitUnlock && *disablePolkitUnlock {
		logger.Error("cannot pass both --polkit-on-unlock and --no-polkit-on-unlock")
		os.Exit(1)
	}
	if *enableForwarding && *disableForwarding {
		logger.Error("cannot pass both --allow-forwarding and --no-allow-forwarding")
		os.Exit(1)
	}

	configMutated := false
	if *enablePolkitUnlock {
		appCfg.RequirePolkitOnUnlock = true
		configMutated = true
	}
	if *disablePolkitUnlock {
		appCfg.RequirePolkitOnUnlock = false
		configMutated = true
	}
	if *enableForwarding {
		appCfg.AllowAgentForwarding = true
		configMutated = true
	}
	if *disableForwarding {
		appCfg.AllowAgentForwarding = false
		configMutated = true
	}
	if *polkitCacheTTL >= 0 {
		appCfg.PolkitCacheTTLSeconds = *polkitCacheTTL
		configMutated = true
	}

	if configMutated {
		if *cfgPath == "" {
			logger.Error("cannot save config: --config path is empty")
			os.Exit(1)
		}
		if err := config.Save(*cfgPath, appCfg); err != nil {
			logger.Error("failed to save config", "path", *cfgPath, "err", err)
			os.Exit(1)
		}
		logger.Info("updated configuration",
			"path", *cfgPath,
			"store_master_password", appCfg.StoreMasterPassword,
			"require_polkit_on_unlock", appCfg.RequirePolkitOnUnlock,
			"allow_agent_forwarding", appCfg.AllowAgentForwarding,
			"polkit_cache_ttl_seconds", appCfg.PolkitCacheTTLSeconds,
		)
		if !*showConfig && !*storeMasterPw && !*clearMasterPw {
			return
		}
	}

	if *showConfig {
		fmt.Printf("# %s\n", *cfgPath)
		out, err := json.MarshalIndent(appCfg, "", "  ")
		if err != nil {
			logger.Error("failed to format config", "err", err)
			os.Exit(1)
		}
		fmt.Println(string(out))
		return
	}

	if *loginAPIKey {
		if err := agent.LoginWithAPIKey(); err != nil {
			logger.Error("API key login failed", "err", err)
			os.Exit(1)
		}
		logger.Info("authenticated Bitwarden CLI via API key")
		return
	}

	if *clearMasterPw {
		appCfg.StoreMasterPassword = false
		if *cfgPath != "" {
			if err := config.Save(*cfgPath, appCfg); err != nil {
				logger.Error("failed to update config", "err", err)
				os.Exit(1)
			}
		}
		removed, err := agent.ClearMasterPassword()
		if err != nil {
			logger.Error("failed to clear master password", "err", err)
			os.Exit(1)
		}
		logger.Info("disabled master password storage", "removed_existing", removed)
		return
	}

	if *storeMasterPw {
		if err := agent.StoreMasterPassword(); err != nil {
			logger.Error("failed to store master password", "err", err)
			os.Exit(1)
		}
		appCfg.StoreMasterPassword = true
		if *cfgPath != "" {
			if err := config.Save(*cfgPath, appCfg); err != nil {
				logger.Error("failed to save config", "err", err)
				os.Exit(1)
			}
		}
		logger.Info("enabled master password storage", "backend", agent.DetectSecretBackend(), "config", *cfgPath)
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

	bwAgent := agent.New(
		*secretKey,
		appCfg.StoreMasterPassword,
		appCfg.RequirePolkitOnUnlock,
		appCfg.AllowAgentForwarding,
		time.Duration(appCfg.PolkitCacheTTLSeconds)*time.Second,
		logger,
	)
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
