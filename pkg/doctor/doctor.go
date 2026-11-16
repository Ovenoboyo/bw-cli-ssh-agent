package doctor

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/Ovenoboyo/bw-cli-ssh-agent/pkg/agent"
)

// Options configures environment paths and settings checked by Run.
type Options struct {
	SocketPath            string
	PidFile               string
	ConfigPath            string
	SecretKey             string
	StoreMasterPassword   bool
	RequirePolkitOnUnlock bool
	AllowAgentForwarding  bool
}

// Run inspects all dependencies, secret storage, prompt tooling, Bitwarden status,
// and daemon state, printing a diagnostic report to w without exposing secret values.
func Run(w io.Writer, opts Options) error {
	if opts.SecretKey == "" {
		opts.SecretKey = agent.DefaultSecretKey
	}

	hasErrors := false
	pass := func(label, detail string) {
		fmt.Fprintf(w, "[OK]   %-24s %s\n", label+":", detail)
	}
	warn := func(label, detail string) {
		fmt.Fprintf(w, "[WARN] %-24s %s\n", label+":", detail)
	}
	fail := func(label, detail string) {
		hasErrors = true
		fmt.Fprintf(w, "[FAIL] %-24s %s\n", label+":", detail)
	}

	fmt.Fprintln(w, "bw-ssh-agent doctor")
	fmt.Fprintln(w, strings.Repeat("-", 60))

	// 1. Core CLI dependencies
	if bwPath, err := exec.LookPath("bw"); err == nil {
		pass("Bitwarden CLI (bw)", bwPath)
	} else {
		fail("Bitwarden CLI (bw)", "not found in PATH")
	}

	if pkPath, err := exec.LookPath("pkcheck"); err == nil {
		pass("Polkit (pkcheck)", pkPath)
	} else {
		fail("Polkit (pkcheck)", "not found in PATH (signing and unlock auth will fail)")
	}

	// 2. Interactive prompt backend
	promptBackend, promptErr := agent.DetectPromptBackend()
	if promptErr == nil {
		pass("Interactive prompt", promptBackend)
	} else {
		warn("Interactive prompt", promptErr.Error())
	}

	// 3. Config file & Secret Storage Backend (libsecret -> kernel keyring -> memory)
	if opts.ConfigPath != "" {
		pass("Config file", fmt.Sprintf("%s (store_master_password=%t, require_polkit_on_unlock=%t, allow_agent_forwarding=%t)",
			opts.ConfigPath,
			opts.StoreMasterPassword,
			opts.RequirePolkitOnUnlock,
			opts.AllowAgentForwarding,
		))
	}

	backend := agent.DetectSecretBackend()
	switch backend {
	case agent.BackendLibsecret:
		pass("Secret storage", "libsecret (D-Bus Secret Service)")
	case agent.BackendKeyring:
		pass("Secret storage", "Linux kernel keyring (@u via native syscalls)")
	default:
		warn("Secret storage", "memory-only fallback (neither libsecret nor kernel keyring available)")
	}

	if backend != agent.BackendMemory {
		if agent.HasStoredSecret(opts.SecretKey) {
			pass("Stored BW_SESSION", fmt.Sprintf("present in %s (%s)", backend, opts.SecretKey))
		} else {
			warn("Stored BW_SESSION", fmt.Sprintf("not found in %s (%s) — will prompt on first use", backend, opts.SecretKey))
		}

		if opts.StoreMasterPassword {
			if agent.HasStoredSecret(agent.MasterPwSecretKey) {
				pass("Stored master password", fmt.Sprintf("present in %s (%s)", backend, agent.MasterPwSecretKey))
			} else {
				warn("Stored master password", fmt.Sprintf("enabled in config, not yet cached in %s (will store on next unlock)", backend))
			}
		}
	}

	if os.Getenv("BW_CLIENTID") != "" && os.Getenv("BW_CLIENTSECRET") != "" {
		pass("Env API key", "BW_CLIENTID and BW_CLIENTSECRET are set in environment")
	}

	// 4. Bitwarden CLI vault status
	if bwStatus, serverURL, err := inspectBWStatus(); err == nil {
		if serverURL == "" {
			serverURL = "https://vault.bitwarden.com (default)"
		}
		pass("Bitwarden vault status", fmt.Sprintf("%s (server: %s)", bwStatus, serverURL))
	} else {
		warn("Bitwarden vault status", err.Error())
	}

	// 5. Daemon & SSH_AUTH_SOCK runtime status
	if opts.PidFile != "" {
		if pid, alive := checkPidAlive(opts.PidFile); alive {
			pass("Daemon process", fmt.Sprintf("running (pid %d)", pid))
		} else {
			warn("Daemon process", fmt.Sprintf("not running (pid file: %s)", opts.PidFile))
		}
	}

	if opts.SocketPath != "" {
		if info, err := os.Stat(opts.SocketPath); err == nil && info.Mode()&os.ModeSocket != 0 {
			pass("Agent Unix socket", opts.SocketPath)
		} else {
			warn("Agent Unix socket", fmt.Sprintf("not listening at %s", opts.SocketPath))
		}
	}

	envSock := os.Getenv("SSH_AUTH_SOCK")
	switch {
	case envSock == "":
		warn("SSH_AUTH_SOCK", "unset in current shell")
	case envSock == opts.SocketPath:
		pass("SSH_AUTH_SOCK", envSock)
	default:
		warn("SSH_AUTH_SOCK", fmt.Sprintf("points to %s (expected %s)", envSock, opts.SocketPath))
	}

	fmt.Fprintln(w, strings.Repeat("-", 60))
	if hasErrors {
		return fmt.Errorf("one or more required dependencies are missing")
	}
	return nil
}

func inspectBWStatus() (string, string, error) {
	out, err := exec.Command("bw", "status").Output()
	if err != nil {
		return "", "", fmt.Errorf("bw status failed: %w", err)
	}
	var res struct {
		Status    string `json:"status"`
		ServerURL string `json:"serverUrl"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		return "", "", fmt.Errorf("failed to parse bw status output: %w", err)
	}
	return res.Status, res.ServerURL, nil
}

func checkPidAlive(pidFile string) (int, bool) {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return pid, false
	}
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		return pid, false
	}
	return pid, true
}
