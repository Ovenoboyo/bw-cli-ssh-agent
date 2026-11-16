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

// Options configures environment paths checked by Run.
type Options struct {
	SocketPath  string
	PidFile     string
	KeyringDesc string
}

// Run inspects all dependencies, keyring entries, prompt tooling, Bitwarden status,
// and daemon state, printing a diagnostic report to w without exposing secret values.
func Run(w io.Writer, opts Options) error {
	if opts.KeyringDesc == "" {
		opts.KeyringDesc = agent.DefaultKeyringDesc
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
	promptBackend, promptErr := detectPromptBackend()
	if promptErr == nil {
		pass("Interactive prompt", promptBackend)
	} else {
		warn("Interactive prompt", promptErr.Error())
	}

	// 3. Kernel keyring & stored credentials (existence only — never print secrets)
	keyringReady := false
	if kcPath, err := exec.LookPath("keyctl"); err != nil {
		warn("Kernel keyring (keyctl)", "not installed (will fall back to in-memory session storage)")
	} else if err := exec.Command("keyctl", "show", "@u").Run(); err != nil {
		warn("Kernel keyring (@u)", fmt.Sprintf("%s found, but user keyring @u is unavailable: %v", kcPath, err))
	} else {
		keyringReady = true
		pass("Kernel keyring (@u)", fmt.Sprintf("available (%s)", kcPath))
	}

	if keyringReady {
		if agent.HasKeyringEntry(opts.KeyringDesc) {
			pass("Stored BW_SESSION", fmt.Sprintf("present in @u (%s)", opts.KeyringDesc))
		} else {
			warn("Stored BW_SESSION", fmt.Sprintf("not found in @u (%s) — will prompt on first use", opts.KeyringDesc))
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

func detectPromptBackend() (string, error) {
	for _, bin := range []string{"zenity", "kdialog", "yad", "systemd-ask-password"} {
		if path, err := exec.LookPath(bin); err == nil {
			return fmt.Sprintf("%s (%s)", bin, path), nil
		}
	}
	if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		tty.Close()
		return "/dev/tty (controlling terminal fallback)", nil
	}
	return "", fmt.Errorf("no GUI askpass helper (zenity/kdialog/yad/systemd-ask-password) and no /dev/tty available")
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
