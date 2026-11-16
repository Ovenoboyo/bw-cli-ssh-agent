package agent

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/term"
)

// readSecretInput reads from the controlling terminal (hiding input if hide is true)
// or falls back to the desktop askpass prompt if stdin is not a TTY.
func readSecretInput(title, prompt string, hide bool) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, prompt)
		if hide {
			b, err := term.ReadPassword(fd)
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return nil, fmt.Errorf("failed to read secret from terminal: %w", err)
			}
			return bytes.TrimSpace(b), nil
		}

		var buf bytes.Buffer
		var ch [1]byte
		for {
			n, err := os.Stdin.Read(ch[:])
			if n > 0 {
				if ch[0] == '\n' || ch[0] == '\r' {
					break
				}
				buf.WriteByte(ch[0])
			}
			if err != nil {
				break
			}
		}
		return bytes.TrimSpace(buf.Bytes()), nil
	}

	return promptSecret(title, strings.TrimSpace(prompt), hide)
}

// promptSecret asks the user for a secret (password or email) via an available desktop/system askpass dialog.
func promptSecret(title, text string, hide bool) ([]byte, error) {
	if path, err := exec.LookPath("zenity"); err == nil {
		args := []string{"--entry", "--title=" + title, "--text=" + text}
		if hide {
			args = append(args, "--hide-text")
		}
		out, err := exec.Command(path, args...).Output()
		if err != nil {
			return nil, fmt.Errorf("prompt canceled or failed: %w", err)
		}
		return bytes.TrimRight(out, "\r\n"), nil
	}

	if path, err := exec.LookPath("kdialog"); err == nil {
		flag := "--inputbox"
		if hide {
			flag = "--password"
		}
		out, err := exec.Command(path, "--title", title, flag, text).Output()
		if err != nil {
			return nil, fmt.Errorf("prompt canceled or failed: %w", err)
		}
		return bytes.TrimRight(out, "\r\n"), nil
	}

	if path, err := exec.LookPath("yad"); err == nil {
		args := []string{"--entry", "--title=" + title, "--text=" + text}
		if hide {
			args = append(args, "--hide-text")
		}
		out, err := exec.Command(path, args...).Output()
		if err != nil {
			return nil, fmt.Errorf("prompt canceled or failed: %w", err)
		}
		return bytes.TrimRight(out, "\r\n"), nil
	}

	if path, err := exec.LookPath("systemd-ask-password"); err == nil {
		out, err := exec.Command(path, "--no-tty", fmt.Sprintf("%s: %s", title, text)).Output()
		if err != nil {
			return nil, fmt.Errorf("systemd-ask-password failed: %w", err)
		}
		return bytes.TrimRight(out, "\r\n"), nil
	}

	return nil, fmt.Errorf("no interactive prompt utility found (install zenity, kdialog, yad, or systemd)")
}

// isSessionInvalid checks common bw CLI stderr messages indicating a locked or expired vault.
func isSessionInvalid(stderr string) bool {
	s := strings.ToLower(stderr)
	return strings.Contains(s, "vault is locked") ||
		strings.Contains(s, "you are not logged in") ||
		strings.Contains(s, "invalid session")
}
