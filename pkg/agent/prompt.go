package agent

import (
	"bytes"
	"fmt"
	"html"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/term"
)

// DetectPromptBackend reports which interactive prompt mechanism will be used.
func DetectPromptBackend() (string, error) {
	if path, err := findPinentry(); err == nil {
		return fmt.Sprintf("pinentry (%s)", path), nil
	}
	for _, bin := range []string{"zenity", "kdialog", "yad", "systemd-ask-password"} {
		if path, err := exec.LookPath(bin); err == nil {
			return fmt.Sprintf("%s (%s)", bin, path), nil
		}
	}
	if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		tty.Close()
		return "/dev/tty (controlling terminal fallback)", nil
	}
	return "", fmt.Errorf("no GUI/pinentry askpass helper and no /dev/tty available")
}

func readSecretInput(title, prompt string, hide bool) ([]byte, error) {
	if b, err := readFromTTY(prompt, hide); err == nil {
		return b, nil
	}
	return promptSecret(title, strings.TrimSpace(prompt), hide, "")
}

func readFromTTY(prompt string, hide bool) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	defer tty.Close()

	fd := int(tty.Fd())
	if !term.IsTerminal(fd) {
		return nil, fmt.Errorf("/dev/tty is not a terminal")
	}

	fmt.Fprint(tty, prompt)
	if hide {
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(tty)
		if err != nil {
			return nil, fmt.Errorf("failed to read secret from tty: %w", err)
		}
		return bytes.TrimSpace(b), nil
	}

	var buf bytes.Buffer
	var ch [1]byte
	for {
		n, err := tty.Read(ch[:])
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

// promptSecret asks the user for a secret, preferring pinentry (with optional libsecret cacheID)
// and falling back to zenity, kdialog, yad, systemd-ask-password, or /dev/tty.
func promptSecret(title, text string, hide bool, cacheID string) ([]byte, error) {
	if hide {
		if _, err := findPinentry(); err == nil {
			secret, err := promptPinentry(title, text, "Password:", cacheID)
			if err != nil {
				return nil, err
			}
			return secret, nil
		}
	}

	if path, err := exec.LookPath("zenity"); err == nil {
		args := []string{
			"--entry",
			"--title=" + html.EscapeString(title),
			"--text=" + html.EscapeString(text),
		}
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
		args := []string{
			"--entry",
			"--title=" + html.EscapeString(title),
			"--text=" + html.EscapeString(text),
		}
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

	promptLine := fmt.Sprintf("\n[%s] %s ", title, text)
	if b, err := readFromTTY(promptLine, hide); err == nil {
		return b, nil
	}

	return nil, fmt.Errorf("no interactive prompt utility found (install pinentry, zenity, or kdialog)")
}

func isSessionInvalid(stderr string) bool {
	s := strings.ToLower(stderr)
	return strings.Contains(s, "vault is locked") ||
		strings.Contains(s, "you are not logged in") ||
		strings.Contains(s, "invalid session")
}
