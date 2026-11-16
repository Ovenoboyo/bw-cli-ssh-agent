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

// readSecretInput reads from the controlling terminal (hiding input if hide is true)
// or falls back to the desktop askpass prompt if no terminal is attached.
func readSecretInput(title, prompt string, hide bool) ([]byte, error) {
	if b, err := readFromTTY(prompt, hide); err == nil {
		return b, nil
	}
	return promptSecret(title, strings.TrimSpace(prompt), hide)
}

// readFromTTY opens /dev/tty directly so it works even if os.Stdin is redirected,
// and reads a line (with echo disabled via term.ReadPassword when hide is true).
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

// promptSecret asks the user for a secret via an available desktop/system askpass dialog,
// falling back to prompting directly on /dev/tty if no GUI/system helper is installed.
func promptSecret(title, text string, hide bool) ([]byte, error) {
	safeTitle := html.EscapeString(title)
	safeText := html.EscapeString(text)

	// 1. Try zenity (GTK / GNOME / Hyprland)
	if path, err := exec.LookPath("zenity"); err == nil {
		args := []string{"--entry", "--title=" + safeTitle, "--text=" + safeText}
		if hide {
			args = append(args, "--hide-text")
		}
		out, err := exec.Command(path, args...).Output()
		if err != nil {
			return nil, fmt.Errorf("prompt canceled or failed: %w", err)
		}
		return bytes.TrimRight(out, "\r\n"), nil
	}

	// 2. Try kdialog (KDE / Qt)
	if path, err := exec.LookPath("kdialog"); err == nil {
		flag := "--inputbox"
		if hide {
			flag = "--password"
		}
		out, err := exec.Command(path, "--title", safeTitle, flag, safeText).Output()
		if err != nil {
			return nil, fmt.Errorf("prompt canceled or failed: %w", err)
		}
		return bytes.TrimRight(out, "\r\n"), nil
	}

	// 3. Try yad
	if path, err := exec.LookPath("yad"); err == nil {

		args := []string{"--entry", "--title=" + safeTitle, "--text=" + safeText}
		if hide {
			args = append(args, "--hide-text")
		}
		out, err := exec.Command(path, args...).Output()
		if err != nil {
			return nil, fmt.Errorf("prompt canceled or failed: %w", err)
		}
		return bytes.TrimRight(out, "\r\n"), nil
	}

	// 4. Try systemd-ask-password
	if path, err := exec.LookPath("systemd-ask-password"); err == nil {
		out, err := exec.Command(path, "--no-tty", fmt.Sprintf("%s: %s", safeTitle, safeText)).Output()
		if err != nil {
			return nil, fmt.Errorf("systemd-ask-password failed: %w", err)
		}
		return bytes.TrimRight(out, "\r\n"), nil
	}

	// 5. Final fallback: prompt directly on the controlling terminal (/dev/tty)
	promptLine := fmt.Sprintf("\n[%s] %s ", safeTitle, safeText)
	if b, err := readFromTTY(promptLine, hide); err == nil {
		return b, nil
	}

	return nil, fmt.Errorf("no interactive prompt utility found and no controlling terminal (/dev/tty) available; install zenity, kdialog, or yad")
}

// isSessionInvalid checks common bw CLI stderr messages indicating a locked or expired vault.
func isSessionInvalid(stderr string) bool {
	s := strings.ToLower(stderr)
	return strings.Contains(s, "vault is locked") ||
		strings.Contains(s, "you are not logged in") ||
		strings.Contains(s, "invalid session")
}
