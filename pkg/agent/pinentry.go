package agent

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func findPinentry() (string, error) {
	for _, bin := range []string{
		"pinentry-gnome3",
		"pinentry-qt",
		"pinentry-gtk-2",
		"pinentry-curses",
		"pinentry",
	} {
		if path, err := exec.LookPath(bin); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("pinentry not found in PATH")
}

// promptPinentry spawns a pinentry process and executes an Assuan GETPIN dialog.
// If cacheID is non-empty, pinentry enables its native "Save in password manager"
// option backed by libsecret/GNOME Keyring/KWallet.
func promptPinentry(title, desc, prompt, cacheID string) ([]byte, error) {
	bin, err := findPinentry()
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(bin)
	cmd.Env = os.Environ()

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start %s: %w", bin, err)
	}
	defer func() {
		_, _ = fmt.Fprintln(stdin, "BYE")
		_ = stdin.Close()
		_ = cmd.Wait()
	}()

	reader := bufio.NewReader(stdout)
	if _, err := readAssuanResponse(reader); err != nil {
		return nil, fmt.Errorf("pinentry greeting failed: %w", err)
	}

	sendCmd := func(c string) ([]byte, error) {
		if _, err := fmt.Fprintln(stdin, c); err != nil {
			return nil, err
		}
		return readAssuanResponse(reader)
	}

	if _, err := sendCmd("SETTITLE " + escapeAssuan(title)); err != nil {
		return nil, err
	}
	if _, err := sendCmd("SETDESC " + escapeAssuan(desc)); err != nil {
		return nil, err
	}
	if _, err := sendCmd("SETPROMPT " + escapeAssuan(prompt)); err != nil {
		return nil, err
	}
	if cacheID != "" {
		_, _ = sendCmd("OPTION allow-external-password-cache")
		_, _ = sendCmd("SETKEYINFO " + escapeAssuan(cacheID))
	}

	return sendCmd("GETPIN")
}

func readAssuanResponse(r *bufio.Reader) ([]byte, error) {
	var data bytes.Buffer
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")

		switch {
		case strings.HasPrefix(line, "OK"):
			return data.Bytes(), nil
		case strings.HasPrefix(line, "ERR "):
			return nil, fmt.Errorf("pinentry error: %s", strings.TrimPrefix(line, "ERR "))
		case strings.HasPrefix(line, "D "):
			decoded := unescapeAssuan(line[2:])
			data.Write(decoded)
			zeroBytes(decoded)
		case strings.HasPrefix(line, "#"), strings.HasPrefix(line, "S "):
			continue
		}
	}
}

func escapeAssuan(s string) string {
	r := strings.NewReplacer("%", "%25", "\n", "%0A", "\r", "%0D")
	return r.Replace(s)
}

func unescapeAssuan(s string) []byte {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if val, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				out = append(out, byte(val))
				i += 2
				continue
			}
		}
		out = append(out, s[i])
	}
	return out
}
