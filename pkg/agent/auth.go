package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// StoreAPIKey checks that keyctl and the user kernel keyring (@u) are available,
// then prompts for the Bitwarden Personal API Key without echoing secrets and stores them.
func StoreAPIKey() error {
	if !HasKeyctl() {
		return fmt.Errorf("keyctl is not installed; refusing to store API key without kernel keyring")
	}
	// Verify the user kernel keyring (@u) is active and writable in this session
	if err := exec.Command("keyctl", "show", "@u").Run(); err != nil {
		return fmt.Errorf("user kernel keyring (@u) is unavailable; refusing to store API key: %w", err)
	}

	clientID, err := readSecretInput("Bitwarden API Key", "Enter Bitwarden Client ID (e.g. user.xxxx): ", false)
	if err != nil {
		return err
	}
	defer zeroBytes(clientID)

	if len(clientID) == 0 {
		return fmt.Errorf("client ID cannot be empty")
	}

	clientSecret, err := readSecretInput("Bitwarden API Key", "Enter Bitwarden Client Secret: ", true)
	if err != nil {
		return err
	}
	defer zeroBytes(clientSecret)

	if len(clientSecret) == 0 {
		return fmt.Errorf("client secret cannot be empty")
	}

	if err := writeKeyringRaw(ClientIDKeyringDesc, clientID); err != nil {
		return fmt.Errorf("failed to store %s in kernel keyring: %w", ClientIDKeyringDesc, err)
	}
	if err := writeKeyringRaw(ClientSecKeyringDesc, clientSecret); err != nil {
		return fmt.Errorf("failed to store %s in kernel keyring: %w", ClientSecKeyringDesc, err)
	}

	return nil
}

// ClearAPIKey removes the stored Bitwarden API key credentials (bw_client_id and bw_client_secret)
// from the Linux user kernel keyring (@u).
func ClearAPIKey() (int, error) {
	if !HasKeyctl() {
		return 0, fmt.Errorf("keyctl is not installed; cannot clear API key from kernel keyring")
	}

	removed := 0
	for _, desc := range []string{ClientIDKeyringDesc, ClientSecKeyringDesc} {
		ok, err := unlinkKeyringRaw(desc)
		if err != nil {
			return removed, err
		}
		if ok {
			removed++
		}
	}
	return removed, nil
}

func checkBWStatus() (string, error) {
	out, err := exec.Command("bw", "status").Output()
	if err != nil {
		return "", fmt.Errorf("bw status failed: %w", err)
	}
	var res struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		return "", fmt.Errorf("failed to parse bw status: %w", err)
	}
	return res.Status, nil
}

func loginInteractive(s *sessionStore) error {
	clientID := []byte(os.Getenv("BW_CLIENTID"))
	clientSecret := []byte(os.Getenv("BW_CLIENTSECRET"))
	if len(clientID) == 0 && s.useKeyring {
		clientID, _ = readKeyringRaw(ClientIDKeyringDesc)
	}
	if len(clientSecret) == 0 && s.useKeyring {
		clientSecret, _ = readKeyringRaw(ClientSecKeyringDesc)
	}
	defer zeroBytes(clientID)
	defer zeroBytes(clientSecret)

	if len(clientID) > 0 && len(clientSecret) > 0 {
		s.logger.Info("logging into Bitwarden via API key")
		cmd := exec.Command("bw", "login", "--apikey")
		cmd.Env = append(os.Environ(),
			"BW_CLIENTID="+string(clientID),
			"BW_CLIENTSECRET="+string(clientSecret),
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("bw API key login failed: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		return nil
	}

	s.logger.Info("prompting for Bitwarden email and master password")
	email, err := promptSecret("Bitwarden Login", "Enter your Bitwarden email:", false)
	if err != nil {
		return err
	}
	defer zeroBytes(email)

	pw, err := promptSecret("Bitwarden Login", "Enter your Bitwarden master password:", true)
	if err != nil {
		return err
	}
	defer zeroBytes(pw)

	cmd := exec.Command("bw", "login", string(email), "--raw")
	cmd.Stdin = bytes.NewReader(append(pw, '\n'))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("bw login failed (if 2FA is enabled, log in once in terminal or use API key): %w (%s)", err, strings.TrimSpace(string(out)))
	}

	session := bytes.TrimSpace(out)
	if len(session) > 0 {
		s.Set(session)
		zeroBytes(session)
	}
	return nil
}

func unlockInteractive(s *sessionStore) ([]byte, error) {
	if sec, ok := s.Get(); ok {
		return sec, nil
	}

	pw, err := promptSecret("Unlock Bitwarden Vault", "Enter your Bitwarden master password to unlock SSH keys:", true)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(pw)

	cmd := exec.Command("bw", "unlock", "--raw")
	cmd.Stdin = bytes.NewReader(append(pw, '\n'))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("bw unlock failed: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}

	session := bytes.TrimSpace(stdout.Bytes())
	if len(session) == 0 {
		return nil, fmt.Errorf("bw unlock returned empty session token")
	}
	return session, nil
}
