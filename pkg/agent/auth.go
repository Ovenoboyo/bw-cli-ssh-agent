package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const maxUnlockAttempts = 3

// LoginWithAPIKey prompts for the Bitwarden Personal API Key (client_id and client_secret)
// without echoing secrets, passes them once to `bw login --apikey`, and zeroes them in memory.
func LoginWithAPIKey() error {
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

	cmd := exec.Command("bw", "login", "--apikey")
	cmd.Env = append(os.Environ(),
		"BW_CLIENTID="+string(clientID),
		"BW_CLIENTSECRET="+string(clientSecret),
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("bw login --apikey failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
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
	defer zeroBytes(clientID)
	defer zeroBytes(clientSecret)

	if len(clientID) > 0 && len(clientSecret) > 0 {
		s.logger.Info("logging into Bitwarden via environment API key")
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
	email, err := promptSecret("Bitwarden Login", "Enter your Bitwarden email:", false, "")
	if err != nil {
		return err
	}
	defer zeroBytes(email)

	pw, err := promptSecret("Bitwarden Login", "Enter your Bitwarden master password:", true, "")
	if err != nil {
		return err
	}
	defer zeroBytes(pw)

	cmd := exec.Command("bw", "login", "--", string(email), "--raw")
	cmd.Stdin = bytes.NewReader(append(pw, '\n'))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("bw login failed (if 2FA is enabled, run 'bw-ssh-agent --login-apikey' once): %w (%s)", err, strings.TrimSpace(string(out)))
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

	// 1. If store_master_password is enabled and a cached password exists, require Polkit first
	if s.storeMasterPw {
		var cachedPw []byte
		switch s.backend {
		case BackendLibsecret:
			cachedPw, _ = readLibsecret(MasterPwSecretKey)
		case BackendKeyring:
			cachedPw, _ = readKeyringRaw(MasterPwKeyringDesc)
		}

		if len(cachedPw) > 0 {
			defer zeroBytes(cachedPw)
			if !s.requirePolkitOnUnlock {
				s.logger.Info("cached master password found; requesting Polkit authorization")
				if err := authorizeAction("unlock Bitwarden SSH agent"); err != nil {
					return nil, err
				}
			}

			if session, err := runBWUnlock(cachedPw); err == nil {
				return session, nil
			} else {
				s.logger.Warn("cached master password rejected by bw unlock; clearing cached password and prompting interactively", "err", err)
				switch s.backend {
				case BackendLibsecret:
					_ = clearLibsecret(MasterPwSecretKey)
				case BackendKeyring:
					_, _ = unlinkKeyringRaw(MasterPwKeyringDesc)
				}
			}
		}
	}

	// 2. Interactive master password prompt with retry loop on wrong password (no redundant Polkit prompt)
	cacheID := ""
	if s.storeMasterPw {
		cacheID = "bw-ssh-agent/master-password"
	}

	promptText := "Enter your Bitwarden master password to unlock SSH keys:"
	for attempt := 1; attempt <= maxUnlockAttempts; attempt++ {
		pw, err := promptSecret("Unlock Bitwarden Vault", promptText, true, cacheID)
		if err != nil {
			// User canceled prompt or prompt helper failed
			return nil, err
		}

		session, unlockErr := runBWUnlock(pw)
		if unlockErr == nil {
			if s.storeMasterPw {
				switch s.backend {
				case BackendLibsecret:
					if err := writeLibsecret(MasterPwSecretKey, pw); err == nil {
						s.logger.Info("stored Bitwarden master password in libsecret")
					}
				case BackendKeyring:
					if err := writeKeyringRaw(MasterPwKeyringDesc, pw, 0); err == nil {
						s.logger.Info("stored Bitwarden master password in kernel keyring (@us)")
					}
				}
			}
			zeroBytes(pw)
			return session, nil
		}

		zeroBytes(pw)
		if !isInvalidMasterPassword(unlockErr.Error()) {
			return nil, unlockErr
		}

		s.logger.Warn("invalid Bitwarden master password entered", "attempt", attempt, "max_attempts", maxUnlockAttempts)
		promptText = fmt.Sprintf("Invalid master password (attempt %d/%d). Please try again:", attempt, maxUnlockAttempts)
	}

	return nil, fmt.Errorf("failed to unlock Bitwarden vault after %d attempts", maxUnlockAttempts)
}

func runBWUnlock(pw []byte) ([]byte, error) {
	cmd := exec.Command("bw", "unlock", "--raw")
	cmd.Stdin = bytes.NewReader(append(append([]byte(nil), pw...), '\n'))
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

func isInvalidMasterPassword(errMsg string) bool {
	s := strings.ToLower(errMsg)
	return strings.Contains(s, "invalid master password") ||
		strings.Contains(s, "wrong password") ||
		strings.Contains(s, "mac failed")
}
