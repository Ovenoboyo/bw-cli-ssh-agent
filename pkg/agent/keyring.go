package agent

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

const (
	DefaultKeyringDesc   = "bw_ssh_session"
	ClientIDKeyringDesc  = "bw_client_id"
	ClientSecKeyringDesc = "bw_client_secret"
)

func hasKeyctl() bool {
	_, err := exec.LookPath("keyctl")
	return err == nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// readKeyringRaw reads a user key from the Linux user kernel keyring (@u).
func readKeyringRaw(desc string) ([]byte, error) {
	idOut, err := exec.Command("keyctl", "search", "@u", "user", desc).Output()
	if err != nil {
		return nil, err
	}
	keyID := strings.TrimSpace(string(idOut))

	secret, err := exec.Command("keyctl", "pipe", keyID).Output()
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(secret), nil
}

// writeKeyringRaw writes a secret into the Linux user kernel keyring (@u), replacing any existing key.
func writeKeyringRaw(desc string, secret []byte) error {
	cmd := exec.Command("keyctl", "padd", "user", desc, "@u")
	cmd.Stdin = bytes.NewReader(secret)
	return cmd.Run()
}

// unlinkKeyringRaw removes a user key from the Linux user kernel keyring (@u) if present.
// It returns true if the key was found and unlinked, or false if it did not exist.
func unlinkKeyringRaw(desc string) (bool, error) {
	idOut, err := exec.Command("keyctl", "search", "@u", "user", desc).Output()
	if err != nil {
		return false, nil
	}
	keyID := strings.TrimSpace(string(idOut))
	if err := exec.Command("keyctl", "unlink", keyID, "@u").Run(); err != nil {
		return false, fmt.Errorf("failed to unlink %s (id %s): %w", desc, keyID, err)
	}
	return true, nil
}
