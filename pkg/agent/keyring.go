package agent

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

const DefaultKeyringDesc = "bw_ssh_session"

// readSessionFromKeyring fetches the Bitwarden session token from the Linux user kernel keyring (@u).
func readSessionFromKeyring(desc string) ([]byte, error) {
	idOut, err := exec.Command("keyctl", "search", "@u", "user", desc).Output()
	if err != nil {
		return nil, fmt.Errorf("session key %q not found in kernel keyring: %w", desc, err)
	}
	keyID := strings.TrimSpace(string(idOut))

	secret, err := exec.Command("keyctl", "pipe", keyID).Output()
	if err != nil {
		return nil, fmt.Errorf("failed to read key %s from keyring: %w", keyID, err)
	}
	return bytes.TrimSpace(secret), nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
