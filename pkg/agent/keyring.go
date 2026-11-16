package agent

import (
	"bytes"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

const (
	DefaultKeyringDesc   = "bw_ssh_session"
	sessionKeyTTLSeconds = 3600 // Auto-expire cached session token after 1 hour
)

// HasKeyctl reports whether the keyctl binary is available on PATH.
func HasKeyctl() bool {
	_, err := exec.LookPath("keyctl")
	return err == nil
}

// HasKeyringEntry checks whether a non-empty user key with desc exists in @u
// without returning its secret value.
func HasKeyringEntry(desc string) bool {
	sec, err := readKeyringRaw(desc)
	if err != nil || len(sec) == 0 {
		return false
	}
	zeroBytes(sec)
	return true
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
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

// writeKeyringRaw writes a secret into @u, restricts permissions to possessor-only (0x3f000000),
// and applies ttlSeconds expiration when ttlSeconds > 0.
func writeKeyringRaw(desc string, secret []byte, ttlSeconds int) error {
	cmd := exec.Command("keyctl", "padd", "user", desc, "@u")
	cmd.Stdin = bytes.NewReader(secret)
	out, err := cmd.Output()
	if err != nil {
		return err
	}
	keyID := strings.TrimSpace(string(out))

	if err := exec.Command("keyctl", "setperm", keyID, "0x3f000000").Run(); err != nil {
		return fmt.Errorf("failed to restrict permissions on key %s: %w", keyID, err)
	}

	if ttlSeconds > 0 {
		if err := exec.Command("keyctl", "timeout", keyID, fmt.Sprintf("%d", ttlSeconds)).Run(); err != nil {
			return fmt.Errorf("failed to set TTL on key %s: %w", keyID, err)
		}
	}
	return nil
}

// unlinkKeyringRaw removes a user key from @u if present.
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
