package agent

import (
	"fmt"
	"runtime"

	"github.com/jsipprell/keyctl"
)

const (
	DefaultKeyringDesc   = "bw_ssh_session"
	MasterPwKeyringDesc  = "bw_master_password"
	sessionKeyTTLSeconds = 3600 // Auto-expire cached session token after 1 hour

	// Possessor-only permissions: View | Read | Write | Search | Link | Setattr (0x3f000000)
	possessorOnlyPerm keyctl.KeyPerm = 0x3f000000
)

// HasKeyring reports whether the Linux user kernel keyring (@u) is accessible.
func HasKeyring() bool {
	_, err := keyctl.UserSessionKeyring()
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

func ensureUserKeyringLinked() (keyctl.Keyring, error) {
	uKr, err := keyctl.UserSessionKeyring()
	if err != nil {
		return nil, err
	}
	if sKr, err := keyctl.SessionKeyring(); err == nil {
		_ = keyctl.Link(sKr, uKr)
	}
	return uKr, nil
}

func readKeyringRaw(desc string) ([]byte, error) {
	kr, err := ensureUserKeyringLinked()
	if err != nil {
		return nil, err
	}

	key, err := kr.Search(desc)
	if err != nil {
		return nil, err
	}

	return key.Get()
}

func writeKeyringRaw(desc string, secret []byte, ttlSeconds int) error {
	kr, err := ensureUserKeyringLinked()
	if err != nil {
		return fmt.Errorf("failed to open user keyring: %w", err)
	}

	key, err := kr.Add(desc, secret)
	if err != nil {
		return fmt.Errorf("failed to add key %q to keyring: %w", desc, err)
	}

	if err := keyctl.SetPerm(key, possessorOnlyPerm); err != nil {
		_ = key.Unlink()
		return fmt.Errorf("failed to set permissions on key %q: %w", desc, err)
	}

	if ttlSeconds > 0 {
		if err := key.ExpireAfter(uint(ttlSeconds)); err != nil {
			return fmt.Errorf("failed to set timeout on key %q: %w", desc, err)
		}
	}
	return nil
}

func unlinkKeyringRaw(desc string) (bool, error) {
	kr, err := ensureUserKeyringLinked()
	if err != nil {
		return false, err
	}

	key, err := kr.Search(desc)
	if err != nil {
		return false, nil
	}

	if err := key.Unlink(); err != nil {
		return false, fmt.Errorf("failed to unlink key %q: %w", desc, err)
	}
	return true, nil
}
