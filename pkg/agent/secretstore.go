package agent

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/zalando/go-keyring"
)

const (
	secretServiceName = "bw-ssh-agent"
	DefaultSecretKey  = "bw_ssh_session"
	MasterPwSecretKey = "bw_master_password"
)

// SecretBackend identifies the active secret storage mechanism.
type SecretBackend string

const (
	BackendLibsecret SecretBackend = "libsecret"
	BackendKeyring   SecretBackend = "kernel-keyring"
	BackendMemory    SecretBackend = "memory"
)

// DetectSecretBackend checks whether org.freedesktop.secrets (via pure-Go D-Bus)
// or the Linux kernel keyring is available.
func DetectSecretBackend() SecretBackend {
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") != "" {
		_, err := keyring.Get(secretServiceName, "__probe__")
		if err == nil || errors.Is(err, keyring.ErrNotFound) {
			return BackendLibsecret
		}
	}

	if HasKeyring() {
		return BackendKeyring
	}

	return BackendMemory
}

func readLibsecret(key string) ([]byte, error) {
	val, err := keyring.Get(secretServiceName, key)
	if err != nil {
		return nil, err
	}
	return bytes.TrimRight([]byte(val), "\r\n"), nil
}

func writeLibsecret(key string, secret []byte) error {
	return keyring.Set(secretServiceName, key, string(secret))
}

func clearLibsecret(key string) error {
	err := keyring.Delete(secretServiceName, key)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}

// HasStoredSecret checks whether a non-empty secret exists in the active backend without returning its value.
func HasStoredSecret(key string) bool {
	switch DetectSecretBackend() {
	case BackendLibsecret:
		sec, err := readLibsecret(key)
		if err != nil || len(sec) == 0 {
			return false
		}
		zeroBytes(sec)
		return true
	case BackendKeyring:
		return HasKeyringEntry(key)
	default:
		return false
	}
}

// StoreMasterPassword prompts for the Bitwarden master password and saves it in libsecret (or @us fallback).
func StoreMasterPassword() error {
	backend := DetectSecretBackend()
	if backend == BackendMemory {
		return fmt.Errorf("neither D-Bus Secret Service (libsecret) nor Linux kernel keyring is available")
	}

	pw, err := readSecretInput("Bitwarden Master Password", "Enter Bitwarden master password to store: ", true)
	if err != nil {
		return err
	}
	defer zeroBytes(pw)

	if len(pw) == 0 {
		return fmt.Errorf("master password cannot be empty")
	}

	switch backend {
	case BackendLibsecret:
		return writeLibsecret(MasterPwSecretKey, pw)
	case BackendKeyring:
		return writeKeyringRaw(MasterPwKeyringDesc, pw, 0)
	default:
		return fmt.Errorf("no persistent secret backend available")
	}
}

// ClearMasterPassword removes the stored master password from both libsecret and the kernel keyring.
func ClearMasterPassword() (bool, error) {
	removed := false

	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") != "" {
		if _, err := keyring.Get(secretServiceName, MasterPwSecretKey); err == nil {
			if err := keyring.Delete(secretServiceName, MasterPwSecretKey); err == nil {
				removed = true
			}
		}
	}

	if HasKeyring() {
		if ok, _ := unlinkKeyringRaw(MasterPwKeyringDesc); ok {
			removed = true
		}
	}

	return removed, nil
}
