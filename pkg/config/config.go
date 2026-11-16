package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Config holds persistent user preferences for bw-ssh-agent.
type Config struct {
	// StoreMasterPassword controls whether the Bitwarden master password is cached
	// in the active secret backend (libsecret or kernel keyring) after unlocking.
	// Defaults to false.
	StoreMasterPassword bool `json:"store_master_password"`

	// RequirePolkitOnUnlock forces a Polkit prompt even when the user is already
	// typing their Bitwarden master password interactively. When false (default),
	// Polkit is only required on unlock if a cached master password is used automatically.
	RequirePolkitOnUnlock bool `json:"require_polkit_on_unlock"`

	// AllowAgentForwarding permits SSH signing requests originating from forwarded
	// SSH agent sessions (is_forwarding=1 in session-bind@openssh.com). Defaults to false.
	AllowAgentForwarding bool `json:"allow_agent_forwarding"`
}

// DefaultPath returns $XDG_CONFIG_HOME/bw-ssh-agent/config.json (or ~/.config/bw-ssh-agent/config.json).
func DefaultPath() (string, error) {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("cannot resolve user config directory: %w", err)
	}
	return filepath.Join(cfgDir, "bw-ssh-agent", "config.json"), nil
}

// Load reads the JSON configuration file at path. If the file does not exist,
// it returns the secure default configuration without error.
func Load(path string) (Config, error) {
	var cfg Config
	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("failed to read config %s: %w", path, err)
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("failed to parse config %s: %w", path, err)
	}
	return cfg, nil
}

// Save writes cfg to path with 0600 permissions, creating parent directories (0700) if needed.
func Save(path string, cfg Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config %s: %w", path, err)
	}
	return nil
}
