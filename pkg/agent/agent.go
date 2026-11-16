package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

type bwItem struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	SSHKey struct {
		PrivateKey string `json:"privateKey"`
		PublicKey  string `json:"publicKey"`
	} `json:"sshKey"`
}

type cachedKey struct {
	ID      string
	Name    string
	PubKey  ssh.PublicKey
	AgentID *sshagent.Key
}

// BitwardenAgent implements sshagent.ExtendedAgent backed by Bitwarden CLI and kernel keyring.
type BitwardenAgent struct {
	keyringDesc string
	logger      *slog.Logger
	mu          sync.RWMutex
	cache       []cachedKey
}

// New creates a new BitwardenAgent using the given kernel keyring description and logger.
// If keyringDesc is empty, DefaultKeyringDesc is used. If logger is nil, slog.Default() is used.
func New(keyringDesc string, logger *slog.Logger) *BitwardenAgent {
	if keyringDesc == "" {
		keyringDesc = DefaultKeyringDesc
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &BitwardenAgent{
		keyringDesc: keyringDesc,
		logger:      logger,
	}
}

// RefreshCache fetches only public key metadata from Bitwarden and stores it in RAM.
func (b *BitwardenAgent) RefreshCache() error {
	start := time.Now()
	b.logger.Info("refreshing public key cache")

	session, err := readSessionFromKeyring(b.keyringDesc)
	if err != nil {
		b.logger.Error("failed to read session from keyring", "err", err)
		return err
	}
	defer zeroBytes(session)

	cmd := exec.Command("bw", "list", "items")
	cmd.Env = append(os.Environ(), "BW_SESSION="+string(session))
	out, err := cmd.Output()
	if err != nil {
		b.logger.Error("bw list items failed", "err", err)
		return fmt.Errorf("bw list items failed: %w", err)
	}

	var all []bwItem
	if err := json.Unmarshal(out, &all); err != nil {
		b.logger.Error("failed to unmarshal bw items", "err", err)
		return err
	}

	var updated []cachedKey
	for _, item := range all {
		if item.SSHKey.PublicKey == "" {
			continue
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(item.SSHKey.PublicKey))
		if err != nil {
			b.logger.Warn("skipping unparseable public key", "item_id", item.ID, "name", item.Name, "err", err)
			continue
		}
		updated = append(updated, cachedKey{
			ID:     item.ID,
			Name:   item.Name,
			PubKey: pub,
			AgentID: &sshagent.Key{
				Format:  pub.Type(),
				Blob:    pub.Marshal(),
				Comment: item.Name,
			},
		})
	}

	b.mu.Lock()
	b.cache = updated
	b.mu.Unlock()

	b.logger.Info("public key cache updated", "count", len(updated), "duration", time.Since(start))
	return nil
}

// List serves cached public keys without spawning bw or triggering Polkit.
func (b *BitwardenAgent) List() ([]*sshagent.Key, error) {
	b.mu.RLock()
	keys := make([]*sshagent.Key, len(b.cache))
	for i, k := range b.cache {
		keys[i] = k.AgentID
	}
	b.mu.RUnlock()

	b.logger.Info("agent call: List", "returned_keys", len(keys))
	return keys, nil
}

func (b *BitwardenAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return b.SignWithFlags(key, data, 0)
}

func (b *BitwardenAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags sshagent.SignatureFlags) (*ssh.Signature, error) {
	start := time.Now()
	targetBlob := key.Marshal()

	b.mu.RLock()
	var matchedID, matchedName string
	for _, k := range b.cache {
		if bytes.Equal(k.AgentID.Blob, targetBlob) {
			matchedID = k.ID
			matchedName = k.Name
			break
		}
	}
	b.mu.RUnlock()

	if matchedID == "" {
		b.logger.Warn("agent call: Sign rejected (unknown key)", "key_type", key.Type())
		return nil, fmt.Errorf("matching key not found in cache")
	}

	b.logger.Info("agent call: Sign requested", "key_name", matchedName, "item_id", matchedID, "flags", flags)

	if err := authorizeSign(matchedName); err != nil {
		b.logger.Warn("polkit authorization denied", "key_name", matchedName, "err", err)
		return nil, err
	}
	b.logger.Info("polkit authorization approved", "key_name", matchedName)

	session, err := readSessionFromKeyring(b.keyringDesc)
	if err != nil {
		b.logger.Error("failed to read session from keyring during sign", "err", err)
		return nil, err
	}
	defer zeroBytes(session)

	getCmd := exec.Command("bw", "get", "item", matchedID)
	getCmd.Env = append(os.Environ(), "BW_SESSION="+string(session))
	rawItem, err := getCmd.Output()
	if err != nil {
		b.logger.Error("bw get item failed", "item_id", matchedID, "err", err)
		return nil, fmt.Errorf("bw get item failed: %w", err)
	}
	defer zeroBytes(rawItem)

	var item bwItem
	if err := json.Unmarshal(rawItem, &item); err != nil {
		b.logger.Error("failed to unmarshal bw item", "item_id", matchedID, "err", err)
		return nil, err
	}

	privBytes := []byte(item.SSHKey.PrivateKey)
	defer zeroBytes(privBytes)

	signer, err := ssh.ParsePrivateKey(privBytes)
	if err != nil {
		b.logger.Error("failed to parse private key", "item_id", matchedID, "err", err)
		return nil, fmt.Errorf("parse private key failed: %w", err)
	}

	var sig *ssh.Signature
	if algSigner, ok := signer.(ssh.AlgorithmSigner); ok {
		var alg string
		switch flags {
		case sshagent.SignatureFlagRsaSha256:
			alg = ssh.KeyAlgoRSASHA256
		case sshagent.SignatureFlagRsaSha512:
			alg = ssh.KeyAlgoRSASHA512
		}
		if alg != "" {
			sig, err = algSigner.SignWithAlgorithm(nil, data, alg)
		}
	}
	if sig == nil && err == nil {
		sig, err = signer.Sign(nil, data)
	}
	if err != nil {
		b.logger.Error("signing failed", "key_name", matchedName, "err", err)
		return nil, err
	}

	b.logger.Info("agent call: Sign completed", "key_name", matchedName, "alg", sig.Format, "duration", time.Since(start))
	return sig, nil
}

// Read-only stubs required to satisfy sshagent.ExtendedAgent
func (b *BitwardenAgent) Add(key sshagent.AddedKey) error {
	b.logger.Warn("agent call: Add rejected (read-only)")
	return fmt.Errorf("read-only agent")
}
func (b *BitwardenAgent) Remove(key ssh.PublicKey) error {
	b.logger.Warn("agent call: Remove rejected (read-only)")
	return fmt.Errorf("read-only agent")
}
func (b *BitwardenAgent) RemoveAll() error {
	b.logger.Warn("agent call: RemoveAll rejected (read-only)")
	return fmt.Errorf("read-only agent")
}
func (b *BitwardenAgent) Lock(passphrase []byte) error {
	b.logger.Warn("agent call: Lock rejected (unsupported)")
	return fmt.Errorf("unsupported")
}
func (b *BitwardenAgent) Unlock(passphrase []byte) error {
	b.logger.Warn("agent call: Unlock rejected (unsupported)")
	return fmt.Errorf("unsupported")
}
func (b *BitwardenAgent) Signers() ([]ssh.Signer, error) {
	return nil, fmt.Errorf("unsupported")
}
func (b *BitwardenAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	b.logger.Info("agent call: Extension (unsupported)", "type", extensionType)
	return nil, sshagent.ErrExtensionUnsupported
}
