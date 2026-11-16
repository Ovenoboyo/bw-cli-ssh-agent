package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

const (
	cacheTTL         = 30 * time.Minute
	selfHealCooldown = 10 * time.Second
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

// PeerInfo identifies the local client process connected to the Unix domain socket.
type PeerInfo struct {
	PID  int32
	UID  uint32
	GID  uint32
	Comm string
}

type connAgent struct {
	*BitwardenAgent
	peer      PeerInfo
	forwarded atomic.Bool
}

// ServeConn serves the OpenSSH agent protocol for a single authenticated local peer.
func (b *BitwardenAgent) ServeConn(c net.Conn, peer PeerInfo) error {
	ca := &connAgent{BitwardenAgent: b, peer: peer}
	return sshagent.ServeAgent(ca, c)
}

func (c *connAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	if extensionType == "session-bind@openssh.com" {
		c.forwarded.Store(true)
		c.logger.Warn("agent forwarding detected on connection; signing will be blocked",
			"peer_pid", c.peer.PID, "peer_comm", c.peer.Comm)
		return nil, fmt.Errorf("agent forwarding is disabled for security")
	}
	return c.BitwardenAgent.Extension(extensionType, contents)
}

func (c *connAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags sshagent.SignatureFlags) (*ssh.Signature, error) {
	if c.forwarded.Load() {
		c.logger.Warn("blocked sign request from forwarded SSH agent session",
			"peer_pid", c.peer.PID, "peer_comm", c.peer.Comm)
		return nil, fmt.Errorf("signing via forwarded SSH agent is disallowed")
	}
	c.logger.Info("sign request peer context", "peer_pid", c.peer.PID, "peer_comm", c.peer.Comm)
	return c.BitwardenAgent.SignWithFlags(key, data, flags)
}

// BitwardenAgent implements sshagent.ExtendedAgent backed by Bitwarden CLI.
type BitwardenAgent struct {
	store  *sessionStore
	logger *slog.Logger

	mu            sync.RWMutex
	initialized   bool
	lastRefreshed time.Time
	cache         []cachedKey
	refreshing    atomic.Bool
}

// New creates a new BitwardenAgent with keyring + in-memory fallback session management.
func New(keyringDesc string, logger *slog.Logger) *BitwardenAgent {
	if logger == nil {
		logger = slog.Default()
	}
	return &BitwardenAgent{
		store:  newSessionStore(keyringDesc, logger),
		logger: logger,
	}
}

func (b *BitwardenAgent) runBWWithRetry(args ...string) ([]byte, error) {
	for attempt := 0; attempt < 2; attempt++ {
		session, err := b.store.EnsureSession()
		if err != nil {
			return nil, err
		}

		cmd := exec.Command("bw", args...)
		cmd.Env = append(os.Environ(), "BW_SESSION="+string(session))
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err = cmd.Run()
		zeroBytes(session)

		if err == nil {
			return stdout.Bytes(), nil
		}

		errText := stderr.String()
		if attempt == 0 && isSessionInvalid(errText) {
			b.logger.Warn("Bitwarden session expired or locked; clearing and re-prompting")
			b.store.Clear()
			continue
		}
		return nil, fmt.Errorf("bw %v failed: %w (%s)", args, err, errText)
	}
	return nil, fmt.Errorf("bw %v failed after unlock retry", args)
}

// RefreshCache fetches only public key metadata from Bitwarden and stores it in RAM.
func (b *BitwardenAgent) RefreshCache() error {
	b.refreshing.Store(true)
	defer b.refreshing.Store(false)

	start := time.Now()
	b.logger.Info("refreshing public key cache")

	out, err := b.runBWWithRetry("list", "items")
	if err != nil {
		b.logger.Error("failed to list items from Bitwarden", "err", err)
		return err
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
	b.initialized = true
	b.lastRefreshed = time.Now()
	b.mu.Unlock()

	b.logger.Info("public key cache updated", "count", len(updated), "duration", time.Since(start))
	return nil
}

// maybeTriggerBackgroundRefresh refreshes the cache asynchronously if >30m have elapsed
// and a session is already unlocked (never pops up a surprise prompt in the background).
func (b *BitwardenAgent) maybeTriggerBackgroundRefresh() {
	b.mu.RLock()
	stale := b.initialized && time.Since(b.lastRefreshed) > cacheTTL
	b.mu.RUnlock()

	if !stale || b.refreshing.Load() {
		return
	}

	if sec, ok := b.store.Get(); ok {
		zeroBytes(sec)
		go func() {
			b.logger.Info("cache TTL (30m) exceeded; refreshing public keys in background")
			_ = b.RefreshCache()
		}()
	}
}

func (b *BitwardenAgent) lookupKey(targetBlob []byte) (string, string) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, k := range b.cache {
		if bytes.Equal(k.AgentID.Blob, targetBlob) {
			return k.ID, k.Name
		}
	}
	return "", ""
}

// List serves cached public keys, initializing on first call and triggering background refresh after 30m.
func (b *BitwardenAgent) List() ([]*sshagent.Key, error) {
	b.mu.RLock()
	init := b.initialized
	b.mu.RUnlock()

	if !init {
		if err := b.RefreshCache(); err != nil {
			return nil, err
		}
	} else {
		b.maybeTriggerBackgroundRefresh()
	}

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

	b.mu.RLock()
	init := b.initialized
	lastRef := b.lastRefreshed
	b.mu.RUnlock()

	if !init {
		if err := b.RefreshCache(); err != nil {
			return nil, err
		}
	}

	targetBlob := key.Marshal()
	matchedID, matchedName := b.lookupKey(targetBlob)

	// Self-heal: if key isn't in cache and we haven't refreshed recently, reload cache once
	if matchedID == "" && time.Since(lastRef) > selfHealCooldown {
		b.logger.Info("requested key not in cache; attempting self-heal cache refresh", "key_type", key.Type())
		if err := b.RefreshCache(); err == nil {
			matchedID, matchedName = b.lookupKey(targetBlob)
		}
	}

	if matchedID == "" {
		b.logger.Warn("agent call: Sign rejected (unknown key)", "key_type", key.Type())
		return nil, fmt.Errorf("matching key not found in cache")
	}

	b.logger.Info("agent call: Sign requested", "key_name", matchedName, "item_id", matchedID, "flags", flags)

	if err := authorizeAction("sign SSH challenge with " + matchedName); err != nil {
		b.logger.Warn("polkit authorization denied", "key_name", matchedName, "err", err)
		return nil, err
	}
	b.logger.Info("polkit authorization approved", "key_name", matchedName)

	rawItem, err := b.runBWWithRetry("get", "item", matchedID)
	if err != nil {
		// Self-heal: item ID may have changed if key was recreated in Bitwarden
		b.logger.Warn("bw get item failed; refreshing cache and retrying once", "item_id", matchedID, "err", err)
		if refErr := b.RefreshCache(); refErr == nil {
			if newID, newName := b.lookupKey(targetBlob); newID != "" {
				matchedID, matchedName = newID, newName
				rawItem, err = b.runBWWithRetry("get", "item", matchedID)
			}
		}
		if err != nil {
			b.logger.Error("bw get item failed after self-heal", "item_id", matchedID, "err", err)
			return nil, err
		}
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

// Lock clears the stored Bitwarden session and wipes the in-memory public key cache.
func (b *BitwardenAgent) Lock(passphrase []byte) error {
	b.store.Clear()
	b.mu.Lock()
	b.cache = nil
	b.initialized = false
	b.lastRefreshed = time.Time{}
	b.mu.Unlock()
	b.logger.Info("agent call: Lock cleared stored Bitwarden session and public key cache")
	return nil
}

// Unlock delegates authorization to Polkit, unlocks Bitwarden interactively, and refreshes the cache.
func (b *BitwardenAgent) Unlock(passphrase []byte) error {
	b.logger.Info("agent call: Unlock requested")
	if err := b.RefreshCache(); err != nil {
		b.logger.Error("agent call: Unlock failed", "err", err)
		return err
	}
	b.logger.Info("agent call: Unlock completed and cache refreshed")
	return nil
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
func (b *BitwardenAgent) Signers() ([]ssh.Signer, error) {
	return nil, fmt.Errorf("unsupported")
}
func (b *BitwardenAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	b.logger.Info("agent call: Extension (unsupported)", "type", extensionType)
	return nil, sshagent.ErrExtensionUnsupported
}
