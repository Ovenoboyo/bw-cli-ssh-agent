package agent

import (
	"log/slog"
	"sync"
)

type sessionStore struct {
	desc       string
	logger     *slog.Logger
	useKeyring bool

	mu        sync.Mutex
	unlockMu  sync.Mutex
	memSecret []byte
}

func newSessionStore(desc string, logger *slog.Logger) *sessionStore {
	if desc == "" {
		desc = DefaultKeyringDesc
	}
	if logger == nil {
		logger = slog.Default()
	}

	useKeyring := hasKeyctl()
	if !useKeyring {
		logger.Warn("keyctl not installed; falling back to keeping BW_SESSION in memory")
	}

	return &sessionStore{
		desc:       desc,
		logger:     logger,
		useKeyring: useKeyring,
	}
}

// Get returns a copy of the cached session token if present in keyring or memory.
func (s *sessionStore) Get() ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.useKeyring {
		if sec, err := readKeyringRaw(s.desc); err == nil && len(sec) > 0 {
			return sec, true
		}
	}

	if len(s.memSecret) > 0 {
		cp := make([]byte, len(s.memSecret))
		copy(cp, s.memSecret)
		return cp, true
	}
	return nil, false
}

// Set persists the session token to the kernel keyring, falling back to RAM with a warning on failure.
func (s *sessionStore) Set(session []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.useKeyring {
		if err := writeKeyringRaw(s.desc, session); err == nil {
			zeroBytes(s.memSecret)
			s.memSecret = nil
			return
		} else {
			s.logger.Warn("failed to store session in kernel keyring; falling back to memory", "err", err)
			s.useKeyring = false
		}
	}

	zeroBytes(s.memSecret)
	s.memSecret = make([]byte, len(session))
	copy(s.memSecret, session)
}

// Clear wipes any stored session token (used when bw reports the token expired or Lock() is called).
func (s *sessionStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	zeroBytes(s.memSecret)
	s.memSecret = nil

	if s.useKeyring {
		_, _ = unlinkKeyringRaw(s.desc)
	}
}

func (s *sessionStore) storageBackendName() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.useKeyring {
		return "kernel-keyring"
	}
	return "memory"
}

// EnsureSession returns a valid BW_SESSION, blocking on an interactive prompt to login/unlock if needed.
func (s *sessionStore) EnsureSession() ([]byte, error) {
	if sec, ok := s.Get(); ok {
		return sec, nil
	}

	// Serialize interactive prompts so concurrent ssh calls wait for a single unlock dialog
	s.unlockMu.Lock()
	defer s.unlockMu.Unlock()

	if sec, ok := s.Get(); ok {
		return sec, nil
	}

	s.logger.Info("no active Bitwarden session found; prompting user to unlock")

	status, err := checkBWStatus()
	if err != nil {
		return nil, err
	}

	if status == "unauthenticated" {
		if err := loginInteractive(s); err != nil {
			return nil, err
		}
	}

	session, err := unlockInteractive(s)
	if err != nil {
		return nil, err
	}

	s.Set(session)
	s.logger.Info("Bitwarden vault unlocked and session stored", "storage", s.storageBackendName())
	return session, nil
}
