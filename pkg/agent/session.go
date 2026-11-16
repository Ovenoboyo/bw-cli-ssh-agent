package agent

import (
	"log/slog"
	"sync"
)

type sessionStore struct {
	desc                  string
	storeMasterPw         bool
	requirePolkitOnUnlock bool
	logger                *slog.Logger
	backend               SecretBackend

	mu        sync.Mutex
	unlockMu  sync.Mutex
	memSecret []byte
}

func newSessionStore(desc string, storeMasterPw, requirePolkitOnUnlock bool, logger *slog.Logger) *sessionStore {
	if desc == "" {
		desc = DefaultSecretKey
	}
	if logger == nil {
		logger = slog.Default()
	}

	backend := DetectSecretBackend()
	if backend == BackendMemory {
		logger.Warn("neither libsecret nor kernel keyring available; falling back to keeping BW_SESSION in memory")
	}

	return &sessionStore{
		desc:                  desc,
		storeMasterPw:         storeMasterPw,
		requirePolkitOnUnlock: requirePolkitOnUnlock,
		logger:                logger,
		backend:               backend,
	}
}

func (s *sessionStore) Get() ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch s.backend {
	case BackendLibsecret:
		if sec, err := readLibsecret(s.desc); err == nil && len(sec) > 0 {
			return sec, true
		}
	case BackendKeyring:
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

func (s *sessionStore) Set(session []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch s.backend {
	case BackendLibsecret:
		if err := writeLibsecret(s.desc, session); err == nil {
			zeroBytes(s.memSecret)
			s.memSecret = nil
			return
		} else {
			s.logger.Warn("failed to store session in libsecret; falling back to memory", "err", err)
			s.backend = BackendMemory
		}
	case BackendKeyring:
		if err := writeKeyringRaw(s.desc, session, sessionKeyTTLSeconds); err == nil {
			zeroBytes(s.memSecret)
			s.memSecret = nil
			return
		} else {
			s.logger.Warn("failed to store session in kernel keyring; falling back to memory", "err", err)
			s.backend = BackendMemory
		}
	}

	zeroBytes(s.memSecret)
	s.memSecret = make([]byte, len(session))
	copy(s.memSecret, session)
}

// ClearSessionOnly wipes BW_SESSION while keeping any cached master password intact.
func (s *sessionStore) ClearSessionOnly() {
	s.mu.Lock()
	defer s.mu.Unlock()

	zeroBytes(s.memSecret)
	s.memSecret = nil

	switch s.backend {
	case BackendLibsecret:
		_ = clearLibsecret(s.desc)
	case BackendKeyring:
		_, _ = unlinkKeyringRaw(s.desc)
	}
}

// ClearAll wipes both BW_SESSION and any cached master password (called on explicit Lock).
func (s *sessionStore) ClearAll() {
	s.mu.Lock()
	defer s.mu.Unlock()

	zeroBytes(s.memSecret)
	s.memSecret = nil

	switch s.backend {
	case BackendLibsecret:
		_ = clearLibsecret(s.desc)
		_ = clearLibsecret(MasterPwSecretKey)
	case BackendKeyring:
		_, _ = unlinkKeyringRaw(s.desc)
		_, _ = unlinkKeyringRaw(MasterPwKeyringDesc)
	}
}

// EnsureSession returns a valid BW_SESSION, prompting interactively if locked/unauthenticated.
func (s *sessionStore) EnsureSession() ([]byte, error) {
	if sec, ok := s.Get(); ok {
		return sec, nil
	}

	s.unlockMu.Lock()
	defer s.unlockMu.Unlock()

	if sec, ok := s.Get(); ok {
		return sec, nil
	}

	if s.requirePolkitOnUnlock {
		s.logger.Info("require_polkit_on_unlock is enabled; requesting Polkit authorization")
		if err := authorizeAction("unlock Bitwarden SSH agent"); err != nil {
			s.logger.Warn("polkit unlock authorization denied", "err", err)
			return nil, err
		}
	}

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
	s.logger.Info("Bitwarden vault unlocked and session stored", "storage", s.backend)
	return session, nil
}
