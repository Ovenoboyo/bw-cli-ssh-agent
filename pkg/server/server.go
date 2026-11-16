package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/Ovenoboyo/bw-cli-ssh-agent/pkg/agent"
	"golang.org/x/sys/unix"
)

const maxConcurrentConns = 16

// Config holds runtime parameters for the SSH agent Unix socket server.
type Config struct {
	SocketPath string
	PidFile    string
	Logger     *slog.Logger
}

// TriggerRefresh reads the running daemon's PID from pidFile and sends SIGHUP to reload its cache.
func TriggerRefresh(pidFile string) error {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return fmt.Errorf("failed to read pid file %s (is bw-ssh-agent running?): %w", pidFile, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return fmt.Errorf("invalid pid in %s", pidFile)
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("process %d not found: %w", pid, err)
	}
	if err := proc.Signal(syscall.SIGHUP); err != nil {
		return fmt.Errorf("failed to send SIGHUP to pid %d: %w", pid, err)
	}
	return nil
}

// Run starts the Unix socket listener, handles SIGHUP cache reloads,
// and shuts down cleanly when ctx is canceled or SIGINT/SIGTERM arrives.
func Run(ctx context.Context, cfg Config, bwAgent *agent.BitwardenAgent) error {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	if err := verifySecureRuntimeDir(filepath.Dir(cfg.SocketPath)); err != nil {
		return err
	}

	_ = os.Remove(cfg.SocketPath)

	// Set umask 0077 before net.Listen to avoid any TOCTOU permission window
	oldUmask := syscall.Umask(0077)
	listener, err := net.Listen("unix", cfg.SocketPath)
	syscall.Umask(oldUmask)
	if err != nil {
		return fmt.Errorf("failed to listen on unix socket %s: %w", cfg.SocketPath, err)
	}
	if err := os.Chmod(cfg.SocketPath, 0600); err != nil {
		listener.Close()
		_ = os.Remove(cfg.SocketPath)
		return fmt.Errorf("failed to chmod socket %s: %w", cfg.SocketPath, err)
	}

	if cfg.PidFile != "" {
		if err := writePidFileSecure(cfg.PidFile, os.Getpid()); err != nil {
			listener.Close()
			_ = os.Remove(cfg.SocketPath)
			return err
		}
		defer os.Remove(cfg.PidFile)
	}

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	defer signal.Stop(sighup)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sighup:
				logger.Info("received SIGHUP, reloading cache")
				if err := bwAgent.RefreshCache(); err != nil {
					logger.Error("cache refresh failed", "err", err)
				}
			}
		}
	}()

	go func() {
		<-ctx.Done()
		logger.Info("shutting down server", "socket", cfg.SocketPath)
		listener.Close()
	}()

	logger.Info("bw-ssh-agent listening", "socket", cfg.SocketPath, "pid", os.Getpid())

	sem := make(chan struct{}, maxConcurrentConns)
	var wg sync.WaitGroup
	var connSeq atomic.Uint64

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				break
			}
			logger.Warn("accept error", "err", err)
			continue
		}

		select {
		case sem <- struct{}{}:
		default:
			logger.Warn("max concurrent connections reached; rejecting client")
			conn.Close()
			continue
		}

		connID := connSeq.Add(1)
		wg.Add(1)
		go func(c net.Conn, id uint64) {
			defer wg.Done()
			defer func() { <-sem }()
			defer c.Close()

			peer, err := inspectPeer(c)
			if err != nil {
				logger.Warn("rejected connection: failed to verify peer credentials", "conn_id", id, "err", err)
				return
			}
			if peer.UID != uint32(os.Getuid()) {
				logger.Warn("rejected connection: UID mismatch", "conn_id", id, "peer_uid", peer.UID, "peer_pid", peer.PID)
				return
			}

			logger.Info("client connected", "conn_id", id, "peer_pid", peer.PID, "peer_comm", peer.Comm)
			if err := bwAgent.ServeConn(c, peer); err != nil && !errors.Is(err, io.EOF) {
				logger.Error("agent protocol error", "conn_id", id, "peer_pid", peer.PID, "err", err)
			}
			logger.Info("client disconnected", "conn_id", id, "peer_pid", peer.PID)
		}(conn, connID)
	}

	wg.Wait()
	_ = os.Remove(cfg.SocketPath)
	logger.Info("shutdown complete")
	return nil
}

func verifySecureRuntimeDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("runtime directory %s inaccessible: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("runtime path %s is not a directory", dir)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if stat.Uid != uint32(os.Getuid()) {
			return fmt.Errorf("runtime directory %s is owned by uid %d, expected %d", dir, stat.Uid, os.Getuid())
		}
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("runtime directory %s has overly permissive mode %o (expected 0700)", dir, info.Mode().Perm())
	}
	return nil
}

func writePidFileSecure(path string, pid int) error {
	_ = os.Remove(path)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return fmt.Errorf("failed to create pid file %s: %w", path, err)
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%d\n", pid)
	return err
}

func inspectPeer(c net.Conn) (agent.PeerInfo, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return agent.PeerInfo{}, fmt.Errorf("connection is not a Unix domain socket")
	}
	rawConn, err := uc.SyscallConn()
	if err != nil {
		return agent.PeerInfo{}, err
	}

	var ucred *unix.Ucred
	var credErr error
	if err := rawConn.Control(func(fd uintptr) {
		ucred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return agent.PeerInfo{}, err
	}
	if credErr != nil {
		return agent.PeerInfo{}, credErr
	}

	comm := "unknown"
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", ucred.Pid)); err == nil {
		comm = strings.TrimSpace(string(data))
	}

	return agent.PeerInfo{
		PID:  ucred.Pid,
		UID:  ucred.Uid,
		GID:  ucred.Gid,
		Comm: comm,
	}, nil
}
