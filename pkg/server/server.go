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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/Ovenoboyo/bw-cli-ssh-agent/pkg/agent"
	sshagent "golang.org/x/crypto/ssh/agent"
)

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
	if err != nil {
		return fmt.Errorf("invalid pid in %s: %w", pidFile, err)
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

	_ = os.Remove(cfg.SocketPath)

	listener, err := net.Listen("unix", cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on unix socket %s: %w", cfg.SocketPath, err)
	}
	if err := os.Chmod(cfg.SocketPath, 0600); err != nil {
		listener.Close()
		_ = os.Remove(cfg.SocketPath)
		return fmt.Errorf("failed to chmod socket %s: %w", cfg.SocketPath, err)
	}

	if cfg.PidFile != "" {
		_ = os.WriteFile(cfg.PidFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0600)
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

		connID := connSeq.Add(1)
		wg.Add(1)
		go func(c net.Conn, id uint64) {
			defer wg.Done()
			defer c.Close()

			logger.Info("client connected", "conn_id", id)
			if err := sshagent.ServeAgent(bwAgent, c); err != nil && !errors.Is(err, io.EOF) {
				logger.Error("agent protocol error", "conn_id", id, "err", err)
			}
			logger.Info("client disconnected", "conn_id", id)
		}(conn, connID)
	}

	wg.Wait()
	_ = os.Remove(cfg.SocketPath)
	logger.Info("shutdown complete")
	return nil
}
