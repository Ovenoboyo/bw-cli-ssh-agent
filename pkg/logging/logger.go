package logging

import (
	"io"
	"log/slog"
	"os"
)

// Setup initializes the default structured logger, optionally writing to logFile.
// It returns the configured logger and a cleanup function to close any opened file.
func Setup(logFile string) (*slog.Logger, func(), error) {
	var out io.Writer = os.Stderr
	var cleanup func()

	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return nil, nil, err
		}
		out = f
		cleanup = func() { _ = f.Close() }
	}

	logger := slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	return logger, cleanup, nil
}
