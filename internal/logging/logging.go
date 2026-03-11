package logging

import (
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Setup initializes the global zerolog logger.
// If logPath is empty, logs only to stderr (console).
// If logPath is set, logs JSON to file and human-readable to stderr.
func Setup(level string, logPath string) error {
	// Parse level
	lvl, err := zerolog.ParseLevel(level)
	if err != nil {
		lvl = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(lvl)

	// Console writer for stderr (human-readable)
	consoleWriter := zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
	}

	if logPath == "" {
		log.Logger = zerolog.New(consoleWriter).With().Timestamp().Caller().Logger()
		return nil
	}

	// Ensure log directory exists
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return err
	}

	// Open log file (append mode)
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}

	// Multi-writer: JSON to file + console to stderr
	multi := io.MultiWriter(consoleWriter, logFile)
	log.Logger = zerolog.New(multi).With().Timestamp().Caller().Logger()

	return nil
}
