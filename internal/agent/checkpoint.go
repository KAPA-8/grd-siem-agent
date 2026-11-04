package agent

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
)

// checkpointStore persists the collector checkpoint for one connection.
type checkpointStore struct {
	path       string
	legacyPath string // pre per-connection file, read once for upgrades
}

// Load returns the stored checkpoint, falling back to the legacy file, or ""
// when there is none.
func (s *checkpointStore) Load() string {
	if cp, ok := s.read(s.path); ok {
		return cp
	}
	if s.legacyPath != "" {
		if cp, ok := s.read(s.legacyPath); ok {
			log.Info().Str("path", s.legacyPath).Msg("resuming from the legacy checkpoint file")
			return cp
		}
	}
	return ""
}

func (s *checkpointStore) read(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			log.Error().Err(err).Str("path", path).Msg("failed to read checkpoint")
		}
		return "", false
	}
	return strings.TrimSpace(string(data)), true
}

// Save writes the checkpoint atomically: a temporary file in the same
// directory is written, fsynced and renamed over the old one, so a crash
// leaves either the old or the new checkpoint, never a truncated file.
// The legacy file is removed once the per-connection file exists.
func (s *checkpointStore) Save(checkpoint string) error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("creating checkpoint directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(s.path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temporary checkpoint: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	if _, err := tmp.WriteString(checkpoint); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("writing checkpoint: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("syncing checkpoint: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("closing checkpoint: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		cleanup()
		return fmt.Errorf("replacing checkpoint: %w", err)
	}
	syncDir(dir)

	if s.legacyPath != "" && s.legacyPath != s.path {
		if err := os.Remove(s.legacyPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
			log.Warn().Err(err).Str("path", s.legacyPath).Msg("could not remove the legacy checkpoint file")
		}
	}
	return nil
}

// syncDir makes the rename durable where the platform supports it (not on
// Windows, where directories cannot be fsynced; the error is ignored).
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	d.Close()
}
