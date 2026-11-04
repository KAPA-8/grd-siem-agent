package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grd-platform/grd-siem-agent/internal/config"
)

func TestCheckpointPath_PerConnection(t *testing.T) {
	cfg := &config.Config{
		SIEM:   config.SIEMConfig{ConnectionID: "3f6c1d2e-8a4b-4c5d-9e6f-7a8b9c0d1e2f"},
		Buffer: config.BufferConfig{Path: "/var/lib/grd-siem-agent/buffer.db"},
	}
	want := filepath.Join("/var/lib/grd-siem-agent", ".grd-agent-checkpoint-3f6c1d2e-8a4b-4c5d-9e6f-7a8b9c0d1e2f")
	if got := config.CheckpointPath(cfg); got != want {
		t.Errorf("CheckpointPath = %s, want %s", got, want)
	}
	if got := config.LegacyCheckpointPath(cfg); got != filepath.Join("/var/lib/grd-siem-agent", ".grd-agent-checkpoint") {
		t.Errorf("LegacyCheckpointPath = %s", got)
	}
	cfg.SIEM.ConnectionID = "../../etc/passwd"
	if got := filepath.Base(config.CheckpointPath(cfg)); got != ".grd-agent-checkpoint-______etc_passwd" {
		t.Errorf("unsafe connection id produced %s", got)
	}
}

func TestCheckpointStore_SaveIsAtomicAndLoadTrims(t *testing.T) {
	dir := t.TempDir()
	store := &checkpointStore{path: filepath.Join(dir, ".grd-agent-checkpoint-c1")}
	if got := store.Load(); got != "" {
		t.Fatalf("Load on an empty dir = %q", got)
	}
	for _, cp := range []string{`{"v":1,"mode":"alerts","ts":1,"ids":["a"]}`, "1793196390000"} {
		if err := store.Save(cp); err != nil {
			t.Fatal(err)
		}
		if got := store.Load(); got != cp {
			t.Errorf("Load = %q, want %q", got, cp)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("directory holds %v, want only the checkpoint (no temporary files)", names)
	}
	if err := os.WriteFile(store.path, []byte("  cp-with-newline\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := store.Load(); got != "cp-with-newline" {
		t.Errorf("Load = %q", got)
	}
}

func TestCheckpointStore_LegacyFileIsUsedOnceForUpgrades(t *testing.T) {
	dir := t.TempDir()
	store := &checkpointStore{
		path:       filepath.Join(dir, ".grd-agent-checkpoint-c1"),
		legacyPath: filepath.Join(dir, ".grd-agent-checkpoint"),
	}
	if err := os.WriteFile(store.legacyPath, []byte("1700000000000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := store.Load(); got != "1700000000000" {
		t.Fatalf("Load = %q, want the legacy checkpoint", got)
	}
	if err := store.Save("1700000005000"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.legacyPath); !os.IsNotExist(err) {
		t.Errorf("legacy file still present after saving the per-connection file: %v", err)
	}
	if got := store.Load(); got != "1700000005000" {
		t.Errorf("Load = %q", got)
	}
}

func TestCheckpointStore_SaveErrorKeepsOldFile(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	store := &checkpointStore{path: filepath.Join(blocker, "cp")}
	if err := store.Save("x"); err == nil || !strings.Contains(err.Error(), "checkpoint") {
		t.Errorf("err = %v", err)
	}
}
