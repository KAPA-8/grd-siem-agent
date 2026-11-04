package collector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grd-platform/grd-siem-agent/internal/config"
)

type nopCollector struct{ name string }

func (n nopCollector) Name() string                                 { return n.name }
func (nopCollector) Init(context.Context) error                     { return nil }
func (nopCollector) Collect(context.Context, string) (Batch, error) { return Batch{}, nil }
func (nopCollector) HealthCheck(context.Context) error              { return nil }
func (nopCollector) Close() error                                   { return nil }

func TestRegistry_NewAndValidate(t *testing.T) {
	errBad := errors.New("bad deployment")
	Register("test_registry_a", func(cfg config.SIEMConfig, _ config.SyncConfig) (Collector, error) {
		if cfg.APIURL == "" {
			return nil, errors.New("factory needs api_url")
		}
		return nopCollector{name: "test_registry_a"}, nil
	}, func(cfg config.SIEMConfig) error {
		if cfg.APIURL == "bad" {
			return errBad
		}
		return nil
	})

	if err := ValidateConfig(config.SIEMConfig{Type: "test_registry_a", APIURL: "ok"}); err != nil {
		t.Errorf("ValidateConfig(valid) = %v", err)
	}
	if err := ValidateConfig(config.SIEMConfig{Type: "test_registry_a", APIURL: "bad"}); !errors.Is(err, errBad) {
		t.Errorf("ValidateConfig(bad) = %v, want %v", err, errBad)
	}

	c, err := New(config.SIEMConfig{Type: "test_registry_a", APIURL: "https://x"}, config.SyncConfig{})
	if err != nil || c.Name() != "test_registry_a" {
		t.Fatalf("New = %v, %v", c, err)
	}
	if _, err := New(config.SIEMConfig{Type: "test_registry_a"}, config.SyncConfig{}); err == nil {
		t.Error("expected the factory error to propagate")
	}
}

func TestRegistry_UnknownTypeListsAvailable(t *testing.T) {
	Register("test_registry_b", func(config.SIEMConfig, config.SyncConfig) (Collector, error) {
		return nopCollector{}, nil
	}, nil)

	for _, err := range []error{
		ValidateConfig(config.SIEMConfig{Type: "splunk"}),
		func() error { _, err := New(config.SIEMConfig{Type: "splunk"}, config.SyncConfig{}); return err }(),
	} {
		if err == nil || !strings.Contains(err.Error(), `"splunk" is not supported`) || !strings.Contains(err.Error(), "test_registry_b") {
			t.Errorf("unexpected error: %v", err)
		}
	}
	if err := ValidateConfig(config.SIEMConfig{Type: "test_registry_b"}); err != nil {
		t.Errorf("nil validator should accept, got %v", err)
	}
}

func TestRegistry_RegisteredIsSorted(t *testing.T) {
	Register("test_registry_z", func(config.SIEMConfig, config.SyncConfig) (Collector, error) { return nopCollector{}, nil }, nil)
	Register("test_registry_m", func(config.SIEMConfig, config.SyncConfig) (Collector, error) { return nopCollector{}, nil }, nil)
	names := Registered()
	for i := 1; i < len(names); i++ {
		if names[i-1] > names[i] {
			t.Fatalf("not sorted: %v", names)
		}
	}
}

func TestRegistry_DuplicateRegistrationPanics(t *testing.T) {
	factory := func(config.SIEMConfig, config.SyncConfig) (Collector, error) { return nopCollector{}, nil }
	Register("test_registry_dup", factory, nil)
	defer func() {
		if recover() == nil {
			t.Error("expected a panic on duplicate registration")
		}
	}()
	Register("test_registry_dup", factory, nil)
}

// config.Load validates siem.type through this registry (installed at init).
func TestRegistry_ConfigLoadUsesRegistry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	yaml := `
platform:
  url: "https://grd.example.com"
  agent_token: "grd_agent_x"
siem:
  type: "splunk"
  connection_id: "3f6c1d2e-8a4b-4c5d-9e6f-7a8b9c0d1e2f"
  api_url: "https://siem.example.com"
  credentials:
    api_key: "k"
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := config.Load(path)
	if err == nil || !strings.Contains(err.Error(), `"splunk" is not supported`) {
		t.Fatalf("config.Load error = %v, want unsupported siem.type", err)
	}
}
