package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grd-platform/grd-siem-agent/internal/config"

	// Real collectors register their validators.
	_ "github.com/grd-platform/grd-siem-agent/internal/collector/qradar"
	_ "github.com/grd-platform/grd-siem-agent/internal/collector/stellarcyber"
)

func load(t *testing.T, yaml string) (*config.Config, error) {
	t.Helper()
	for _, key := range config.Keys() {
		t.Setenv(config.EnvVarName(key), "")
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return config.Load(path)
}

const stellarYAML = `
platform:
  url: "https://grd.example.com"
  agent_token: "grd_agent_x"
siem:
  type: stellar_cyber
  connection_id: "3f6c1d2e-8a4b-4c5d-9e6f-7a8b9c0d1e2f"
  api_url: "https://acme.stellarcyber.cloud"
  deployment: DEPLOYMENT
  data_source: cases
  credentials:
    username: "api@acme.com"
    api_key: "token"
    auth_mode: api_token
    tenant_id: "t1"
`

func TestLoad_StellarCyberThroughTheRegistry(t *testing.T) {
	cfg, err := load(t, strings.Replace(stellarYAML, "DEPLOYMENT", "saas", 1))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SIEM.Deployment != "saas" || cfg.SIEM.DataSource != "cases" || cfg.SIEM.Credentials.TenantID != "t1" || !cfg.SIEM.Credentials.ValidateSSL {
		t.Errorf("cfg.SIEM = %+v", cfg.SIEM)
	}

	_, err = load(t, strings.Replace(stellarYAML, "DEPLOYMENT", "cloud", 1))
	if err == nil || !strings.Contains(err.Error(), "siem.deployment must be saas or onprem") {
		t.Errorf("err = %v", err)
	}
}

func TestLoad_QRadarStillValid(t *testing.T) {
	yaml := `
platform:
  url: "https://grd.example.com"
  agent_token: "grd_agent_x"
siem:
  type: qradar
  connection_id: "3f6c1d2e-8a4b-4c5d-9e6f-7a8b9c0d1e2f"
  api_url: "https://10.1.11.61"
  credentials:
    api_key: "sec-token"
    validate_ssl: false
`
	if _, err := load(t, yaml); err != nil {
		t.Fatal(err)
	}
}
