package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grd-platform/grd-siem-agent/internal/config"

	// Real collectors register their validators.
	_ "github.com/grd-platform/grd-siem-agent/internal/collector/fortisiem"
	_ "github.com/grd-platform/grd-siem-agent/internal/collector/qradar"
	_ "github.com/grd-platform/grd-siem-agent/internal/collector/stellarcyber"
)

func load(t *testing.T, yaml string) (*config.Config, error) {
	t.Helper()
	for _, key := range config.Keys() {
		for _, name := range config.EnvVarNames(key) {
			t.Setenv(name, "")
		}
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

const fortisiemYAML = `
platform:
  url: "https://grd.example.com"
  agent_token: "grd_agent_x"
siem:
  type: fortisiem
  connection_id: "3f6c1d2e-8a4b-4c5d-9e6f-7a8b9c0d1e2f"
  api_url: "https://10.0.0.10"
  deployment: onprem
  credentials:
    organization: "super"
    username: "apiuser"
    PASSWORD_LINE
    validate_ssl: false
`

func TestLoad_FortiSIEM(t *testing.T) {
	cfg, err := load(t, strings.Replace(fortisiemYAML, "PASSWORD_LINE", `password: ' p:a$s"w''o@r/d '`, 1))
	if err != nil {
		t.Fatal(err)
	}
	cred := cfg.SIEM.Credentials
	if cred.Password != ` p:a$s"w'o@r/d ` || !cred.SecurityOnly || cred.APIKey != "" || cfg.Sync.StatusRefreshHours != 6 {
		t.Errorf("credentials = %+v, status_refresh_hours = %d", cred, cfg.Sync.StatusRefreshHours)
	}

	// The password may come from GRD_SIEM_PASSWORD, and no api_key is needed.
	yaml := strings.Replace(fortisiemYAML, "PASSWORD_LINE", "", 1)
	if _, err := load(t, yaml); err == nil || !strings.Contains(err.Error(), "GRD_SIEM_PASSWORD") || strings.Contains(err.Error(), "api_key") {
		t.Errorf("err = %v", err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GRD_SIEM_PASSWORD", "from-env:$x\n")
	cfg, err = config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SIEM.Credentials.Password != "from-env:$x" {
		t.Errorf("password = %q", cfg.SIEM.Credentials.Password)
	}
	// The canonical variable wins over the alias.
	t.Setenv("GRD_SIEM_CREDENTIALS_PASSWORD", "canonical")
	if cfg, err = config.Load(path); err != nil || cfg.SIEM.Credentials.Password != "canonical" {
		t.Errorf("password = %q, %v", cfg.SIEM.Credentials.Password, err)
	}
}

func TestLoad_FortiSIEMOAuthSecretFromEnv(t *testing.T) {
	yaml := strings.NewReplacer("PASSWORD_LINE", "", "    organization: \"super\"\n", "", "    username: \"apiuser\"\n", "    auth_mode: oauth\n    client_id: \"cid\"\n").Replace(fortisiemYAML)
	if _, err := load(t, yaml); err == nil || !strings.Contains(err.Error(), "GRD_SIEM_CLIENT_SECRET") {
		t.Fatalf("err = %v", err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GRD_SIEM_CLIENT_SECRET", "secret-from-env")
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SIEM.Credentials.ClientSecret != "secret-from-env" || cfg.SIEM.Credentials.AuthMode != "oauth" {
		t.Errorf("credentials = %+v", cfg.SIEM.Credentials)
	}
}
