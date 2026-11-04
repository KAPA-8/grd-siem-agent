package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grd-platform/grd-siem-agent/internal/config"
)

func writeTestConfig(t *testing.T, yaml string) string {
	t.Helper()
	for _, key := range config.Keys() {
		t.Setenv(config.EnvVarName(key), "")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml = strings.ReplaceAll(yaml, "DATA_DIR", filepath.ToSlash(dir))
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const stellarConfig = `
platform:
  url: "https://grd.example.com"
  agent_token: "grd_agent_x"
siem:
  type: stellar_cyber
  connection_id: "3f6c1d2e-8a4b-4c5d-9e6f-7a8b9c0d1e2f"
  api_url: "https://acme.stellarcyber.cloud"
  credentials:
    username: "api@acme.com"
    api_key: "token"
    CA_LINE
buffer:
  path: "DATA_DIR/buffer.db"
`

func runValidate(t *testing.T, path string) (string, error) {
	t.Helper()
	configPath = path
	cmd := validateCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	err := cmd.RunE(cmd, nil)
	return out.String(), err
}

func TestValidateCommand(t *testing.T) {
	out, err := runValidate(t, writeTestConfig(t, strings.Replace(stellarConfig, "CA_LINE", "", 1)))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Config is valid.", "Deployment:    saas", "Data source:   alerts", "Auth mode:     api_token", ".grd-agent-checkpoint-3f6c1d2e"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "token") && strings.Contains(out, "grd_agent_x") {
		t.Error("validate must not print secrets")
	}

	_, err = runValidate(t, writeTestConfig(t, strings.Replace(stellarConfig, "CA_LINE", `ca_cert_file: "/nonexistent/ca.pem"`, 1)))
	if err == nil || !strings.Contains(err.Error(), "ca_cert_file") {
		t.Errorf("missing CA file: err = %v", err)
	}
}
