package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/grd-platform/grd-siem-agent/internal/config"
)

func writeTestConfig(t *testing.T, yaml string) string {
	t.Helper()
	for _, key := range config.Keys() {
		for _, name := range config.EnvVarNames(key) {
			t.Setenv(name, "")
		}
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

const fortisiemConfig = `
platform:
  url: "https://grd.example.com"
  agent_token: "grd_agent_x"
siem:
  type: fortisiem
  connection_id: "3f6c1d2e-8a4b-4c5d-9e6f-7a8b9c0d1e2f"
  api_url: "API_URL"
  deployment: onprem
  credentials:
    username: "apiuser"
    password: 'p:a$s"w''o@r/d'
    validate_ssl: false
buffer:
  path: "DATA_DIR/buffer.db"
`

func TestValidateCommand_FortiSIEM(t *testing.T) {
	out, err := runValidate(t, writeTestConfig(t, strings.Replace(fortisiemConfig, "API_URL", "https://10.0.0.10", 1)))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"SIEM Type:     fortisiem", "Deployment:    onprem", "Auth mode:     basic", "User:          super/apiuser", "Security only: true", "Status sweep:  every 6 hours"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "o@r/d") {
		t.Error("validate must not print the password")
	}
}

func runTestSIEM(t *testing.T, path string, args ...string) (string, error) {
	t.Helper()
	configPath = path
	cmd := testSIEMCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := cmd.ParseFlags(args); err != nil {
		t.Fatal(err)
	}
	err := cmd.RunE(cmd, nil)
	return out.String(), err
}

// test-siem needs neither the agent token nor the connection ID, and never
// talks to the platform.
func TestTestSIEMCommand_FortiSIEM(t *testing.T) {
	var gotAuth []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/phoenix/rest/pub/incident" || r.Method != http.MethodPost {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		gotAuth = append(gotAuth, r.Header.Get("Authorization"))
		now := time.Now().UnixMilli()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"start":0,"total":"2","data":[
			{"incidentId":1,"incidentFirstSeen":%d,"incidentLastSeen":%d,"phIncidentCategory":4,"incidentStatus":0,"incidentReso":3,"eventSeverity":"7"},
			{"incidentId":2,"incidentFirstSeen":%d,"incidentLastSeen":%d,"phIncidentCategory":4,"incidentStatus":2,"incidentReso":2,"eventSeverity":9}]}`,
			now-60_000, now-30_000, now-120_000, now-60_000)
	}))
	defer server.Close()

	yaml := strings.NewReplacer(
		"API_URL", server.URL,
		`  agent_token: "grd_agent_x"`+"\n", "",
		`  connection_id: "3f6c1d2e-8a4b-4c5d-9e6f-7a8b9c0d1e2f"`+"\n", "",
	).Replace(fortisiemConfig)
	path := writeTestConfig(t, yaml)
	output := filepath.Join(filepath.Dir(path), "alerts.json")
	out, err := runTestSIEM(t, path, "--collect", "--output", output)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"SIEM connection OK: conexión correcta", "24 h: 2", "Alerts:        2 (status only: 0, discarded at the source: 1)"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	creds, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(gotAuth[0], "Basic "))
	if string(creds) != `super/apiuser:p:a$s"w'o@r/d` {
		t.Errorf("basic credentials = %q", creds)
	}
	data, err := os.ReadFile(output)
	if err != nil || !strings.Contains(string(data), `"sourceStatus": "manually_cleared/true_positive"`) {
		t.Errorf("output file: %v\n%s", err, data)
	}

	// A bad password fails with the organization prefix hint.
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	_, err = runTestSIEM(t, path)
	if err == nil || !strings.Contains(err.Error(), "prefijo de su organización") {
		t.Errorf("err = %v", err)
	}
}
