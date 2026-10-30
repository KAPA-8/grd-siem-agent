package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

const validYAML = `
agent:
  id: "agent-1"
platform:
  url: "https://grd.example.com"
  agent_token: "grd_agent_yaml"
siem:
  type: "stellar_cyber"
  connection_id: "3f6c1d2e-8a4b-4c5d-9e6f-7a8b9c0d1e2f"
  api_url: "https://acme.stellarcyber.cloud"
  credentials:
    username: "api@acme.com"
    api_key: "yaml-key"
`

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// isolateEnv blanks every GRD_ variable (viper ignores empty ones) so the
// host environment cannot leak into the tests.
func isolateEnv(t *testing.T) {
	t.Helper()
	for _, key := range Keys() {
		t.Setenv(EnvVarName(key), "")
	}
}

// stubSIEMValidator stands in for the collector registry.
func stubSIEMValidator(t *testing.T) *int {
	t.Helper()
	calls := 0
	prev := siemValidator
	SetSIEMValidator(func(cfg SIEMConfig) error {
		calls++
		if cfg.Type != "qradar" && cfg.Type != "stellar_cyber" {
			return errors.New("siem.type " + cfg.Type + " is not supported")
		}
		return nil
	})
	t.Cleanup(func() { SetSIEMValidator(prev) })
	return &calls
}

func TestEnvVarName(t *testing.T) {
	if got := EnvVarName("siem.credentials.api_key"); got != "GRD_SIEM_CREDENTIALS_API_KEY" {
		t.Errorf("got %s", got)
	}
}

func TestKeysCoverTheSchema(t *testing.T) {
	keys := map[string]bool{}
	for _, k := range Keys() {
		keys[k] = true
	}
	for _, want := range []string{
		"platform.agent_token", "siem.type", "siem.deployment", "siem.data_source",
		"siem.credentials.username", "siem.credentials.api_key", "siem.credentials.auth_mode",
		"siem.credentials.tenant_id", "siem.credentials.validate_ssl", "siem.credentials.ca_cert_file",
		"siem.credentials.api_version", "sync.filters.min_severity", "update.check_interval_hours",
	} {
		if !keys[want] {
			t.Errorf("Keys() is missing %s", want)
		}
	}
}

// B11: a secret set only in the environment, with no key in the YAML, was
// ignored by Unmarshal while validation looked at os.Getenv and passed.
func TestLoad_EnvWithoutYAMLKey(t *testing.T) {
	isolateEnv(t)
	stubSIEMValidator(t)
	yaml := strings.NewReplacer(`  agent_token: "grd_agent_yaml"`+"\n", "", `    api_key: "yaml-key"`+"\n", "").Replace(validYAML)
	if strings.Contains(yaml, "agent_token") || strings.Contains(yaml, "api_key") {
		t.Fatal("test YAML still has the secret keys")
	}
	path := writeConfig(t, yaml)

	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "GRD_PLATFORM_AGENT_TOKEN") {
		t.Fatalf("without the env var: err = %v, want the agent token to be required", err)
	}

	t.Setenv("GRD_PLATFORM_AGENT_TOKEN", "grd_agent_from_env\n")
	t.Setenv("GRD_SIEM_CREDENTIALS_API_KEY", "key-from-env")
	t.Setenv("GRD_SIEM_CREDENTIALS_TENANT_ID", "tenant-from-env")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Platform.AgentToken != "grd_agent_from_env" || cfg.SIEM.Credentials.APIKey != "key-from-env" || cfg.SIEM.Credentials.TenantID != "tenant-from-env" {
		t.Errorf("token=%q key=%q tenant=%q", cfg.Platform.AgentToken, cfg.SIEM.Credentials.APIKey, cfg.SIEM.Credentials.TenantID)
	}
}

func TestLoad_EnvOverridesYAML(t *testing.T) {
	isolateEnv(t)
	stubSIEMValidator(t)
	t.Setenv("GRD_PLATFORM_AGENT_TOKEN", "grd_agent_env")
	t.Setenv("GRD_SYNC_INTERVAL_MINUTES", "30")
	t.Setenv("GRD_SIEM_CREDENTIALS_VALIDATE_SSL", "false")
	t.Setenv("GRD_UPDATE_ENABLED", "false")
	cfg, err := Load(writeConfig(t, validYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Platform.AgentToken != "grd_agent_env" || cfg.Sync.IntervalMinutes != 30 || cfg.SIEM.Credentials.ValidateSSL || cfg.Update.Enabled {
		t.Errorf("cfg = %+v", cfg)
	}
	// Defaults still apply to keys set nowhere.
	if cfg.Sync.LookbackDays != 7 || cfg.Heartbeat.IntervalSeconds != 60 || cfg.Sync.MaxAlertsPerSync != 1000 {
		t.Errorf("defaults lost: %+v", cfg.Sync)
	}
}

// Every key, including ones absent from both the YAML and the defaults, can
// be set through its GRD_ variable.
func TestLoadMinimal_EveryKeyFromEnv(t *testing.T) {
	isolateEnv(t)
	want := map[string]any{}
	for _, key := range Keys() {
		field := fieldByKey(t, reflect.ValueOf(&Config{}).Elem(), key)
		switch field.Kind() {
		case reflect.String:
			want[key] = "env-" + strings.ReplaceAll(key, ".", "-")
			t.Setenv(EnvVarName(key), want[key].(string))
		case reflect.Int:
			want[key] = int64(len(key))
			t.Setenv(EnvVarName(key), strconv.Itoa(len(key)))
		case reflect.Bool:
			// Use the opposite of the default when there is one.
			value := key != "siem.credentials.validate_ssl" && key != "buffer.enabled" && key != "update.enabled"
			want[key] = value
			t.Setenv(EnvVarName(key), map[bool]string{true: "true", false: "false"}[value])
		default:
			t.Fatalf("unsupported kind %s for %s", field.Kind(), key)
		}
	}

	cfg, err := LoadMinimal(writeConfig(t, "agent:\n  name: from-yaml\n"))
	if err != nil {
		t.Fatal(err)
	}
	root := reflect.ValueOf(cfg).Elem()
	for _, key := range Keys() {
		field := fieldByKey(t, root, key)
		var got any
		switch field.Kind() {
		case reflect.String:
			got = field.String()
		case reflect.Int:
			got = field.Int()
		case reflect.Bool:
			got = field.Bool()
		}
		if got != want[key] {
			t.Errorf("%s (%s) = %v, want %v", key, EnvVarName(key), got, want[key])
		}
	}
}

// fieldByKey walks the mapstructure tags of a key.
func fieldByKey(t *testing.T, v reflect.Value, key string) reflect.Value {
	t.Helper()
	for _, part := range strings.Split(key, ".") {
		found := false
		for i := 0; i < v.NumField(); i++ {
			if strings.Split(v.Type().Field(i).Tag.Get("mapstructure"), ",")[0] == part {
				v = v.Field(i)
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("no field for %s", key)
		}
	}
	return v
}

func TestLoad_MissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil || !strings.Contains(err.Error(), "reading config file") {
		t.Errorf("err = %v", err)
	}
}

func validConfig() *Config {
	return &Config{
		Platform: PlatformConfig{URL: "https://grd.example.com", AgentToken: "grd_agent_x"},
		SIEM: SIEMConfig{
			Type:         "stellar_cyber",
			ConnectionID: "3f6c1d2e-8a4b-4c5d-9e6f-7a8b9c0d1e2f",
			APIURL:       "https://acme.stellarcyber.cloud",
			Credentials:  CredentialConfig{Username: "api@acme.com", APIKey: "k"},
		},
		Sync:      SyncConfig{IntervalMinutes: 15, LookbackDays: 7, MaxAlertsPerSync: 1000, Filters: Filters{MinSeverity: "low"}},
		Buffer:    BufferConfig{Enabled: true, Path: "/var/lib/grd-siem-agent/buffer.db"},
		Heartbeat: HeartbeatConfig{IntervalSeconds: 60},
		Update:    UpdateConfig{Enabled: true, CheckIntervalMinutes: 10},
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string // empty = valid
	}{
		{"valid", func(*Config) {}, ""},
		{"platform url required", func(c *Config) { c.Platform.URL = "" }, "platform.url is required"},
		{"platform url must be https", func(c *Config) { c.Platform.URL = "http://grd.example.com" }, "must use https"},
		{"platform url not a url", func(c *Config) { c.Platform.URL = "grd.example.com" }, "not a valid URL"},
		{"platform url scheme", func(c *Config) { c.Platform.URL = "ftp://grd.example.com" }, "must use https"},
		{"http localhost allowed", func(c *Config) { c.Platform.URL = "http://localhost:3000" }, ""},
		{"http loopback v4 allowed", func(c *Config) { c.Platform.URL = "http://127.0.0.1:3000" }, ""},
		{"http loopback v6 allowed", func(c *Config) { c.Platform.URL = "http://[::1]:3000" }, ""},
		{"http lookalike rejected", func(c *Config) { c.Platform.URL = "http://localhost.evil.com" }, "must use https"},
		{"agent token required", func(c *Config) { c.Platform.AgentToken = "" }, "GRD_PLATFORM_AGENT_TOKEN"},
		{"siem type required", func(c *Config) { c.SIEM.Type = "" }, "siem.type is required"},
		{"siem type from registry", func(c *Config) { c.SIEM.Type = "splunk" }, "not supported"},
		{"connection id required", func(c *Config) { c.SIEM.ConnectionID = "" }, "siem.connection_id is required"},
		{"connection id uuid", func(c *Config) { c.SIEM.ConnectionID = "my-connection" }, "must be a UUID"},
		{"api url required", func(c *Config) { c.SIEM.APIURL = "" }, "siem.api_url is required"},
		{"api key required", func(c *Config) { c.SIEM.Credentials.APIKey = "" }, "siem.credentials.api_key is required"},
		{"interval positive", func(c *Config) { c.Sync.IntervalMinutes = 0 }, "sync.interval_minutes"},
		{"interval not negative", func(c *Config) { c.Sync.IntervalMinutes = -5 }, "sync.interval_minutes"},
		{"lookback positive", func(c *Config) { c.Sync.LookbackDays = 0 }, "sync.lookback_days"},
		{"max alerts min", func(c *Config) { c.Sync.MaxAlertsPerSync = 0 }, "between 1 and 10000"},
		{"max alerts max", func(c *Config) { c.Sync.MaxAlertsPerSync = 10001 }, "between 1 and 10000"},
		{"max alerts 1", func(c *Config) { c.Sync.MaxAlertsPerSync = 1 }, ""},
		{"max alerts 10000", func(c *Config) { c.Sync.MaxAlertsPerSync = 10000 }, ""},
		{"min severity", func(c *Config) { c.Sync.Filters.MinSeverity = "severe" }, "min_severity"},
		{"min severity empty", func(c *Config) { c.Sync.Filters.MinSeverity = "" }, ""},
		{"heartbeat positive", func(c *Config) { c.Heartbeat.IntervalSeconds = 0 }, "heartbeat.interval_seconds"},
		{"update interval when enabled", func(c *Config) { c.Update.CheckIntervalMinutes = 0 }, "update.check_interval_minutes"},
		{"update hours only", func(c *Config) { c.Update.CheckIntervalMinutes, c.Update.CheckIntervalHours = 0, 6 }, ""},
		{"update disabled", func(c *Config) { c.Update.Enabled, c.Update.CheckIntervalMinutes = false, 0 }, ""},
		{"update negative", func(c *Config) { c.Update.CheckIntervalHours = -1 }, "cannot be negative"},
		{"buffer path", func(c *Config) { c.Buffer.Path = " " }, "buffer.path"},
		{"buffer disabled needs no path", func(c *Config) { c.Buffer.Enabled, c.Buffer.Path = false, "" }, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubSIEMValidator(t)
			cfg := validConfig()
			tt.mutate(cfg)
			err := validate(cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
			if strings.Contains(err.Error(), "register") {
				t.Errorf("stale 'register' hint in %q", err)
			}
		})
	}
}

func TestValidate_ReportsEveryProblemAndSkipsTypeChecksUntilBasicsAreSet(t *testing.T) {
	calls := stubSIEMValidator(t)
	cfg := validConfig()
	cfg.Platform.AgentToken = ""
	cfg.SIEM.Credentials.APIKey = ""
	cfg.Heartbeat.IntervalSeconds = 0
	err := validate(cfg)
	for _, want := range []string{"agent_token", "api_key", "heartbeat"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, missing %q", err, want)
		}
	}
	if *calls != 0 {
		t.Errorf("type validator called %d times despite missing siem basics", *calls)
	}
	cfg.SIEM.Credentials.APIKey = "k"
	_ = validate(cfg)
	if *calls != 1 {
		t.Errorf("type validator calls = %d, want 1", *calls)
	}
}

func TestLoad_NormalizesValues(t *testing.T) {
	isolateEnv(t)
	stubSIEMValidator(t)
	yaml := strings.Replace(validYAML, `type: "stellar_cyber"`, `type: " Stellar_Cyber "`, 1) + "sync:\n  filters:\n    min_severity: \"HIGH\"\n"
	cfg, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SIEM.Type != "stellar_cyber" || cfg.Sync.Filters.MinSeverity != "high" {
		t.Errorf("type=%q min_severity=%q", cfg.SIEM.Type, cfg.Sync.Filters.MinSeverity)
	}
}
