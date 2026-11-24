package fortisiem

import (
	"strings"
	"testing"

	"github.com/grd-platform/grd-siem-agent/internal/config"
)

func TestNormalizeBaseURL(t *testing.T) {
	tests := map[string]string{
		"https://ID-fsm.REGION.fortisoc.forticloud.com":           "https://id-fsm.region.fortisoc.forticloud.com",
		"  https://supervisor.example.com/  ":                     "https://supervisor.example.com",
		"supervisor.example.com":                                  "https://supervisor.example.com",
		"https://10.0.0.10/phoenix/rest/pub/incident":             "https://10.0.0.10",
		"https://10.0.0.10:8443/PHOENIX/":                         "https://10.0.0.10:8443",
		"https://supervisor.example.com/fsm/phoenix/rest/x?y=1#z": "https://supervisor.example.com/fsm",
		"http://supervisor.example.com":                           "http://supervisor.example.com",
		"https://supervisor.example.com/phoenixfoo":               "https://supervisor.example.com/phoenixfoo",
	}
	for in, want := range tests {
		got, err := NormalizeBaseURL(in)
		if err != nil || got != want {
			t.Errorf("NormalizeBaseURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "ftp://x", "https://", "https://user:pw@supervisor.example.com"} {
		if _, err := NormalizeBaseURL(bad); err == nil {
			t.Errorf("NormalizeBaseURL(%q) accepted", bad)
		}
	}
}

func siemConfig(mutate func(*config.SIEMConfig)) config.SIEMConfig {
	cfg := config.SIEMConfig{
		Type:   Name,
		APIURL: "https://supervisor.example.com",
		Credentials: config.CredentialConfig{
			Username: "apiuser", Password: "secret", ValidateSSL: true, SecurityOnly: true,
		},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	return cfg
}

func TestResolveSettings_Defaults(t *testing.T) {
	s, err := resolveSettings(siemConfig(nil))
	if err != nil {
		t.Fatal(err)
	}
	if s.deployment != deploymentCloud || s.authMode != authModeBasic || !s.securityOnly || s.baseURL != "https://supervisor.example.com" {
		t.Errorf("settings = %+v", s)
	}
	if got := basicUser(s.organization, s.username); got != "super/apiuser" {
		t.Errorf("basic user = %q, want the super organization by default", got)
	}
	// The password keeps spaces and special characters.
	s, err = resolveSettings(siemConfig(func(c *config.SIEMConfig) { c.Credentials.Password = ` p:a$s"w'o@r/d ` }))
	if err != nil || s.password != ` p:a$s"w'o@r/d ` {
		t.Errorf("password = %q, %v", s.password, err)
	}
}

func TestResolveSettings_Errors(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*config.SIEMConfig)
		want   string
	}{
		{"deployment", func(c *config.SIEMConfig) { c.Deployment = "saas" }, "siem.deployment debe ser cloud u onprem"},
		{"auth mode", func(c *config.SIEMConfig) { c.Credentials.AuthMode = "token" }, "auth_mode debe ser basic u oauth"},
		{"username", func(c *config.SIEMConfig) { c.Credentials.Username = "" }, "username es obligatorio"},
		{"username colon", func(c *config.SIEMConfig) { c.Credentials.Username = "a:b" }, "no puede contener ':'"},
		{"organization", func(c *config.SIEMConfig) { c.Credentials.Organization = "super/x" }, "organization no puede contener"},
		{"password", func(c *config.SIEMConfig) { c.Credentials.Password = "" }, "GRD_SIEM_PASSWORD"},
		{"client id", func(c *config.SIEMConfig) { c.Credentials.AuthMode = "oauth" }, "client_id es obligatorio"},
		{"client secret", func(c *config.SIEMConfig) { c.Credentials.AuthMode = "OAuth"; c.Credentials.ClientID = "x" }, "GRD_SIEM_CLIENT_SECRET"},
		{"cloud http", func(c *config.SIEMConfig) { c.APIURL = "http://x.example.com" }, "debe usar https con FortiSIEM Cloud"},
		{"tenant", func(c *config.SIEMConfig) { c.Credentials.TenantID = strings.Repeat("x", 256) }, "tenant_id"},
		{"url", func(c *config.SIEMConfig) { c.APIURL = "" }, "siem.api_url es obligatorio"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(siemConfig(tt.mutate))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}
	// On-prem accepts http (a lab Supervisor) and OAuth with both fields.
	if err := ValidateConfig(siemConfig(func(c *config.SIEMConfig) { c.Deployment = "onprem"; c.APIURL = "http://10.0.0.10" })); err != nil {
		t.Errorf("onprem http: %v", err)
	}
	if err := ValidateConfig(siemConfig(func(c *config.SIEMConfig) {
		c.Credentials = config.CredentialConfig{AuthMode: "oauth", ClientID: "id", ClientSecret: "s"}
	})); err != nil {
		t.Errorf("oauth: %v", err)
	}
}

func TestMinSeverityFor(t *testing.T) {
	for in, want := range map[string]string{"": "", "info": "", "LOW": "low", "critical": "critical"} {
		if got, err := minSeverityFor(in); err != nil || got != want {
			t.Errorf("minSeverityFor(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := minSeverityFor("severe"); err == nil {
		t.Error("invalid severity accepted")
	}
}
