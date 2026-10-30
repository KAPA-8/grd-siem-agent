package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"

	"github.com/spf13/viper"
)

// Config is the root configuration for the GRD SIEM Agent.
type Config struct {
	Agent     AgentConfig     `mapstructure:"agent"`
	Platform  PlatformConfig  `mapstructure:"platform"`
	SIEM      SIEMConfig      `mapstructure:"siem"`
	Sync      SyncConfig      `mapstructure:"sync"`
	Buffer    BufferConfig    `mapstructure:"buffer"`
	Logging   LoggingConfig   `mapstructure:"logging"`
	Heartbeat HeartbeatConfig `mapstructure:"heartbeat"`
	Update    UpdateConfig    `mapstructure:"update"`
}

type AgentConfig struct {
	ID       string `mapstructure:"id"`
	Name     string `mapstructure:"name"`
	Hostname string `mapstructure:"hostname"`
}

type PlatformConfig struct {
	URL        string `mapstructure:"url"`
	AgentToken string `mapstructure:"agent_token"` // grd_agent_xxx token from GRD Dashboard
}

type SIEMConfig struct {
	Type         string           `mapstructure:"type"`          // registered collector: qradar | stellar_cyber
	APIURL       string           `mapstructure:"api_url"`       // SIEM API base URL
	ConnectionID string           `mapstructure:"connection_id"` // Platform connection UUID
	Deployment   string           `mapstructure:"deployment"`    // stellar_cyber: saas (default) | onprem
	DataSource   string           `mapstructure:"data_source"`   // stellar_cyber: alerts (default) | cases
	Credentials  CredentialConfig `mapstructure:"credentials"`
}

type CredentialConfig struct {
	Username    string `mapstructure:"username"`     // stellar_cyber api_token mode: account email (case-sensitive)
	APIKey      string `mapstructure:"api_key"`      // QRadar SEC token / Stellar Cyber API token or scoped key
	AuthMode    string `mapstructure:"auth_mode"`    // stellar_cyber: api_token (default) | scoped_key
	TenantID    string `mapstructure:"tenant_id"`    // stellar_cyber: optional tenant (cust_id) filter
	ValidateSSL bool   `mapstructure:"validate_ssl"` // verify the SIEM certificate (always on for Stellar Cyber SaaS)
	CACertFile  string `mapstructure:"ca_cert_file"` // optional PEM bundle trusted in addition to the system roots
	APIVersion  string `mapstructure:"api_version"`  // QRadar API version (default: "19.0")
}

type SyncConfig struct {
	IntervalMinutes  int     `mapstructure:"interval_minutes"`
	LookbackDays     int     `mapstructure:"lookback_days"`
	MaxAlertsPerSync int     `mapstructure:"max_alerts_per_sync"`
	Filters          Filters `mapstructure:"filters"`
}

type Filters struct {
	MinSeverity string `mapstructure:"min_severity"`
}

type BufferConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	Path      string `mapstructure:"path"`
	MaxSizeMB int    `mapstructure:"max_size_mb"`
}

type LoggingConfig struct {
	Level     string `mapstructure:"level"`
	Path      string `mapstructure:"path"`
	MaxSizeMB int    `mapstructure:"max_size_mb"`
}

type HeartbeatConfig struct {
	IntervalSeconds int `mapstructure:"interval_seconds"`
}

type UpdateConfig struct {
	Enabled              bool   `mapstructure:"enabled"`
	CheckIntervalHours   int    `mapstructure:"check_interval_hours"`
	CheckIntervalMinutes int    `mapstructure:"check_interval_minutes"`
	GitHubRepo           string `mapstructure:"github_repo"`
	AllowPrerelease      bool   `mapstructure:"allow_prerelease"`
}

// siemValidator validates the siem section against the collector registry.
// The collector package installs it from its init(); config cannot import the
// registry directly because collectors depend on config.
var siemValidator func(SIEMConfig) error

// SetSIEMValidator installs the function that validates siem.type and the
// type-specific settings. Called by the collector registry at init.
func SetSIEMValidator(fn func(SIEMConfig) error) {
	siemValidator = fn
}

// EnvPrefix is the prefix of the environment variables that override
// configuration keys: platform.agent_token -> GRD_PLATFORM_AGENT_TOKEN.
const EnvPrefix = "GRD"

// EnvVarName returns the environment variable that overrides a key.
func EnvVarName(key string) string {
	return EnvPrefix + "_" + strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
}

// Load reads the configuration from the given YAML file path,
// applies defaults, binds environment variables, and validates.
func Load(path string) (*Config, error) {
	cfg, err := read(path)
	if err != nil {
		return nil, err
	}
	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}
	return cfg, nil
}

// LoadMinimal loads config without run-mode validation (for the update command).
func LoadMinimal(path string) (*Config, error) {
	return read(path)
}

func read(path string) (*Config, error) {
	v := viper.New()

	setDefaults(v)

	v.SetConfigFile(path)
	v.SetConfigType("yaml")

	if err := bindEnv(v); err != nil {
		return nil, err
	}

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	normalize(&cfg)
	return &cfg, nil
}

// bindEnv binds every configuration key to its GRD_ environment variable.
// viper's AutomaticEnv alone only applies to keys it already knows from the
// file or a default, so a secret set only in the environment (for example
// GRD_PLATFORM_AGENT_TOKEN with no agent_token key in the YAML) was ignored.
func bindEnv(v *viper.Viper) error {
	for _, key := range Keys() {
		if err := v.BindEnv(key, EnvVarName(key)); err != nil {
			return fmt.Errorf("binding %s: %w", EnvVarName(key), err)
		}
	}
	return nil
}

// Keys returns every configuration key (e.g. "siem.credentials.api_key"),
// derived from the mapstructure tags of Config so new keys are never missed.
func Keys() []string {
	return keysOf(reflect.TypeOf(Config{}), "")
}

func keysOf(t reflect.Type, prefix string) []string {
	var keys []string
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tag := strings.Split(field.Tag.Get("mapstructure"), ",")[0]
		if tag == "" || tag == "-" {
			continue
		}
		key := tag
		if prefix != "" {
			key = prefix + "." + tag
		}
		if field.Type.Kind() == reflect.Struct {
			keys = append(keys, keysOf(field.Type, key)...)
		} else {
			keys = append(keys, key)
		}
	}
	return keys
}

// normalize trims values where stray whitespace (a newline at the end of an
// environment variable or a pasted token) would break requests.
func normalize(cfg *Config) {
	for _, s := range []*string{
		&cfg.Platform.URL,
		&cfg.Platform.AgentToken,
		&cfg.SIEM.Type,
		&cfg.SIEM.APIURL,
		&cfg.SIEM.ConnectionID,
		&cfg.SIEM.Deployment,
		&cfg.SIEM.DataSource,
		&cfg.SIEM.Credentials.Username,
		&cfg.SIEM.Credentials.APIKey,
		&cfg.SIEM.Credentials.AuthMode,
		&cfg.SIEM.Credentials.TenantID,
		&cfg.SIEM.Credentials.CACertFile,
		&cfg.Sync.Filters.MinSeverity,
	} {
		*s = strings.TrimSpace(*s)
	}
	cfg.SIEM.Type = strings.ToLower(cfg.SIEM.Type)
	cfg.Sync.Filters.MinSeverity = strings.ToLower(cfg.Sync.Filters.MinSeverity)
}

// checkpointFilePrefix is the checkpoint file name; the per-connection file
// appends "-<connection_id>".
const checkpointFilePrefix = ".grd-agent-checkpoint"

// CheckpointPath returns the checkpoint file for the configured connection:
// <buffer dir>/.grd-agent-checkpoint-<connection_id>. It lives next to the
// buffer (writable by grd-agent) instead of the config directory (typically
// read-only /etc/grd-siem-agent/). One file per connection means a changed
// connection never resumes from another connection's checkpoint.
func CheckpointPath(cfg *Config) string {
	return filepath.Join(checkpointDir(cfg), checkpointFilePrefix+"-"+safeFileName(cfg.SIEM.ConnectionID))
}

// LegacyCheckpointPath is the single checkpoint file used by older agents.
// It is read once when the per-connection file does not exist yet.
func LegacyCheckpointPath(cfg *Config) string {
	return filepath.Join(checkpointDir(cfg), checkpointFilePrefix)
}

func checkpointDir(cfg *Config) string {
	if cfg.Buffer.Path != "" {
		return filepath.Dir(cfg.Buffer.Path)
	}
	return os.TempDir()
}

// safeFileName keeps letters, digits, '-' and '_' (a UUID is unchanged).
func safeFileName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "default"
	}
	return b.String()
}

// MaxAlertsPerSyncLimit is the upper bound of sync.max_alerts_per_sync (the
// Stellar Cyber search window; the agent posts them in chunks of 500).
const MaxAlertsPerSyncLimit = 10000

var (
	uuidPattern     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	validSeverities = map[string]bool{"": true, "info": true, "low": true, "medium": true, "high": true, "critical": true}
)

// validate checks that all required fields are set for run mode. It reports
// every problem at once.
func validate(cfg *Config) error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if cfg.Platform.URL == "" {
		add("platform.url is required")
	} else if err := validatePlatformURL(cfg.Platform.URL); err != nil {
		errs = append(errs, err)
	}
	if cfg.Platform.AgentToken == "" {
		add("platform.agent_token is required (or set %s); copy it from the GRD Dashboard", EnvVarName("platform.agent_token"))
	}

	errsBeforeSIEM := len(errs)
	if cfg.SIEM.Type == "" {
		add("siem.type is required")
	}
	if cfg.SIEM.ConnectionID == "" {
		add("siem.connection_id is required (the connection UUID from the GRD Dashboard)")
	} else if !uuidPattern.MatchString(cfg.SIEM.ConnectionID) {
		add("siem.connection_id must be a UUID (got %q)", cfg.SIEM.ConnectionID)
	}
	if cfg.SIEM.APIURL == "" {
		add("siem.api_url is required")
	}
	if cfg.SIEM.Credentials.APIKey == "" {
		add("siem.credentials.api_key is required (or set %s)", EnvVarName("siem.credentials.api_key"))
	}
	// Type-specific checks (and the registry lookup) once the basics are set.
	if len(errs) == errsBeforeSIEM && siemValidator != nil {
		if err := siemValidator(cfg.SIEM); err != nil {
			errs = append(errs, err)
		}
	}

	if cfg.Sync.IntervalMinutes <= 0 {
		add("sync.interval_minutes must be greater than 0")
	}
	if cfg.Sync.LookbackDays <= 0 {
		add("sync.lookback_days must be greater than 0")
	}
	if cfg.Sync.MaxAlertsPerSync < 1 || cfg.Sync.MaxAlertsPerSync > MaxAlertsPerSyncLimit {
		add("sync.max_alerts_per_sync must be between 1 and %d (got %d)", MaxAlertsPerSyncLimit, cfg.Sync.MaxAlertsPerSync)
	}
	if !validSeverities[cfg.Sync.Filters.MinSeverity] {
		add("sync.filters.min_severity must be one of info, low, medium, high, critical (got %q)", cfg.Sync.Filters.MinSeverity)
	}

	if cfg.Heartbeat.IntervalSeconds <= 0 {
		add("heartbeat.interval_seconds must be greater than 0")
	}
	if cfg.Update.CheckIntervalMinutes < 0 || cfg.Update.CheckIntervalHours < 0 {
		add("update.check_interval_minutes and update.check_interval_hours cannot be negative")
	} else if cfg.Update.Enabled && cfg.Update.CheckIntervalMinutes == 0 && cfg.Update.CheckIntervalHours == 0 {
		add("update.check_interval_minutes (or check_interval_hours) must be greater than 0 when update.enabled is true")
	}

	if cfg.Buffer.Enabled && strings.TrimSpace(cfg.Buffer.Path) == "" {
		add("buffer.path is required when buffer.enabled is true")
	}

	return errors.Join(errs...)
}

// validatePlatformURL requires https, except for a local platform
// (localhost or a loopback address) during development.
func validatePlatformURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("platform.url %q is not a valid URL", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if strings.EqualFold(host, "localhost") {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
		return fmt.Errorf("platform.url must use https; http is only allowed for localhost (got %q)", raw)
	default:
		return fmt.Errorf("platform.url must use https (got %q)", raw)
	}
}
