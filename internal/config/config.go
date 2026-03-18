package config

import (
	"fmt"
	"os"
	"path/filepath"
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
	AgentToken string `mapstructure:"agent_token"` // grd_agent_xxx token from registration
	OrgAPIKey  string `mapstructure:"org_api_key"` // Only used for registration
}

type SIEMConfig struct {
	Type         string           `mapstructure:"type"`
	APIURL       string           `mapstructure:"api_url"`
	ConnectionID string           `mapstructure:"connection_id"` // Platform connection UUID
	Credentials  CredentialConfig `mapstructure:"credentials"`
}

type CredentialConfig struct {
	APIKey      string `mapstructure:"api_key"`
	ValidateSSL bool   `mapstructure:"validate_ssl"`
	APIVersion  string `mapstructure:"api_version"` // QRadar API version (default: "19.0")
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

// Load reads the configuration from the given YAML file path,
// applies defaults, binds environment variables, and validates.
func Load(path string) (*Config, error) {
	v := viper.New()

	setDefaults(v)

	v.SetConfigFile(path)
	v.SetConfigType("yaml")

	// Bind environment variables with GRD_ prefix
	v.SetEnvPrefix("GRD")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}

	return &cfg, nil
}

// LoadMinimal loads config with minimal validation (for register command).
func LoadMinimal(path string) (*Config, error) {
	v := viper.New()

	setDefaults(v)

	v.SetConfigFile(path)
	v.SetConfigType("yaml")

	v.SetEnvPrefix("GRD")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	return &cfg, nil
}

// CheckpointPath returns the path to the checkpoint file.
// It uses the buffer directory (writable by grd-agent) instead of the config
// directory (which is typically read-only /etc/grd-siem-agent/).
func CheckpointPath(cfg *Config) string {
	if cfg.Buffer.Path != "" {
		return filepath.Join(filepath.Dir(cfg.Buffer.Path), ".grd-agent-checkpoint")
	}
	return filepath.Join(os.TempDir(), ".grd-agent-checkpoint")
}

// validate checks that all required fields are set for run mode.
func validate(cfg *Config) error {
	if cfg.Platform.URL == "" {
		return fmt.Errorf("platform.url is required")
	}
	if cfg.Platform.AgentToken == "" {
		if os.Getenv("GRD_PLATFORM_AGENT_TOKEN") == "" {
			return fmt.Errorf("platform.agent_token is required (or set GRD_PLATFORM_AGENT_TOKEN). Run 'grd-siem-agent register' first")
		}
	}
	if cfg.SIEM.Type == "" {
		return fmt.Errorf("siem.type is required")
	}

	validSIEMTypes := map[string]bool{"qradar": true, "splunk": true, "sentinel": true}
	if !validSIEMTypes[cfg.SIEM.Type] {
		return fmt.Errorf("siem.type must be one of: qradar, splunk, sentinel (got: %s)", cfg.SIEM.Type)
	}

	if cfg.Sync.IntervalMinutes < 1 {
		return fmt.Errorf("sync.interval_minutes must be >= 1")
	}

	// SIEM URL and credentials can come from remote config, so only warn
	if cfg.SIEM.APIURL == "" && cfg.SIEM.ConnectionID == "" {
		return fmt.Errorf("either siem.api_url or siem.connection_id is required")
	}

	return nil
}
