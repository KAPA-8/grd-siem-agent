package config

import "github.com/spf13/viper"

// setDefaults configures sensible default values for all config fields.
func setDefaults(v *viper.Viper) {
	// Agent
	v.SetDefault("agent.name", "GRD SIEM Agent")
	v.SetDefault("agent.hostname", "")

	// Sync
	v.SetDefault("sync.interval_minutes", 15)
	v.SetDefault("sync.lookback_days", 7)
	v.SetDefault("sync.max_alerts_per_sync", 1000)
	v.SetDefault("sync.filters.min_severity", "low")

	// SIEM credentials
	v.SetDefault("siem.credentials.validate_ssl", true)

	// Buffer
	v.SetDefault("buffer.enabled", true)
	v.SetDefault("buffer.path", "./buffer.db")
	v.SetDefault("buffer.max_size_mb", 500)

	// Logging
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.path", "")
	v.SetDefault("logging.max_size_mb", 100)

	// Heartbeat
	v.SetDefault("heartbeat.interval_seconds", 60)

	// Self-update from GitHub Releases
	v.SetDefault("update.enabled", true)
	v.SetDefault("update.check_interval_hours", 6)
	v.SetDefault("update.github_repo", "grd-platform/grd-siem-agent")
	v.SetDefault("update.allow_prerelease", false)
}
