package qradar

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/grd-platform/grd-siem-agent/internal/collector"
	"github.com/grd-platform/grd-siem-agent/internal/config"
	"github.com/grd-platform/grd-siem-agent/internal/models"
)

// Ensure QRadarCollector implements collector.Collector at compile time.
var _ collector.Collector = (*QRadarCollector)(nil)

// QRadarCollector implements the Collector interface for IBM QRadar.
type QRadarCollector struct {
	client      *Client
	syncCfg     config.SyncConfig
	lookbackMs  int64
	fetchNotes  bool
}

// NewCollector creates a new QRadar collector.
func NewCollector(siemCfg config.SIEMConfig, syncCfg config.SyncConfig) *QRadarCollector {
	client := NewClient(
		siemCfg.APIURL,
		siemCfg.Credentials.APIKey,
		siemCfg.Credentials.ValidateSSL,
		siemCfg.Credentials.APIVersion,
	)

	lookbackMs := time.Duration(syncCfg.LookbackDays) * 24 * time.Hour

	return &QRadarCollector{
		client:     client,
		syncCfg:    syncCfg,
		lookbackMs: lookbackMs.Milliseconds(),
		fetchNotes: true,
	}
}

func (c *QRadarCollector) Name() string {
	return "qradar"
}

// Init validates connectivity to QRadar.
// Tries /api/system/about first; if 403 (insufficient permissions), falls back
// to a minimal offenses query to verify the connection works.
func (c *QRadarCollector) Init(ctx context.Context) error {
	info, err := c.client.GetSystemInfo(ctx)
	if err == nil {
		log.Info().
			Str("version", info.Version).
			Msg("connected to QRadar")
		return nil
	}

	// If system/about fails (common with limited tokens), try fetching 1 offense
	log.Warn().Err(err).Msg("system/about not accessible, verifying via offenses endpoint")

	_, testErr := c.client.GetOffenses(ctx, "", 1)
	if testErr != nil {
		return fmt.Errorf("failed to connect to QRadar: %w (system/about also failed: %v)", testErr, err)
	}

	log.Info().Msg("connected to QRadar (via offenses endpoint)")
	return nil
}

// Collect fetches offenses updated since the checkpoint,
// normalizes them, and returns the new checkpoint.
func (c *QRadarCollector) Collect(ctx context.Context, checkpoint string) ([]models.Alert, string, error) {
	// Determine the epoch_ms threshold
	var sinceMs int64
	if checkpoint != "" {
		parsed, err := strconv.ParseInt(checkpoint, 10, 64)
		if err != nil {
			log.Warn().Str("checkpoint", checkpoint).Msg("invalid checkpoint, using lookback")
			sinceMs = c.defaultCheckpoint()
		} else {
			sinceMs = parsed
		}
	} else {
		sinceMs = c.defaultCheckpoint()
	}

	// Build QRadar filter
	filter := fmt.Sprintf("last_updated_time > %d", sinceMs)

	// Apply severity filter
	if minSev := c.syncCfg.Filters.MinSeverity; minSev != "" {
		sevThreshold := severityToQRadarMin(minSev)
		if sevThreshold > 0 {
			filter += fmt.Sprintf(" and severity >= %d", sevThreshold)
		}
	}

	log.Info().
		Str("filter", filter).
		Int("max_alerts", c.syncCfg.MaxAlertsPerSync).
		Msg("collecting offenses from QRadar")

	// Fetch offenses
	offenses, err := c.client.GetOffenses(ctx, filter, c.syncCfg.MaxAlertsPerSync)
	if err != nil {
		return nil, checkpoint, fmt.Errorf("fetching offenses: %w", err)
	}

	if len(offenses) == 0 {
		log.Info().Msg("no new offenses found")
		return nil, checkpoint, nil
	}

	// Map offenses to normalized alerts
	alerts := make([]models.Alert, 0, len(offenses))
	var maxUpdatedTime int64

	for _, offense := range offenses {
		alert := MapOffenseToAlert(offense)

		// Optionally fetch notes for each offense
		if c.fetchNotes {
			notes, err := c.client.GetOffenseNotes(ctx, offense.ID)
			if err != nil {
				log.Warn().
					Int64("offense_id", offense.ID).
					Err(err).
					Msg("failed to fetch notes, skipping")
			} else if len(notes) > 0 {
				alert.Notes = MapNotes(notes)
			}
		}

		alerts = append(alerts, alert)

		if offense.LastUpdatedTime > maxUpdatedTime {
			maxUpdatedTime = offense.LastUpdatedTime
		}
	}

	newCheckpoint := checkpoint
	if maxUpdatedTime > 0 {
		newCheckpoint = strconv.FormatInt(maxUpdatedTime, 10)
	}

	log.Info().
		Int("alerts_collected", len(alerts)).
		Str("new_checkpoint", newCheckpoint).
		Msg("collection complete")

	return alerts, newCheckpoint, nil
}

// HealthCheck verifies QRadar connectivity.
func (c *QRadarCollector) HealthCheck(ctx context.Context) error {
	_, err := c.client.GetSystemInfo(ctx)
	if err != nil {
		// Fallback: try offenses endpoint
		_, err = c.client.GetOffenses(ctx, "", 1)
	}
	return err
}

// Close is a no-op for the QRadar collector (HTTP client doesn't need closing).
func (c *QRadarCollector) Close() error {
	return nil
}

// defaultCheckpoint calculates a checkpoint based on lookback_days.
func (c *QRadarCollector) defaultCheckpoint() int64 {
	return time.Now().Add(-time.Duration(c.lookbackMs) * time.Millisecond).UnixMilli()
}

// severityToQRadarMin maps our severity string to QRadar's minimum severity value.
func severityToQRadarMin(severity string) int {
	switch severity {
	case "low":
		return 0
	case "medium":
		return 4
	case "high":
		return 6
	case "critical":
		return 8
	default:
		return 0
	}
}

// init registers the QRadar collector in the collector registry.
func init() {
	collector.Register("qradar", func(cfg config.SIEMConfig, syncCfg config.SyncConfig) collector.Collector {
		return NewCollector(cfg, syncCfg)
	})
}
