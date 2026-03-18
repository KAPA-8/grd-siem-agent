package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/grd-platform/grd-siem-agent/internal/buffer"
	"github.com/grd-platform/grd-siem-agent/internal/collector"
	"github.com/grd-platform/grd-siem-agent/internal/collector/qradar"
	"github.com/grd-platform/grd-siem-agent/internal/config"
	"github.com/grd-platform/grd-siem-agent/internal/health"
	"github.com/grd-platform/grd-siem-agent/internal/models"
	"github.com/grd-platform/grd-siem-agent/internal/transport"
	"github.com/grd-platform/grd-siem-agent/internal/updater"
	"github.com/grd-platform/grd-siem-agent/internal/version"
)

// Agent is the core orchestrator that coordinates collection, sending, and buffering.
type Agent struct {
	cfg            *config.Config
	coll           collector.Collector
	sender         *transport.Sender
	buf            buffer.Buffer
	heartbeat      *health.HeartbeatService
	updater        *updater.Updater
	checkpointPath string
}

// New creates a new Agent from configuration.
func New(cfg *config.Config, configPath string) (*Agent, error) {
	// Create collector from registry
	coll, err := collector.New(cfg.SIEM, cfg.Sync)
	if err != nil {
		return nil, fmt.Errorf("creating collector: %w", err)
	}

	sender := transport.NewSender(cfg.Platform)

	// Create buffer
	var buf buffer.Buffer
	if cfg.Buffer.Enabled {
		sqlBuf, err := buffer.NewSQLiteBuffer(cfg.Buffer.Path)
		if err != nil {
			log.Warn().Err(err).Msg("SQLite buffer init failed, using memory buffer")
			buf = buffer.NewMemoryBuffer()
		} else {
			buf = sqlBuf
		}
	} else {
		buf = buffer.NewMemoryBuffer()
	}

	// Create heartbeat service
	hb := health.NewHeartbeatService(sender, cfg.Heartbeat, cfg.Agent.Hostname, 1)

	// Create updater service
	upd := updater.New(cfg.Update)

	return &Agent{
		cfg:            cfg,
		coll:           coll,
		sender:         sender,
		buf:            buf,
		heartbeat:      hb,
		updater:        upd,
		checkpointPath: config.CheckpointPath(cfg),
	}, nil
}

// Run starts the agent's main loop. It blocks until the context is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	log.Info().
		Str("agent_id", a.cfg.Agent.ID).
		Str("agent_name", a.cfg.Agent.Name).
		Str("siem_type", a.cfg.SIEM.Type).
		Str("version", version.Version).
		Int("interval_minutes", a.cfg.Sync.IntervalMinutes).
		Msg("starting agent")

	// Initialize collector (validates SIEM connectivity)
	if err := a.coll.Init(ctx); err != nil {
		return fmt.Errorf("collector init: %w", err)
	}
	defer a.coll.Close()
	defer a.buf.Close()

	// Load checkpoint
	checkpoint := a.loadCheckpoint()
	log.Info().Str("checkpoint", checkpoint).Msg("loaded checkpoint")

	// Start heartbeat in background goroutine
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		a.heartbeat.Run(ctx)
	}()

	// Start update checker in background goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		a.updater.Run(ctx)
	}()

	// Drain any buffered alerts from previous runs
	a.drainBuffer(ctx)

	// Run first collection immediately
	checkpoint = a.collectAndSend(ctx, checkpoint)

	// Start polling loop
	interval := time.Duration(a.cfg.Sync.IntervalMinutes) * time.Minute
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	log.Info().Dur("interval", interval).Msg("polling loop started")

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("shutting down gracefully, waiting for background tasks...")
			wg.Wait()
			log.Info().Msg("agent stopped")
			return nil
		case <-ticker.C:
			// Drain buffer before new collection
			a.drainBuffer(ctx)
			checkpoint = a.collectAndSend(ctx, checkpoint)
		}
	}
}

// collectAndSend performs one collection cycle, converts to platform format, and sends.
func (a *Agent) collectAndSend(ctx context.Context, checkpoint string) string {
	log.Info().Msg("starting collection cycle")

	alerts, newCheckpoint, err := a.coll.Collect(ctx, checkpoint)
	if err != nil {
		log.Error().Err(err).Msg("collection failed")
		return checkpoint
	}

	if len(alerts) == 0 {
		log.Info().Msg("no new alerts to send")
		return checkpoint
	}

	// Convert internal alerts to platform format (AlertImportTemplate)
	templates := make([]models.AlertImportTemplate, 0, len(alerts))
	for _, alert := range alerts {
		templates = append(templates, qradar.AlertToImportTemplate(alert))
	}

	// Determine date range for sync metadata
	dateFrom := alerts[0].CreatedAt
	dateTo := alerts[len(alerts)-1].UpdatedAt
	for _, alert := range alerts {
		if alert.CreatedAt.Before(dateFrom) {
			dateFrom = alert.CreatedAt
		}
		if alert.UpdatedAt.After(dateTo) {
			dateTo = alert.UpdatedAt
		}
	}

	// Build sync payload matching platform API contract
	payload := models.SyncPayload{
		ConnectionID: a.cfg.SIEM.ConnectionID,
		Alerts:       templates,
		SyncMetadata: models.SyncMetadata{
			DateFrom:          dateFrom.UTC().Format(time.RFC3339),
			DateTo:            dateTo.UTC().Format(time.RFC3339),
			SIEMType:          a.cfg.SIEM.Type,
			TotalFetched:      len(alerts),
			TotalAfterFilter:  len(templates),
			DuplicatesRemoved: 0,
			AgentVersion:      version.Version,
		},
	}

	// Send to platform with retry
	retryCfg := transport.DefaultRetryConfig()
	var syncResp *models.SyncResponse

	err = transport.WithRetry(ctx, retryCfg, "sync", func() error {
		var sendErr error
		syncResp, sendErr = a.sender.SendSync(ctx, payload)
		return sendErr
	})

	if err != nil {
		log.Error().
			Err(err).
			Int("alert_count", len(templates)).
			Msg("failed to send alerts after retries, buffering")

		// Buffer for later retry
		if bufErr := a.buf.Push(templates, a.cfg.SIEM.ConnectionID); bufErr != nil {
			log.Error().Err(bufErr).Msg("failed to buffer alerts — data loss!")
		}
		return checkpoint
	}

	log.Info().
		Int("alerts_imported", syncResp.AlertsImported).
		Int("alerts_skipped", syncResp.AlertsSkipped).
		Bool("limit_reached", syncResp.LimitReached).
		Msg("sync completed successfully")

	if syncResp.LimitReached {
		log.Warn().Msg("organization alert limit reached, some alerts may not have been imported")
	}

	// Persist checkpoint only after successful send
	a.saveCheckpoint(newCheckpoint)

	return newCheckpoint
}

// drainBuffer attempts to send any previously buffered alerts.
func (a *Agent) drainBuffer(ctx context.Context) {
	bufLen, err := a.buf.Len()
	if err != nil {
		log.Error().Err(err).Msg("failed to check buffer length")
		return
	}

	if bufLen == 0 {
		return
	}

	log.Info().Int("buffered_entries", bufLen).Msg("draining buffer")

	batches, err := a.buf.Pop(10) // Drain up to 10 batches at a time
	if err != nil {
		log.Error().Err(err).Msg("failed to pop from buffer")
		return
	}

	for _, batch := range batches {
		payload := models.SyncPayload{
			ConnectionID: batch.ConnectionID,
			Alerts:       batch.Alerts,
			SyncMetadata: models.SyncMetadata{
				SIEMType:         a.cfg.SIEM.Type,
				TotalFetched:     len(batch.Alerts),
				TotalAfterFilter: len(batch.Alerts),
				AgentVersion:     version.Version,
			},
		}

		_, err := a.sender.SendSync(ctx, payload)
		if err != nil {
			log.Warn().Err(err).Int("alerts", len(batch.Alerts)).Msg("buffer drain failed, re-buffering")
			if pushErr := a.buf.Push(batch.Alerts, batch.ConnectionID); pushErr != nil {
				log.Error().Err(pushErr).Msg("failed to re-buffer alerts — data loss!")
			}
			return // Stop draining, platform may be down
		}

		log.Info().Int("alerts", len(batch.Alerts)).Msg("drained buffered batch successfully")
	}
}

// loadCheckpoint reads the checkpoint from the persistent file.
func (a *Agent) loadCheckpoint() string {
	data, err := os.ReadFile(a.checkpointPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// saveCheckpoint writes the checkpoint to the persistent file.
func (a *Agent) saveCheckpoint(checkpoint string) {
	dir := filepath.Dir(a.checkpointPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Error().Err(err).Msg("failed to create checkpoint directory")
		return
	}

	if err := os.WriteFile(a.checkpointPath, []byte(checkpoint), 0o644); err != nil {
		log.Error().Err(err).Msg("failed to save checkpoint")
	}
}
