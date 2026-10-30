package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/grd-platform/grd-siem-agent/internal/buffer"
	"github.com/grd-platform/grd-siem-agent/internal/collector"
	"github.com/grd-platform/grd-siem-agent/internal/config"
	"github.com/grd-platform/grd-siem-agent/internal/health"
	"github.com/grd-platform/grd-siem-agent/internal/models"
	"github.com/grd-platform/grd-siem-agent/internal/transport"
	"github.com/grd-platform/grd-siem-agent/internal/updater"
	"github.com/grd-platform/grd-siem-agent/internal/version"
)

const (
	// maxAlertsPerPost is the chunk size for POST /sync (the platform
	// accepts at most 1000 alerts per request).
	maxAlertsPerPost = 500
	// drainPageSize is how many buffered batches are read at a time.
	drainPageSize = 10
)

// PlatformClient is the part of the platform API the agent uses.
type PlatformClient interface {
	SendSync(ctx context.Context, payload models.SyncPayload) (*models.SyncResponse, error)
	SendHeartbeat(ctx context.Context, payload models.HeartbeatPayload) error
}

// backgroundTask is a loop that runs until its context is cancelled.
type backgroundTask interface {
	Run(ctx context.Context)
}

// Agent is the core orchestrator that coordinates collection, sending, and buffering.
type Agent struct {
	cfg         *config.Config
	coll        collector.Collector
	sender      PlatformClient
	buf         buffer.Buffer
	heartbeat   backgroundTask
	updater     backgroundTask
	checkpoints *checkpointStore
	retryCfg    transport.RetryConfig

	// checkpoint is the last checkpoint whose alerts were all delivered.
	checkpoint string
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

	a := newAgent(cfg, coll, sender, buf)
	a.heartbeat = health.NewHeartbeatService(sender, cfg.Heartbeat, cfg.Agent.Hostname, 1)
	a.updater = updater.New(cfg.Update)
	return a, nil
}

// newAgent wires an agent from its dependencies.
func newAgent(cfg *config.Config, coll collector.Collector, sender PlatformClient, buf buffer.Buffer) *Agent {
	return &Agent{
		cfg:    cfg,
		coll:   coll,
		sender: sender,
		buf:    buf,
		checkpoints: &checkpointStore{
			path:       config.CheckpointPath(cfg),
			legacyPath: config.LegacyCheckpointPath(cfg),
		},
		retryCfg: transport.DefaultRetryConfig(),
	}
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
	a.checkpoint = a.checkpoints.Load()
	log.Info().Str("checkpoint", a.checkpoint).Msg("loaded checkpoint")

	var wg sync.WaitGroup
	for _, task := range []backgroundTask{a.heartbeat, a.updater} {
		if task == nil {
			continue
		}
		wg.Add(1)
		go func(task backgroundTask) {
			defer wg.Done()
			task.Run(ctx)
		}(task)
	}

	// Drain any buffered alerts from previous runs, then collect immediately.
	a.cycle(ctx)

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
			a.cycle(ctx)
		}
	}
}

// cycle delivers buffered batches first, then runs one collection.
func (a *Agent) cycle(ctx context.Context) {
	a.drainBuffer(ctx)
	a.collectAndSend(ctx)
}

// collectAndSend performs one collection cycle and delivers the alerts in
// chunks of at most maxAlertsPerPost.
//
// The checkpoint advances only when every chunk was accepted with
// success=true and alerts_errors=0 (limit_reached still counts: those alerts
// were refused by the organization's quota, not lost in transit). Otherwise
// the same window is collected again next cycle; the platform deduplicates
// on externalId. Chunks that could not be delivered at all are also stored in
// the buffer.
func (a *Agent) collectAndSend(ctx context.Context) {
	log.Info().Msg("starting collection cycle")

	before := a.checkpoint
	batch, err := a.coll.Collect(ctx, before)
	if err != nil {
		log.Error().Err(err).Msg("collection failed")
		return
	}

	if len(batch.Templates) == 0 {
		log.Info().Msg("no new alerts to send")
		a.advanceCheckpoint(batch.Checkpoint) // nothing to deliver: trivially complete
		return
	}

	payloads := a.buildPayloads(batch)
	delivered := true
	for i, payload := range payloads {
		resp, err := a.sendWithRetry(ctx, payload)
		if err != nil {
			log.Error().
				Err(err).
				Int("chunk", i+1).
				Int("chunks", len(payloads)).
				Msg("failed to send alerts, buffering the undelivered chunks")
			a.bufferPayloads(payloads[i:], before, i)
			delivered = false
			break
		}
		if !acceptSyncResponse(resp, i+1, len(payloads)) {
			delivered = false
		}
	}

	if !delivered {
		log.Warn().Msg("checkpoint not advanced; the same alerts will be collected again next cycle")
		return
	}
	a.advanceCheckpoint(batch.Checkpoint)
}

// acceptSyncResponse logs the platform's answer and reports whether every
// alert of the chunk was handled.
func acceptSyncResponse(resp *models.SyncResponse, chunk, chunks int) bool {
	event := log.Info()
	if !resp.Success || resp.AlertsErrors > 0 {
		event = log.Warn()
	}
	event.
		Int("chunk", chunk).
		Int("chunks", chunks).
		Bool("success", resp.Success).
		Int("alerts_imported", resp.AlertsImported).
		Int("alerts_duplicate", resp.AlertsDuplicate).
		Int("alerts_skipped", resp.AlertsSkipped).
		Int("alerts_errors", resp.AlertsErrors).
		Bool("limit_reached", resp.LimitReached).
		Msg("sync response")

	if !resp.Success || resp.AlertsErrors > 0 {
		return false
	}
	if resp.LimitReached {
		log.Warn().
			Int("alerts_skipped", resp.AlertsSkipped).
			Msg("organization alert limit reached: skipped alerts are not re-sent; raise the limit in the GRD platform")
	}
	return true
}

// buildPayloads splits a batch into payloads of at most maxAlertsPerPost
// alerts. Every payload carries the queried window as date_from/date_to. The
// collector-level counts (records dropped by filters, duplicates) are
// attributed to the first payload, so the sync logs add up to the batch.
func (a *Agent) buildPayloads(batch collector.Batch) []models.SyncPayload {
	dateFrom, dateTo := windowDates(batch)
	dropped := max(batch.Fetched-batch.DuplicatesRemoved-len(batch.Templates), 0)

	var payloads []models.SyncPayload
	for start := 0; start < len(batch.Templates); start += maxAlertsPerPost {
		chunk := batch.Templates[start:min(start+maxAlertsPerPost, len(batch.Templates))]
		meta := models.SyncMetadata{
			DateFrom:         dateFrom,
			DateTo:           dateTo,
			SIEMType:         a.cfg.SIEM.Type,
			TotalFetched:     len(chunk),
			TotalAfterFilter: len(chunk),
			AgentVersion:     version.Version,
		}
		if start == 0 {
			meta.TotalFetched += dropped + batch.DuplicatesRemoved
			meta.DuplicatesRemoved = batch.DuplicatesRemoved
		}
		payloads = append(payloads, models.SyncPayload{
			ConnectionID: a.cfg.SIEM.ConnectionID,
			Alerts:       chunk,
			SyncMetadata: meta,
		})
	}
	return payloads
}

// windowDates returns the queried window as RFC 3339 UTC. A collector that
// does not report a window gets the range of its alerts' dates.
func windowDates(batch collector.Batch) (string, string) {
	if !batch.WindowFrom.IsZero() && !batch.WindowTo.IsZero() {
		return batch.WindowFrom.UTC().Format(time.RFC3339), batch.WindowTo.UTC().Format(time.RFC3339)
	}
	meta := buffer.DeriveMetadata(batch.Templates, time.Now())
	return meta.DateFrom, meta.DateTo
}

func (a *Agent) sendWithRetry(ctx context.Context, payload models.SyncPayload) (*models.SyncResponse, error) {
	var resp *models.SyncResponse
	err := transport.WithRetry(ctx, a.retryCfg, "sync", func() error {
		var sendErr error
		resp, sendErr = a.sender.SendSync(ctx, payload)
		return sendErr
	})
	return resp, err
}

// bufferPayloads stores undelivered payloads. Each is keyed by the checkpoint
// the cycle started from and its chunk index: while the platform is down the
// same window is collected again every cycle, and the newer copy replaces the
// older one instead of piling up.
func (a *Agent) bufferPayloads(payloads []models.SyncPayload, checkpoint string, firstChunk int) {
	for i, payload := range payloads {
		if err := a.buf.Push(payload, bufferKey(payload.ConnectionID, checkpoint, firstChunk+i)); err != nil {
			log.Error().Err(err).Int("alerts", len(payload.Alerts)).Msg("failed to buffer alerts; they will be collected again next cycle")
		}
	}
}

func bufferKey(connectionID, checkpoint string, chunk int) string {
	sum := sha256.Sum256([]byte(checkpoint))
	return fmt.Sprintf("%s:%s:%d", connectionID, hex.EncodeToString(sum[:8]), chunk)
}

// advanceCheckpoint records a fully delivered checkpoint and persists it.
func (a *Agent) advanceCheckpoint(checkpoint string) {
	if checkpoint == a.checkpoint {
		return
	}
	a.checkpoint = checkpoint
	if err := a.checkpoints.Save(checkpoint); err != nil {
		// The in-memory checkpoint still advances; after a restart the
		// window is re-sent and deduplicated by the platform.
		log.Error().Err(err).Msg("failed to save checkpoint")
		return
	}
	log.Debug().Str("checkpoint", checkpoint).Msg("checkpoint saved")
}

// drainBuffer sends buffered batches oldest first. A batch is removed (Ack)
// only after every chunk of it was accepted without errors; everything else
// stays buffered. Draining stops when the platform is unreachable, and skips
// past a batch the platform rejects permanently (e.g. its connection was
// deleted) so it cannot block the batches behind it.
func (a *Agent) drainBuffer(ctx context.Context) {
	var afterID int64
	delivered, kept := 0, 0
	defer func() {
		if delivered > 0 || kept > 0 {
			log.Info().Int("delivered", delivered).Int("kept", kept).Msg("buffer drain finished")
		}
	}()

	for ctx.Err() == nil {
		batches, err := a.buf.Peek(afterID, drainPageSize)
		if err != nil {
			log.Error().Err(err).Msg("failed to read the buffer")
			return
		}
		if len(batches) == 0 {
			return
		}
		for _, b := range batches {
			afterID = b.ID
			ok, err := a.deliverBuffered(ctx, b.Payload)
			if err != nil {
				code := transport.StatusCode(err)
				if transport.IsPermanent(err) && code != 401 && code != 403 {
					log.Error().Err(err).Int64("batch", b.ID).Msg("platform rejected a buffered batch; keeping it")
					kept++
					continue
				}
				log.Warn().Err(err).Msg("buffer drain interrupted; batches stay buffered")
				return
			}
			if !ok {
				kept++
				continue
			}
			if err := a.buf.Ack(b.ID); err != nil {
				log.Error().Err(err).Int64("batch", b.ID).Msg("failed to remove a delivered batch; it may be sent again")
			}
			delivered++
		}
	}
}

// deliverBuffered sends one buffered payload (split into chunks when an old
// agent stored more than maxAlertsPerPost alerts), with a single attempt per
// chunk. It reports whether the platform handled every alert.
func (a *Agent) deliverBuffered(ctx context.Context, payload models.SyncPayload) (bool, error) {
	if payload.ConnectionID == "" {
		payload.ConnectionID = a.cfg.SIEM.ConnectionID
	}
	if payload.SyncMetadata.SIEMType == "" {
		payload.SyncMetadata.SIEMType = a.cfg.SIEM.Type
	}
	if payload.SyncMetadata.AgentVersion == "" {
		payload.SyncMetadata.AgentVersion = version.Version
	}

	ok := true
	for start := 0; start < len(payload.Alerts); start += maxAlertsPerPost {
		chunk := payload
		chunk.Alerts = payload.Alerts[start:min(start+maxAlertsPerPost, len(payload.Alerts))]
		if start > 0 {
			chunk.SyncMetadata.TotalFetched = len(chunk.Alerts)
			chunk.SyncMetadata.TotalAfterFilter = len(chunk.Alerts)
			chunk.SyncMetadata.DuplicatesRemoved = 0
		} else if len(payload.Alerts) > maxAlertsPerPost {
			chunk.SyncMetadata.TotalFetched -= len(payload.Alerts) - len(chunk.Alerts)
			chunk.SyncMetadata.TotalAfterFilter = len(chunk.Alerts)
		}
		resp, err := a.sender.SendSync(ctx, chunk)
		if err != nil {
			return false, err
		}
		if !acceptSyncResponse(resp, start/maxAlertsPerPost+1, (len(payload.Alerts)+maxAlertsPerPost-1)/maxAlertsPerPost) {
			ok = false
		}
	}
	return ok, nil
}
