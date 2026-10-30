package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
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
	// healthCheckInterval spaces out the collector health checks run for
	// the heartbeat.
	healthCheckInterval = 5 * time.Minute
	// healthCheckTimeout bounds one health check.
	healthCheckTimeout = 30 * time.Second
	// maxBufferedRejections is how many times the platform may refuse a
	// buffered batch (a permanent 4xx other than 401/403, e.g. its connection
	// was deleted, or a partial import) before the batch is dropped, so it is
	// not re-sent forever and the heartbeat does not stay degraded. Buffered
	// alerts are a safety net: the checkpoint never advances past alerts
	// that were not delivered, so their window is collected again.
	maxBufferedRejections = 5
)

// defaultInitRetry retries collector Init until it succeeds: 5s, 10s, ...
// up to 5 minutes between attempts, forever.
var defaultInitRetry = transport.RetryConfig{InitialInterval: 5 * time.Second, MaxInterval: 5 * time.Minute}

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
	initRetry   transport.RetryConfig
	status      *health.Tracker

	// checkpoint is the last checkpoint whose alerts were all delivered.
	checkpoint string

	// siemMu serializes the collector's SIEM requests: Collect (main loop)
	// and HealthCheck (heartbeat goroutine) never run at the same time.
	// Stellar Cyber asks for sequential requests, and a health check queued
	// behind a collection's token exchange would time out and report the
	// SIEM as down.
	siemMu sync.Mutex

	healthMu        sync.Mutex
	lastHealthCheck time.Time // last Init, successful Collect or health check
	healthEvery     time.Duration
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
	a.heartbeat = health.NewHeartbeatService(sender, time.Duration(cfg.Heartbeat.IntervalSeconds)*time.Second, cfg.Agent.Hostname, 1, a.heartbeatStatus)
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
		retryCfg:    transport.SyncRetryConfig(),
		initRetry:   defaultInitRetry,
		status:      &health.Tracker{},
		healthEvery: healthCheckInterval,
	}
}

// Run starts the agent's main loop. It blocks until the context is cancelled.
//
// The heartbeat starts first, so the platform sees the agent (in "error")
// even while the SIEM is unreachable; collector Init is then retried with
// backoff until it succeeds or the context is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	log.Info().
		Str("agent_id", a.cfg.Agent.ID).
		Str("agent_name", a.cfg.Agent.Name).
		Str("siem_type", a.cfg.SIEM.Type).
		Str("version", version.Version).
		Int("interval_minutes", a.cfg.Sync.IntervalMinutes).
		Msg("starting agent")

	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() {
		cancel()
		wg.Wait() // the heartbeat may be running a health check
		a.coll.Close()
		a.buf.Close()
		log.Info().Msg("agent stopped")
	}()

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

	if err := a.initCollector(ctx); err != nil {
		log.Info().Msg("shutting down before the collector was initialized")
		return nil
	}

	// Load checkpoint
	a.checkpoint = a.checkpoints.Load()
	log.Info().Str("checkpoint", a.checkpoint).Msg("loaded checkpoint")

	// Drain any buffered alerts from previous runs, then collect immediately.
	a.cycle(ctx)

	// Start polling loop
	interval := time.Duration(a.cfg.Sync.IntervalMinutes) * time.Minute
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	log.Info().Dur("interval", interval).Msg("polling loop started")

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("shutting down gracefully, waiting for background tasks...")
			return nil
		case <-ticker.C:
			a.cycle(ctx)
		}
	}
}

// initCollector calls Init until it succeeds, backing off between attempts.
// It only fails when ctx is cancelled.
func (a *Agent) initCollector(ctx context.Context) error {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = a.initRetry.InitialInterval
	b.MaxInterval = a.initRetry.MaxInterval
	b.MaxElapsedTime = 0 // never give up
	b.Reset()

	for attempt := 1; ; attempt++ {
		err := a.coll.Init(ctx)
		if err == nil {
			a.markSIEMChecked() // Init just probed the SIEM: the next health check can wait
			a.status.SetInit(nil)
			if attempt > 1 {
				log.Info().Int("attempts", attempt).Msg("collector initialized")
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		a.status.SetInit(err)
		wait := b.NextBackOff()
		log.Error().Err(err).Int("attempt", attempt).Dur("retry_in", wait).Msg("collector init failed; retrying")

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// heartbeatStatus is the heartbeat's StatusFunc: it refreshes the buffer
// depth, runs the collector health check when one is due, and reports.
func (a *Agent) heartbeatStatus(ctx context.Context) health.Report {
	if a.status.Initialized() {
		a.maybeHealthCheck(ctx)
	}
	a.refreshBuffered()
	return a.status.Report()
}

// markSIEMChecked records that the SIEM just answered (Init, a successful
// collection or a health check), which postpones the next health check.
func (a *Agent) markSIEMChecked() {
	a.healthMu.Lock()
	a.lastHealthCheck = time.Now()
	a.healthMu.Unlock()
}

// maybeHealthCheck runs the collector health check when the SIEM has not been
// checked for healthEvery. It is skipped while a collection is running: the
// collection talks to the SIEM and reports its state itself.
func (a *Agent) maybeHealthCheck(ctx context.Context) {
	a.healthMu.Lock()
	due := a.lastHealthCheck.IsZero() || time.Since(a.lastHealthCheck) >= a.healthEvery
	a.healthMu.Unlock()
	if !due || !a.siemMu.TryLock() {
		return
	}
	defer a.siemMu.Unlock()
	a.markSIEMChecked()

	checkCtx, cancel := context.WithTimeout(ctx, healthCheckTimeout)
	err := a.coll.HealthCheck(checkCtx)
	cancel()
	if ctx.Err() == nil {
		if err != nil {
			log.Warn().Err(err).Msg("collector health check failed")
		}
		a.status.SetSIEM(err)
	}
}

func (a *Agent) refreshBuffered() {
	n, err := a.buf.Len()
	if err != nil {
		log.Warn().Err(err).Msg("failed to read the buffer size")
		return
	}
	a.status.SetBuffered(n)
}

// cycle delivers buffered batches first, then runs one collection.
func (a *Agent) cycle(ctx context.Context) {
	a.drainBuffer(ctx)
	a.collectAndSend(ctx)
}

// collectAndSend performs one collection cycle and delivers the alerts in
// chunks of at most maxAlertsPerPost.
//
// Each chunk is retried for the short transport.SyncRetryConfig window; the
// heartbeat reports the failure from the first failed attempt, and a chunk
// that still fails is buffered with the ones after it.
//
// The checkpoint advances only when every chunk was accepted with
// success=true and alerts_errors=0 (limit_reached still counts: those alerts
// were refused by the organization's quota, not lost in transit; so do
// alerts_rejected, which the platform will never accept however often they
// are sent). Otherwise
// the same window is collected again next cycle; the platform deduplicates
// on externalId. Chunks that could not be delivered at all are also stored in
// the buffer.
func (a *Agent) collectAndSend(ctx context.Context) {
	log.Info().Msg("starting collection cycle")

	before := a.checkpoint
	a.siemMu.Lock()
	batch, err := a.coll.Collect(ctx, before)
	a.siemMu.Unlock()
	if err != nil {
		if ctx.Err() == nil {
			log.Error().Err(err).Msg("collection failed")
			a.status.SetSIEM(err)
		}
		return
	}
	a.markSIEMChecked() // a successful collection is a health check
	a.status.SetSIEM(nil)

	if len(batch.Templates) == 0 {
		log.Info().Msg("no new alerts to send")
		a.advanceCheckpoint(batch.Checkpoint) // nothing to deliver: trivially complete
		a.status.SetDelivery(nil)
		return
	}

	payloads := a.buildPayloads(batch)
	var deliveryErr error
	for i, payload := range payloads {
		resp, err := a.sendWithRetry(ctx, payload)
		if err != nil {
			log.Error().
				Err(err).
				Int("chunk", i+1).
				Int("chunks", len(payloads)).
				Msg("failed to send alerts, buffering the undelivered chunks")
			a.bufferPayloads(payloads[i:], before, i)
			a.refreshBuffered()
			deliveryErr = err
			break
		}
		if !acceptSyncResponse(resp, i+1, len(payloads)) {
			deliveryErr = fmt.Errorf("platform imported chunk %d/%d only partially (success=%v, alerts_errors=%d)", i+1, len(payloads), resp.Success, resp.AlertsErrors)
		}
		// The platform answered: a failure reported by a retry gives way to
		// this cycle's outcome so far.
		a.status.SetDelivery(deliveryErr)
	}

	if ctx.Err() == nil {
		a.status.SetDelivery(deliveryErr)
	}
	if deliveryErr != nil {
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
		Int("alerts_rejected", resp.AlertsRejected).
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
	if resp.AlertsRejected > 0 {
		log.Warn().
			Int("alerts_rejected", resp.AlertsRejected).
			Msg("platform rejected invalid alerts; they are not re-sent (see the sync log in the GRD platform)")
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

// sendWithRetry posts one chunk with retries. Every failed attempt is
// reported to the heartbeat at once, so the agent does not look healthy while
// the platform is unreachable and the retries run.
func (a *Agent) sendWithRetry(ctx context.Context, payload models.SyncPayload) (*models.SyncResponse, error) {
	var resp *models.SyncResponse
	err := transport.WithRetryNotify(ctx, a.retryCfg, "sync", func() error {
		var sendErr error
		resp, sendErr = a.sender.SendSync(ctx, payload)
		return sendErr
	}, func(err error) {
		if ctx.Err() == nil {
			a.status.SetDelivery(err)
		}
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
// only after every chunk of it was accepted without errors. Draining stops
// when the platform is unreachable (the batches stay buffered), and skips
// past a batch the platform refuses (a permanent 4xx such as a deleted
// connection, or a partial import) so it cannot block the batches behind it;
// such a batch is dropped once it has been refused maxBufferedRejections times.
// A delivered batch clears the delivery error reported to the heartbeat.
func (a *Agent) drainBuffer(ctx context.Context) {
	var afterID int64
	delivered, kept, dropped := 0, 0, 0
	defer func() {
		if delivered > 0 || kept > 0 || dropped > 0 {
			log.Info().Int("delivered", delivered).Int("kept", kept).Int("dropped", dropped).Msg("buffer drain finished")
		}
		a.refreshBuffered()
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
				if !transport.IsPermanent(err) || code == 401 || code == 403 {
					log.Warn().Err(err).Msg("buffer drain interrupted; batches stay buffered")
					if ctx.Err() == nil {
						a.status.SetDelivery(err)
					}
					return
				}
			} else if !ok {
				err = errors.New("the platform imported the batch only partially")
			}
			if err != nil {
				if a.rejectBuffered(b, err) {
					dropped++
				} else {
					kept++
				}
				continue
			}
			if err := a.buf.Ack(b.ID); err != nil {
				log.Error().Err(err).Int64("batch", b.ID).Msg("failed to remove a delivered batch; it may be sent again")
			}
			a.status.SetDelivery(nil) // the platform is reachable again
			delivered++
		}
	}
}

// rejectBuffered records one refusal of a buffered batch and drops the batch
// once it has been refused maxBufferedRejections times. It reports whether
// the batch was dropped.
func (a *Agent) rejectBuffered(b buffer.BufferedBatch, reason error) bool {
	rejections := b.Rejections + 1
	if rejections >= maxBufferedRejections {
		log.Error().
			Err(reason).
			Int64("batch", b.ID).
			Int("rejections", rejections).
			Int("alerts", len(b.Payload.Alerts)).
			Str("connection_id", b.Payload.ConnectionID).
			Msg("platform keeps refusing a buffered batch; dropping it")
		if err := a.buf.Ack(b.ID); err != nil {
			log.Error().Err(err).Int64("batch", b.ID).Msg("failed to drop a refused batch")
			return false
		}
		return true
	}
	log.Error().
		Err(reason).
		Int64("batch", b.ID).
		Int("rejections", rejections).
		Int("max_rejections", maxBufferedRejections).
		Msg("platform refused a buffered batch; keeping it for now")
	if err := a.buf.Reject(b.ID); err != nil {
		log.Error().Err(err).Int64("batch", b.ID).Msg("failed to record the refusal of a buffered batch")
	}
	return false
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
