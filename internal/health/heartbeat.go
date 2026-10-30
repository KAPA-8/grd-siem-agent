package health

import (
	"context"
	"os"
	"runtime"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/grd-platform/grd-siem-agent/internal/models"
	"github.com/grd-platform/grd-siem-agent/internal/version"
)

// DefaultInterval applies when the configured interval is not positive
// (time.NewTicker panics on 0).
const DefaultInterval = 60 * time.Second

// Sender delivers heartbeats to the platform.
type Sender interface {
	SendHeartbeat(ctx context.Context, payload models.HeartbeatPayload) error
}

// StatusFunc returns the agent state for the next heartbeat.
type StatusFunc func(ctx context.Context) Report

// HeartbeatService sends periodic heartbeats to the platform.
type HeartbeatService struct {
	sender      Sender
	interval    time.Duration
	hostname    string
	startTime   time.Time
	activeConns int
	status      StatusFunc
	lastStatus  string
}

// NewHeartbeatService creates a new heartbeat service. status may be nil
// (always healthy).
func NewHeartbeatService(sender Sender, interval time.Duration, hostname string, activeConns int, status StatusFunc) *HeartbeatService {
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	if interval <= 0 {
		interval = DefaultInterval
	}
	if status == nil {
		status = func(context.Context) Report { return Report{Status: StatusHealthy} }
	}

	return &HeartbeatService{
		sender:      sender,
		interval:    interval,
		hostname:    hostname,
		startTime:   time.Now(),
		activeConns: activeConns,
		status:      status,
	}
}

// Run starts the heartbeat loop. It blocks until the context is cancelled.
// Heartbeat failures are logged but never block the agent.
func (h *HeartbeatService) Run(ctx context.Context) {
	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()

	log.Info().Dur("interval", h.interval).Msg("heartbeat service started")

	// Send first heartbeat immediately
	h.sendHeartbeat(ctx)

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("heartbeat service stopped")
			return
		case <-ticker.C:
			h.sendHeartbeat(ctx)
		}
	}
}

func (h *HeartbeatService) sendHeartbeat(ctx context.Context) {
	report := h.status(ctx)
	if ctx.Err() != nil {
		return
	}
	if report.Status != h.lastStatus {
		event := log.Info()
		if report.Status != StatusHealthy {
			event = log.Warn()
		}
		event.Str("status", report.Status).Str("detail", report.Detail).Msg("agent status changed")
		h.lastStatus = report.Status
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	payload := models.HeartbeatPayload{
		Status:            report.Status,
		StatusDetail:      report.Detail,
		UptimeSeconds:     int64(time.Since(h.startTime).Seconds()),
		MemoryUsageMB:     float64(memStats.Alloc) / 1024 / 1024,
		ActiveConnections: h.activeConns,
		BufferedBatches:   report.BufferedBatches,
		AgentVersion:      version.Version,
		Hostname:          h.hostname,
		OSInfo:            runtime.GOOS + "/" + runtime.GOARCH,
	}

	if err := h.sender.SendHeartbeat(ctx, payload); err != nil {
		log.Warn().Err(err).Msg("heartbeat failed")
	} else {
		log.Debug().
			Str("status", payload.Status).
			Float64("memory_mb", payload.MemoryUsageMB).
			Int64("uptime_s", payload.UptimeSeconds).
			Msg("heartbeat sent")
	}
}
