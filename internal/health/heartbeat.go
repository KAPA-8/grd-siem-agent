package health

import (
	"context"
	"os"
	"runtime"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/grd-platform/grd-siem-agent/internal/config"
	"github.com/grd-platform/grd-siem-agent/internal/models"
	"github.com/grd-platform/grd-siem-agent/internal/transport"
	"github.com/grd-platform/grd-siem-agent/internal/version"
)

// HeartbeatService sends periodic heartbeats to the platform.
type HeartbeatService struct {
	sender          *transport.Sender
	cfg             config.HeartbeatConfig
	hostname        string
	startTime       time.Time
	activeConns     int
}

// NewHeartbeatService creates a new heartbeat service.
func NewHeartbeatService(sender *transport.Sender, cfg config.HeartbeatConfig, hostname string, activeConns int) *HeartbeatService {
	if hostname == "" {
		hostname, _ = os.Hostname()
	}

	return &HeartbeatService{
		sender:      sender,
		cfg:         cfg,
		hostname:    hostname,
		startTime:   time.Now(),
		activeConns: activeConns,
	}
}

// Run starts the heartbeat loop. It blocks until the context is cancelled.
// Heartbeat failures are logged but never block the agent.
func (h *HeartbeatService) Run(ctx context.Context) {
	interval := time.Duration(h.cfg.IntervalSeconds) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	log.Info().Dur("interval", interval).Msg("heartbeat service started")

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
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	payload := models.HeartbeatPayload{
		Status:            "healthy",
		UptimeSeconds:     int64(time.Since(h.startTime).Seconds()),
		MemoryUsageMB:     float64(memStats.Alloc) / 1024 / 1024,
		ActiveConnections: h.activeConns,
		AgentVersion:      version.Version,
		Hostname:          h.hostname,
	}

	if err := h.sender.SendHeartbeat(ctx, payload); err != nil {
		log.Warn().Err(err).Msg("heartbeat failed")
	} else {
		log.Debug().
			Float64("memory_mb", payload.MemoryUsageMB).
			Int64("uptime_s", payload.UptimeSeconds).
			Msg("heartbeat sent")
	}
}
