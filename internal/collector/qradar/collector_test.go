package qradar

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/grd-platform/grd-siem-agent/internal/config"
)

type offensesServer struct {
	mu       sync.Mutex
	offenses []QRadarOffense
	filters  []string
}

func (s *offensesServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.HasSuffix(r.URL.Path, "/notes") {
		_ = json.NewEncoder(w).Encode([]QRadarNote{})
		return
	}
	s.filters = append(s.filters, r.URL.Query().Get("filter"))
	_ = json.NewEncoder(w).Encode(s.offenses)
}

func newTestQRadar(t *testing.T, offenses []QRadarOffense) (*QRadarCollector, *offensesServer) {
	t.Helper()
	srv := &offensesServer{offenses: offenses}
	server := httptest.NewServer(srv)
	t.Cleanup(server.Close)
	c, err := NewCollector(config.SIEMConfig{
		Type:        "qradar",
		APIURL:      server.URL,
		Credentials: config.CredentialConfig{APIKey: "sec", ValidateSSL: true},
	}, config.SyncConfig{LookbackDays: 7, MaxAlertsPerSync: 100, Filters: config.Filters{MinSeverity: "low"}})
	if err != nil {
		t.Fatal(err)
	}
	return c, srv
}

func TestCollect_ReturnsTemplatesWindowAndCheckpoint(t *testing.T) {
	c, srv := newTestQRadar(t, []QRadarOffense{
		{ID: 1, Description: "Brute force", Severity: 6, Status: "OPEN", StartTime: 1000, LastUpdatedTime: 1700000001000},
		{ID: 2, Description: "Port scan", Severity: 3, Status: "OPEN", StartTime: 2000, LastUpdatedTime: 1700000002000},
	})

	before := time.Now()
	batch, err := c.Collect(context.Background(), "1700000000000")
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Templates) != 2 || batch.Templates[0].ExternalID != "qradar-offense-1" || batch.Templates[1].ExternalID != "qradar-offense-2" {
		t.Fatalf("templates = %+v", batch.Templates)
	}
	if batch.Checkpoint != "1700000002000" || batch.Fetched != 2 {
		t.Errorf("checkpoint/fetched = %s/%d", batch.Checkpoint, batch.Fetched)
	}
	if batch.WindowFrom.UnixMilli() != 1700000000000 || batch.WindowTo.Before(before) {
		t.Errorf("window = [%v, %v]", batch.WindowFrom, batch.WindowTo)
	}
	if srv.filters[0] != "last_updated_time > 1700000000000" {
		t.Errorf("filter = %q", srv.filters[0])
	}
}

func TestCollect_ForeignCheckpointUsesLookback(t *testing.T) {
	c, srv := newTestQRadar(t, nil)
	cp := `{"v":1,"mode":"alerts","ts":1793196390000,"ids":[]}`
	batch, err := c.Collect(context.Background(), cp)
	if err != nil {
		t.Fatal(err)
	}
	if batch.Checkpoint != cp || len(batch.Templates) != 0 {
		t.Errorf("empty cycle must keep the checkpoint: %+v", batch)
	}
	wantFrom := time.Now().Add(-7 * 24 * time.Hour)
	if d := batch.WindowFrom.Sub(wantFrom); d < -time.Minute || d > time.Minute {
		t.Errorf("window starts at %v, want about %v", batch.WindowFrom, wantFrom)
	}
	if !strings.HasPrefix(srv.filters[0], "last_updated_time > ") || strings.Contains(srv.filters[0], "1793196390000") {
		t.Errorf("filter = %q", srv.filters[0])
	}
}

func TestNewCollector_CAFileError(t *testing.T) {
	_, err := NewCollector(config.SIEMConfig{
		APIURL:      "https://qradar.local",
		Credentials: config.CredentialConfig{APIKey: "sec", ValidateSSL: true, CACertFile: filepath.Join(t.TempDir(), "missing.pem")},
	}, config.SyncConfig{})
	if err == nil || !strings.Contains(err.Error(), "ca_cert_file") {
		t.Errorf("err = %v", err)
	}
}
