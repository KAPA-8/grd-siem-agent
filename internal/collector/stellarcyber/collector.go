// Package stellarcyber collects alerts from Stellar Cyber Open XDR (SaaS or
// on-prem Data Processor) for the GRD platform.
//
// Two data sources are supported:
//   - alerts: the aella-ser-* alert index through /connect/api/data (needs a
//     root All-Access token, or a scoped key on 6.3+).
//   - cases: /connect/api/v1/cases plus /cases/{id}/alerts (works with scoped keys).
//
// Collection is incremental on ingestion time (write_time for alerts,
// modified_at for cases) with a stability lag, and the checkpoint keeps the
// IDs seen at the last timestamp so ties are never lost or duplicated.
package stellarcyber

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/grd-platform/grd-siem-agent/internal/collector"
	"github.com/grd-platform/grd-siem-agent/internal/config"
	"github.com/grd-platform/grd-siem-agent/internal/siemhttp"
)

// Name is the siem.type of this collector.
const Name = "stellar_cyber"

const (
	deploymentSaaS   = "saas"
	deploymentOnPrem = "onprem"
	dataSourceAlerts = "alerts"
	dataSourceCases  = "cases"

	checkpointVersion = 1

	// stabilityLag keeps the window's upper bound behind "now" so documents
	// still being written are picked up by the next cycle instead of missed.
	stabilityLag = 120 * time.Second

	alertsPageSize     = 500   // max size per _search request
	maxResultWindow    = 10000 // from + size limit of the alert index
	casesPageSize      = 100
	caseAlertsPageSize = 50 // /cases/{id}/alerts limit

	defaultMaxAlerts    = 1000
	defaultLookbackDays = 7

	// maxCheckpointSkew rejects checkpoints too far in the future (corrupt
	// file or a clock that jumped), which would otherwise stall collection.
	maxCheckpointSkew = 24 * time.Hour
)

func init() {
	collector.Register(Name, New, ValidateConfig)
}

// settings is the validated, defaulted Stellar Cyber configuration.
type settings struct {
	baseURL    string
	deployment string
	dataSource string
	authMode   string
	username   string
	apiKey     string
	tenantID   string
}

func lowerOr(value, fallback string) string {
	if v := strings.ToLower(strings.TrimSpace(value)); v != "" {
		return v
	}
	return fallback
}

// resolveSettings applies defaults (deployment saas, data_source alerts,
// auth_mode api_token) and validates the siem section.
func resolveSettings(cfg config.SIEMConfig) (settings, error) {
	s := settings{
		deployment: lowerOr(cfg.Deployment, deploymentSaaS),
		dataSource: lowerOr(cfg.DataSource, dataSourceAlerts),
		authMode:   lowerOr(cfg.Credentials.AuthMode, authModeAPIToken),
		username:   strings.TrimSpace(cfg.Credentials.Username), // case-sensitive
		apiKey:     strings.TrimSpace(cfg.Credentials.APIKey),
		tenantID:   strings.TrimSpace(cfg.Credentials.TenantID),
	}

	var errs []error
	if s.deployment != deploymentSaaS && s.deployment != deploymentOnPrem {
		errs = append(errs, fmt.Errorf("siem.deployment must be saas or onprem (got %q)", cfg.Deployment))
	}
	if s.dataSource != dataSourceAlerts && s.dataSource != dataSourceCases {
		errs = append(errs, fmt.Errorf("siem.data_source must be alerts or cases (got %q)", cfg.DataSource))
	}
	switch s.authMode {
	case authModeAPIToken:
		if s.username == "" {
			errs = append(errs, errors.New("siem.credentials.username (the API account email) is required with auth_mode api_token"))
		} else if !strings.Contains(s.username, "@") {
			errs = append(errs, fmt.Errorf("siem.credentials.username must be the API account email address (got %q)", s.username))
		}
	case authModeScopedKey:
	default:
		errs = append(errs, fmt.Errorf("siem.credentials.auth_mode must be api_token or scoped_key (got %q)", cfg.Credentials.AuthMode))
	}
	if s.apiKey == "" {
		errs = append(errs, errors.New("siem.credentials.api_key is required"))
	}

	baseURL, err := NormalizeBaseURL(cfg.APIURL)
	if err != nil {
		errs = append(errs, err)
	} else if s.deployment == deploymentSaaS && strings.HasPrefix(baseURL, "http://") {
		errs = append(errs, fmt.Errorf("siem.api_url must use https for Stellar Cyber SaaS (got %q)", cfg.APIURL))
	}
	s.baseURL = baseURL

	return s, errors.Join(errs...)
}

// ValidateConfig validates the Stellar Cyber part of the configuration.
func ValidateConfig(cfg config.SIEMConfig) error {
	_, err := resolveSettings(cfg)
	return err
}

// Collector implements collector.Collector for Stellar Cyber.
type Collector struct {
	settings  settings
	client    *Client
	minScore  int
	maxAlerts int
	lookback  time.Duration
	now       func() time.Time

	// Paging limits (constants; fields so tests can shrink them).
	pageSize           int
	maxResultWindow    int
	casesPageSize      int
	caseAlertsPageSize int
}

var _ collector.Collector = (*Collector)(nil)

// New creates a Stellar Cyber collector. SaaS always verifies the server
// certificate; on-prem honours validate_ssl and ca_cert_file.
func New(cfg config.SIEMConfig, syncCfg config.SyncConfig) (collector.Collector, error) {
	return newCollector(cfg, syncCfg)
}

func newCollector(cfg config.SIEMConfig, syncCfg config.SyncConfig) (*Collector, error) {
	s, err := resolveSettings(cfg)
	if err != nil {
		return nil, err
	}

	skipVerify := false
	if !cfg.Credentials.ValidateSSL {
		if s.deployment == deploymentOnPrem {
			skipVerify = true
			log.Warn().Msg("stellar cyber: TLS certificate verification is disabled (validate_ssl: false); prefer ca_cert_file")
		} else {
			log.Warn().Msg("stellar cyber: validate_ssl: false is ignored for SaaS; certificates are always verified")
		}
	}
	httpClient, err := siemhttp.NewClient(siemhttp.Options{
		InsecureSkipVerify: skipVerify,
		CAFile:             cfg.Credentials.CACertFile,
		Timeout:            requestTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("stellar cyber: %w", err)
	}
	return newCollectorWith(s, httpClient, syncCfg)
}

// newCollectorWith builds a collector from resolved settings and an HTTP client.
func newCollectorWith(s settings, httpClient *http.Client, syncCfg config.SyncConfig) (*Collector, error) {
	minScore, err := minScoreFor(syncCfg.Filters.MinSeverity)
	if err != nil {
		return nil, err
	}
	maxAlerts := syncCfg.MaxAlertsPerSync
	if maxAlerts <= 0 {
		maxAlerts = defaultMaxAlerts
	}
	maxAlerts = min(maxAlerts, maxResultWindow)
	lookbackDays := syncCfg.LookbackDays
	if lookbackDays <= 0 {
		lookbackDays = defaultLookbackDays
	}

	now := time.Now
	return &Collector{
		settings:           s,
		client:             newClient(s.baseURL, httpClient, s, now),
		minScore:           minScore,
		maxAlerts:          maxAlerts,
		lookback:           time.Duration(lookbackDays) * 24 * time.Hour,
		now:                now,
		pageSize:           alertsPageSize,
		maxResultWindow:    maxResultWindow,
		casesPageSize:      casesPageSize,
		caseAlertsPageSize: caseAlertsPageSize,
	}, nil
}

// Name returns the SIEM type.
func (c *Collector) Name() string { return Name }

// Init exchanges the credential for a token and checks access to the data
// source. The platform version (from /cases/health) is logged when available.
func (c *Collector) Init(ctx context.Context) error {
	if err := c.probe(ctx); err != nil {
		return err
	}
	event := log.Info().
		Str("url", c.settings.baseURL).
		Str("deployment", c.settings.deployment).
		Str("data_source", c.settings.dataSource).
		Str("auth_mode", c.settings.authMode)
	if h, err := c.client.health(ctx); err == nil && h.Data.Version != "" {
		event = event.Str("version", h.Data.Version)
	}
	event.Msg("connected to Stellar Cyber")
	return nil
}

// HealthCheck verifies the credential and access to the data source.
func (c *Collector) HealthCheck(ctx context.Context) error {
	return c.probe(ctx)
}

func (c *Collector) probe(ctx context.Context) error {
	var err error
	if c.settings.dataSource == dataSourceCases {
		_, err = c.client.listCases(ctx, url.Values{"limit": {"1"}})
	} else {
		err = c.client.probeAlerts(ctx)
	}
	return err
}

// Close releases idle connections.
func (c *Collector) Close() error {
	c.client.httpClient.CloseIdleConnections()
	return nil
}

// checkpointState is the persisted checkpoint:
// {"v":1,"mode":"alerts"|"cases","ts":<ms>,"ids":[...]}, where ts is the
// last write_time (alerts) or modified_at (cases) delivered and ids are the
// alert or case IDs already delivered at exactly that ts.
type checkpointState struct {
	V    int      `json:"v"`
	Mode string   `json:"mode"`
	TS   int64    `json:"ts"`
	IDs  []string `json:"ids"`
}

// parseCheckpoint accepts only a checkpoint of this collector's mode. Anything
// else (empty, a QRadar epoch, the other mode, a corrupt or far-future value)
// makes the collector fall back to the lookback window.
func parseCheckpoint(raw, mode string, now time.Time) (checkpointState, bool) {
	if strings.TrimSpace(raw) == "" {
		return checkpointState{}, false
	}
	var cp checkpointState
	if err := json.Unmarshal([]byte(raw), &cp); err != nil ||
		cp.V != checkpointVersion || cp.Mode != mode || cp.TS <= 0 {
		log.Warn().Str("checkpoint", raw).Str("mode", mode).Msg("stellar cyber: ignoring checkpoint from another format or mode; using lookback")
		return checkpointState{}, false
	}
	if cp.TS > now.Add(maxCheckpointSkew).UnixMilli() {
		log.Warn().Int64("ts", cp.TS).Msg("stellar cyber: checkpoint is in the future; using lookback")
		return checkpointState{}, false
	}
	return cp, true
}

// checkpointTracker computes the next checkpoint: the highest timestamp seen
// and the IDs delivered at exactly that timestamp.
type checkpointTracker struct {
	mode    string
	ts      int64
	ids     map[string]struct{}
	changed bool
}

// newCheckpointTracker starts from the current checkpoint, or from the
// window's lower bound when there is none (so a foreign checkpoint is
// replaced even when nothing new is found).
func newCheckpointTracker(mode string, cp checkpointState, valid bool, lower int64) *checkpointTracker {
	t := &checkpointTracker{mode: mode, ts: lower, ids: map[string]struct{}{}, changed: !valid}
	if valid {
		t.ts = cp.TS
		for _, id := range cp.IDs {
			t.ids[id] = struct{}{}
		}
	}
	return t
}

func (t *checkpointTracker) observe(ts int64, id string) {
	switch {
	case ts > t.ts:
		t.ts = ts
		t.ids = map[string]struct{}{id: {}}
		t.changed = true
	case ts == t.ts:
		if _, ok := t.ids[id]; !ok {
			t.ids[id] = struct{}{}
			t.changed = true
		}
	}
}

// skipPast moves the checkpoint just past ts, dropping the ID list.
func (t *checkpointTracker) skipPast(ts int64) {
	t.ts = ts + 1
	t.ids = map[string]struct{}{}
	t.changed = true
}

// encode returns the new checkpoint, or current when nothing changed.
func (t *checkpointTracker) encode(current string) string {
	if !t.changed {
		return current
	}
	ids := make([]string, 0, len(t.ids))
	for id := range t.ids {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	data, _ := json.Marshal(checkpointState{V: checkpointVersion, Mode: t.mode, TS: t.ts, IDs: ids})
	return string(data)
}

// Collect fetches the alerts ingested since the checkpoint. The window is
// [checkpoint ts or now-lookback, now-stabilityLag).
func (c *Collector) Collect(ctx context.Context, checkpoint string) (collector.Batch, error) {
	now := c.now()
	mode := c.settings.dataSource
	cp, valid := parseCheckpoint(checkpoint, mode, now)

	lower := now.Add(-c.lookback).UnixMilli()
	if valid {
		lower = cp.TS
	}
	upper := now.Add(-stabilityLag).UnixMilli()

	batch := collector.Batch{
		Checkpoint: checkpoint,
		WindowFrom: time.UnixMilli(lower).UTC(),
		WindowTo:   time.UnixMilli(upper).UTC(),
	}
	tracker := newCheckpointTracker(mode, cp, valid, lower)

	if lower < upper {
		var err error
		if mode == dataSourceCases {
			err = c.collectCases(ctx, &batch, cp, valid, tracker, lower, upper)
		} else {
			err = c.collectAlerts(ctx, &batch, cp, valid, tracker, lower, upper)
		}
		if err != nil {
			return collector.Batch{}, err
		}
	}
	batch.Checkpoint = tracker.encode(checkpoint)

	log.Info().
		Str("data_source", mode).
		Time("from", batch.WindowFrom).
		Time("to", batch.WindowTo).
		Int("fetched", batch.Fetched).
		Int("alerts", len(batch.Templates)).
		Msg("stellar cyber: collection complete")
	return batch, nil
}

// collectAlerts pages through write_time:[lower TO upper} sorted ascending,
// skipping the IDs already delivered at the checkpoint ts, until the window
// is exhausted, max_alerts_per_sync is reached or from+size hits 10000.
func (c *Collector) collectAlerts(ctx context.Context, batch *collector.Batch, cp checkpointState, valid bool, tracker *checkpointTracker, lower, upper int64) error {
	query := buildAlertsQuery(rangeClause(fieldWriteTime, lower, upper), c.minScore, c.settings.tenantID)

	skip := map[string]struct{}{}
	if valid {
		for _, id := range cp.IDs {
			skip[id] = struct{}{}
		}
	}
	seen := map[string]struct{}{}
	accepted := 0
	from := 0
	windowFull := false
	lastWriteTime := int64(math.MinInt64)
	warnedOrder := false

	for accepted < c.maxAlerts {
		// Never ask for more than can still be accepted (plus the IDs that
		// will be skipped), and never past the from+size window.
		size := min(c.pageSize, c.maxResultWindow-from, c.maxAlerts-accepted+len(skip))
		if size <= 0 {
			windowFull = true
			break
		}
		res, err := c.client.searchAlerts(ctx, query, from, size)
		if err != nil {
			return fmt.Errorf("searching alerts (from=%d): %w", from, err)
		}
		hits := res.Hits.Hits
		for _, hit := range hits {
			if accepted >= c.maxAlerts {
				break // the rest is collected next cycle
			}
			if hit.ID == "" {
				log.Warn().Str("index", hit.Index).Msg("stellar cyber: skipping alert without _id")
				continue
			}
			if _, ok := skip[hit.ID]; ok {
				delete(skip, hit.ID)
				continue
			}
			writeTime, hasWriteTime := epochMs(hit.Source["write_time"])
			if hasWriteTime && (writeTime < lower || writeTime >= upper) {
				continue
			}
			batch.Fetched++
			if _, dup := seen[hit.ID]; dup {
				batch.DuplicatesRemoved++
				continue
			}
			seen[hit.ID] = struct{}{}
			accepted++
			if hasWriteTime {
				if writeTime < lastWriteTime && !warnedOrder {
					warnedOrder = true
					log.Warn().Msg("stellar cyber: alerts are not sorted by write_time; the server may ignore sort")
				}
				lastWriteTime = max(lastWriteTime, writeTime)
				tracker.observe(writeTime, hit.ID)
			}
			c.appendMapped(batch, hit, nil)
		}
		from += len(hits)
		if len(hits) < size {
			break // window exhausted
		}
	}

	// Every reachable result was already delivered at the checkpoint ts: more
	// than maxResultWindow alerts share one millisecond. Step past it rather
	// than stall forever.
	if windowFull && accepted == 0 && valid {
		log.Error().
			Int64("write_time", cp.TS).
			Int("window", c.maxResultWindow).
			Msg("stellar cyber: more alerts share one write_time than the search window allows; skipping the rest of that millisecond")
		tracker.skipPast(cp.TS)
	}
	return nil
}

// collectCases lists the cases modified in [lower, upper) once per status,
// then fetches each case's alerts (50 per page) in modified_at order. Cases
// are never split: once max_alerts_per_sync alerts have been read no new case
// is started, and the checkpoint stops at the last case processed.
func (c *Collector) collectCases(ctx context.Context, batch *collector.Batch, cp checkpointState, valid bool, tracker *checkpointTracker, lower, upper int64) error {
	cases, err := c.listModifiedCases(ctx, lower, upper)
	if err != nil {
		return err
	}
	sort.Slice(cases, func(i, j int) bool {
		if cases[i].ModifiedAt.ms != cases[j].ModifiedAt.ms {
			return cases[i].ModifiedAt.ms < cases[j].ModifiedAt.ms
		}
		return cases[i].ID < cases[j].ID
	})

	skip := map[string]struct{}{}
	if valid {
		for _, id := range cp.IDs {
			skip[id] = struct{}{}
		}
	}
	seenDocs := map[string]struct{}{}

	for _, cs := range cases {
		modifiedAt := cs.ModifiedAt.ms
		if modifiedAt < lower || modifiedAt >= upper {
			continue
		}
		if _, done := skip[cs.ID]; done && valid && modifiedAt == cp.TS {
			continue
		}
		if batch.Fetched >= c.maxAlerts {
			log.Info().Int("max_alerts", c.maxAlerts).Msg("stellar cyber: max_alerts_per_sync reached; remaining cases are collected next cycle")
			break
		}

		docs, err := c.allCaseAlerts(ctx, cs.ID)
		if err != nil {
			return fmt.Errorf("fetching alerts of case %s: %w", cs.ID, err)
		}
		extra := map[string]any{"caseId": cs.ID}
		if name := strings.TrimSpace(cs.Name); name != "" {
			extra["caseName"] = name
		}
		for _, doc := range docs {
			if doc.ID == "" || doc.Source == nil || (doc.Found != nil && !*doc.Found) {
				continue
			}
			batch.Fetched++
			if _, dup := seenDocs[doc.ID]; dup {
				batch.DuplicatesRemoved++
				continue
			}
			seenDocs[doc.ID] = struct{}{}
			if !c.passesFilters(doc.Source) {
				continue
			}
			c.appendMapped(batch, doc, extra)
		}
		tracker.observe(modifiedAt, cs.ID)
	}
	return nil
}

// passesFilters applies to case alerts the filters the alerts mode sends to
// the server: NOT event_status:"Ignored" and event_score:>=min.
func (c *Collector) passesFilters(source map[string]any) bool {
	if strings.EqualFold(str(source["event_status"]), ignoredStatus) {
		return false
	}
	if c.minScore > 0 {
		score, ok := numeric(source["event_score"])
		if !ok || score < float64(c.minScore) {
			return false
		}
	}
	return true
}

// listModifiedCases queries each status separately and merges the results.
func (c *Collector) listModifiedCases(ctx context.Context, lower, upper int64) ([]stellarCase, error) {
	var all []stellarCase
	seen := map[string]struct{}{}
	for _, status := range caseStatuses {
		statusSeen := map[string]struct{}{}
		for skip := 0; ; {
			query := url.Values{}
			query.Set("FROM~"+fieldModifiedAt, strconv.FormatInt(lower, 10))
			query.Set("TO~"+fieldModifiedAt, strconv.FormatInt(upper, 10))
			query.Set("sort", fieldModifiedAt)
			query.Set("order", "asc")
			query.Set("limit", strconv.Itoa(c.casesPageSize))
			query.Set("skip", strconv.Itoa(skip))
			query.Set("status", status)
			if c.settings.tenantID != "" {
				query.Set("tenantid", c.settings.tenantID)
			}
			page, err := c.client.listCases(ctx, query)
			if err != nil {
				return nil, fmt.Errorf("listing %q cases: %w", status, err)
			}
			fresh := 0
			for _, cs := range page.Data.Cases {
				if cs.ID == "" || !cs.ModifiedAt.ok {
					log.Warn().Str("case", cs.ID).Msg("stellar cyber: skipping case without _id or modified_at")
					continue
				}
				if _, dup := statusSeen[cs.ID]; dup {
					continue
				}
				statusSeen[cs.ID] = struct{}{}
				fresh++
				if _, dup := seen[cs.ID]; dup {
					continue // its status changed between two queries
				}
				seen[cs.ID] = struct{}{}
				all = append(all, cs)
			}
			n := len(page.Data.Cases)
			skip += n
			if n < c.casesPageSize {
				break
			}
			if total := page.total(); total > 0 && int64(skip) >= total {
				break
			}
			if fresh == 0 {
				log.Warn().Str("status", status).Msg("stellar cyber: cases page repeated (skip ignored?); stopping")
				break
			}
		}
	}
	return all, nil
}

// allCaseAlerts pages /cases/{id}/alerts until a short page.
func (c *Collector) allCaseAlerts(ctx context.Context, caseID string) ([]Hit, error) {
	var docs []Hit
	seen := map[string]struct{}{}
	for skip := 0; ; skip += c.caseAlertsPageSize {
		page, err := c.client.caseAlerts(ctx, caseID, skip, c.caseAlertsPageSize)
		if err != nil {
			return nil, err
		}
		fresh := 0
		for _, doc := range page {
			if _, dup := seen[doc.ID]; !dup {
				seen[doc.ID] = struct{}{}
				fresh++
			}
		}
		docs = append(docs, page...)
		if len(page) < c.caseAlertsPageSize {
			return docs, nil
		}
		if fresh == 0 {
			log.Warn().Str("case", caseID).Msg("stellar cyber: case alerts page repeated (skip ignored?); stopping")
			return docs, nil
		}
	}
}

func (c *Collector) appendMapped(batch *collector.Batch, hit Hit, extra map[string]any) {
	template, _, err := MapHit(hit, extra)
	if err != nil {
		log.Warn().Str("id", hit.ID).Err(err).Msg("stellar cyber: skipping alert")
		return
	}
	batch.Templates = append(batch.Templates, template)
}
